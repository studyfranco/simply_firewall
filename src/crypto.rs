//! Request signing (HMAC-SHA256) and signing-secret encryption at rest (AES-GCM-256).
//!
//! Two distinct concerns live here, both keyed off an API key's `signing_secret`:
//!
//! 1. **Request authentication** — every `/api/*` call carries `X-API-Key` (identity lookup),
//!    `X-Timestamp` (anti-replay) and `X-Signature-256` (proof of possession). The signature is an
//!    HMAC-SHA256 over the **CANONICAL_V1** string `METHOD\nPATH\nTIMESTAMP\nRAW_BODY` using the
//!    looked-up key's `signing_secret`. See [`compute_signature`] and [`verify_signature`].
//!
//!    The same canonical string is used for outbound `CANONICAL_V1` webhook dispatches
//!    (`crate::webhooks`), so a `simply_ip_vault` instance can sign a request that another instance
//!    — or `simply_hook_executor` — verifies with identical code.
//! 2. **Secret confidentiality at rest** — unlike `key_hash` (a one-way hash), a `signing_secret`
//!    must be recoverable verbatim to verify a signature, so it cannot be hashed. When
//!    `VAULT_ENCRYPTION_KEY` is set it is therefore sealed with AES-GCM-256 before being written to
//!    the database; without it, the secret is stored raw for zero-config local development. See
//!    [`seal_signing_secret`] and [`open_signing_secret`].

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::{Digest, Sha256};

use crate::error::AppError;

/// Maximum tolerated difference, in seconds, between `X-Timestamp` and the server's own clock.
///
/// A request outside this window is rejected as a replay (or as originating from a host with a
/// badly skewed clock, which is indistinguishable from a replay and equally unsafe to trust). The
/// window is deliberately symmetric — a timestamp too far in the *future* is just as suspect as one
/// too far in the past, and allowing it would let a captured request be held and replayed later.
pub const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;

/// Name of the environment variable holding the master encryption key for `signing_secret` values.
pub const ENCRYPTION_KEY_ENV: &str = "VAULT_ENCRYPTION_KEY";

/// Marker prefixing every AES-GCM-256-sealed `signing_secret` in the database.
///
/// Its presence (not the mere fact that `VAULT_ENCRYPTION_KEY` happens to be set right now) is what
/// decides whether a stored value needs decrypting. That makes the dev→prod transition
/// non-destructive: rows written before encryption was enabled keep working, and rows written while
/// it was enabled produce a clear error rather than silently returning ciphertext as if it were the
/// secret if the key is later removed.
const SEALED_PREFIX: &str = "aesgcm256:";

/// AES-GCM standard nonce length, in bytes.
const NONCE_LEN: usize = 12;

/// Generates a fresh 32-byte HMAC signing secret, hex-encoded.
///
/// Deliberately the same shape and entropy as [`crate::api::generate_random_key`] — but a wholly
/// independent value: knowing a key's public `X-API-Key` must never reveal its signing secret.
pub fn generate_signing_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Builds the **CANONICAL_V1** byte string that gets signed:
/// `METHOD\nPATH\nTIMESTAMP\nRAW_BODY`.
///
/// The four fields are joined by a single `\n` (LF), exactly as specified in `AGENT.MD`. `method` is
/// expected uppercase and `path` is the URL path *without* the query string — see
/// [`verify_signature`] for why the query is excluded.
///
/// The newline delimiter is what makes the encoding *unambiguous*: with plain concatenation, the
/// pair `("POST", "/api/ban")` and `("POS", "T/api/ban")` produce identical bytes, so a signature
/// over one is a valid signature over the other. A delimiter that cannot appear in a method or a URL
/// path removes that whole class of boundary confusion. It is also the format
/// `simply_hook_executor` speaks, so one canonical string now serves both the inbound API and
/// outbound `CANONICAL_V1` webhook dispatches.
pub fn canonical_v1_payload(method: &str, path: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(method.len() + path.len() + timestamp.len() + body.len() + 3);
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(path.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(body);
    message
}

/// Computes the hex-encoded HMAC-SHA256 request signature for `X-Signature-256`.
///
/// Infallible in practice: `Hmac` accepts keys of any length, so the only error path is a
/// `secret` that cannot be used as HMAC key material at all, which is reported as
/// [`AppError::Internal`] rather than panicking (`AGENT.MD` forbids `.unwrap()`/`.expect()`).
pub fn compute_signature(
    secret: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    body: &[u8],
) -> Result<String, AppError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|e| {
        tracing::error!("Failed to build HMAC from signing secret: {}", e);
        AppError::Internal
    })?;
    mac.update(&canonical_v1_payload(method, path, timestamp, body));
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Verifies a caller-supplied `X-Signature-256` against the expected HMAC.
///
/// The comparison is constant-time (via `Mac::verify_slice`), so a caller cannot recover a valid
/// signature byte-by-byte from response-timing differences.
///
/// `path` must be the URL path only — the query string is intentionally *not* part of the signed
/// message. Signing it would mean any proxy that reorders, re-encodes, or appends query parameters
/// (a routine thing for reverse proxies to do) silently invalidates otherwise-valid requests. The
/// tradeoff is explicit and documented in `AGENT.MD`: query parameters on `/api/*` are read-only
/// filters, while every mutating field travels in the signed body.
///
/// A `sha256=` prefix on `provided` is accepted and stripped, matching the format this project
/// already uses for outbound webhook signatures, so one signing helper can serve both directions.
pub fn verify_signature(
    secret: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    body: &[u8],
    provided: &str,
) -> bool {
    let provided = provided
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or(provided.trim());

    let Ok(provided_bytes) = hex::decode(provided) else {
        return false;
    };

    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(&canonical_v1_payload(method, path, timestamp, body));
    mac.verify_slice(&provided_bytes).is_ok()
}

/// Resolves the AES-GCM-256 key from `VAULT_ENCRYPTION_KEY`, or `None` when it is unset/empty.
///
/// The env var's value is SHA-256'd to derive exactly 32 bytes of key material rather than being
/// required to *be* 32 raw bytes. This lets operators supply an arbitrary-length passphrase without
/// a length-validation footgun, while still producing a full-width key. It is deterministic, so the
/// same passphrase always decrypts the same database.
fn encryption_key() -> Option<[u8; 32]> {
    let configured = std::env::var(ENCRYPTION_KEY_ENV).ok()?;
    if configured.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(configured.as_bytes());
    Some(hasher.finalize().into())
}

/// Reports whether signing secrets are being encrypted at rest, for startup logging.
pub fn encryption_enabled() -> bool {
    encryption_key().is_some()
}

/// Encrypts a `signing_secret` for storage, if `VAULT_ENCRYPTION_KEY` is configured.
///
/// Returns the value to write to `api_keys.signing_secret`: either
/// `aesgcm256:<hex nonce><hex ciphertext||tag>`, or — when no encryption key is set — the plaintext
/// unchanged, which is the documented zero-config development fallback.
pub fn seal_signing_secret(plaintext: &str) -> Result<String, AppError> {
    let Some(key_bytes) = encryption_key() else {
        return Ok(plaintext.to_owned());
    };

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| {
        tracing::error!("Invalid AES-GCM key derived from {}: {}", ENCRYPTION_KEY_ENV, e);
        AppError::Internal
    })?;

    // A fresh random nonce per message: GCM catastrophically loses confidentiality if a nonce is
    // ever reused under the same key, so it is never derived from the plaintext or a counter.
    let nonce_bytes: [u8; NONCE_LEN] = rand::rng().random();
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).map_err(|e| {
        tracing::error!("Failed to encrypt signing secret: {}", e);
        AppError::Internal
    })?;

    Ok(format!(
        "{SEALED_PREFIX}{}{}",
        hex::encode(nonce_bytes),
        hex::encode(ciphertext)
    ))
}

/// Recovers a `signing_secret` read from the database, decrypting it when it is sealed.
///
/// A value without the [`SEALED_PREFIX`] is returned as-is (raw development storage). A sealed value
/// encountered while `VAULT_ENCRYPTION_KEY` is unset is a hard error, not a silent pass-through:
/// handing ciphertext back as if it were the secret would make every signature check fail with a
/// misleading `401` instead of surfacing the real misconfiguration.
pub fn open_signing_secret(stored: &str) -> Result<String, AppError> {
    let Some(sealed) = stored.strip_prefix(SEALED_PREFIX) else {
        return Ok(stored.to_owned());
    };

    let Some(key_bytes) = encryption_key() else {
        tracing::error!(
            "Signing secret is encrypted at rest but {} is not set — cannot authenticate \
             requests for this key. Restore the original encryption key.",
            ENCRYPTION_KEY_ENV
        );
        return Err(AppError::Internal);
    };

    let raw = hex::decode(sealed).map_err(|e| {
        tracing::error!("Malformed sealed signing secret (bad hex): {}", e);
        AppError::Internal
    })?;
    if raw.len() <= NONCE_LEN {
        tracing::error!("Malformed sealed signing secret: truncated payload");
        return Err(AppError::Internal);
    }
    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| {
        tracing::error!("Invalid AES-GCM key derived from {}: {}", ENCRYPTION_KEY_ENV, e);
        AppError::Internal
    })?;
    let nonce = Nonce::try_from(nonce_bytes).map_err(|e| {
        tracing::error!("Invalid AES-GCM nonce in stored signing secret: {}", e);
        AppError::Internal
    })?;

    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).map_err(|_| {
        // Deliberately not logging the underlying AEAD error detail: for GCM a decryption failure
        // is always "authentication tag mismatch", which means either the wrong
        // VAULT_ENCRYPTION_KEY or a tampered row. Both need the same operator action.
        tracing::error!(
            "Failed to decrypt signing secret — wrong {} or tampered database row.",
            ENCRYPTION_KEY_ENV
        );
        AppError::Internal
    })?;

    String::from_utf8(plaintext).map_err(|e| {
        tracing::error!("Decrypted signing secret is not valid UTF-8: {}", e);
        AppError::Internal
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `VAULT_ENCRYPTION_KEY` is process-wide state, so the two tests that mutate it must not run
    /// concurrently on different libtest threads (`set_var` is `unsafe` precisely because
    /// concurrent mutation is a data race).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn canonical_v1_payload_is_newline_delimited() {
        assert_eq!(
            canonical_v1_payload("POST", "/api/ban", "1700000000", b"{\"a\":1}"),
            b"POST\n/api/ban\n1700000000\n{\"a\":1}".to_vec(),
            "CANONICAL_V1 joins the four fields with a single LF"
        );
        // An empty body still leaves the third delimiter in place, so "no body" is distinguishable
        // from a body that happens to start where the timestamp ends.
        assert_eq!(
            canonical_v1_payload("GET", "/api/ips", "1700000000", b""),
            b"GET\n/api/ips\n1700000000\n".to_vec()
        );
    }

    #[test]
    fn delimiter_removes_field_boundary_ambiguity() {
        // The concrete attack the delimiter closes: under plain concatenation these two distinct
        // requests hash identically, so a signature for one authenticates the other.
        let shifted = compute_signature("secret", "POS", "T/api/ban", "1700000000", b"");
        let real = compute_signature("secret", "POST", "/api/ban", "1700000000", b"");
        assert_ne!(real.as_deref().ok(), shifted.as_deref().ok());
    }

    #[test]
    fn signature_is_stable_and_order_sensitive() {
        let sig = compute_signature("secret", "POST", "/api/ban", "1700000000", b"{}");
        let same = compute_signature("secret", "POST", "/api/ban", "1700000000", b"{}");
        assert_eq!(sig.as_deref().ok(), same.as_deref().ok());

        // Each component must genuinely feed the MAC, so a change to any one of them changes it.
        for (m, p, t, b) in [
            ("GET", "/api/ban", "1700000000", &b"{}"[..]),
            ("POST", "/api/white", "1700000000", &b"{}"[..]),
            ("POST", "/api/ban", "1700000001", &b"{}"[..]),
            ("POST", "/api/ban", "1700000000", &b"{\"a\":1}"[..]),
        ] {
            let other = compute_signature("secret", m, p, t, b);
            assert_ne!(sig.as_deref().ok(), other.as_deref().ok());
        }
    }

    #[test]
    fn verify_accepts_valid_and_rejects_tampered() {
        let sig = compute_signature("s3cret", "POST", "/api/ban", "1700000000", b"body")
            .expect("HMAC of a non-empty secret cannot fail");

        assert!(verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", &sig));
        // The `sha256=` prefix used by outbound webhook signatures is accepted too.
        assert!(verify_signature(
            "s3cret",
            "POST",
            "/api/ban",
            "1700000000",
            b"body",
            &format!("sha256={sig}")
        ));

        // Wrong secret, mutated body, and non-hex garbage must all fail closed.
        assert!(!verify_signature("other", "POST", "/api/ban", "1700000000", b"body", &sig));
        assert!(!verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body!", &sig));
        assert!(!verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", "zzz"));
        assert!(!verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", ""));
    }

    #[test]
    fn seal_is_a_no_op_without_an_encryption_key() {
        let _guard = ENV_LOCK.lock();
        unsafe { std::env::remove_var(ENCRYPTION_KEY_ENV) };

        let sealed = seal_signing_secret("plain-secret").expect("no-op seal cannot fail");
        assert_eq!(sealed, "plain-secret", "dev fallback stores the secret raw");
        assert_eq!(
            open_signing_secret(&sealed).ok().as_deref(),
            Some("plain-secret")
        );
    }

    #[test]
    fn seal_round_trips_and_is_randomized_when_a_key_is_set() {
        let _guard = ENV_LOCK.lock();
        unsafe { std::env::set_var(ENCRYPTION_KEY_ENV, "unit-test-passphrase") };

        let sealed = seal_signing_secret("plain-secret").expect("seal with a valid key");
        assert!(sealed.starts_with(SEALED_PREFIX), "sealed values are tagged");
        assert!(!sealed.contains("plain-secret"), "plaintext must not survive");
        assert_eq!(
            open_signing_secret(&sealed).ok().as_deref(),
            Some("plain-secret")
        );

        // A fresh nonce per call means the same plaintext never seals to the same ciphertext.
        let sealed_again = seal_signing_secret("plain-secret").expect("seal with a valid key");
        assert_ne!(sealed, sealed_again);

        // Tampering with the ciphertext must be caught by the GCM auth tag, not silently accepted.
        let mut tampered = sealed.clone().into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'a' { b'b' } else { b'a' };
        let tampered = String::from_utf8(tampered).expect("hex stays ASCII");
        assert!(open_signing_secret(&tampered).is_err());

        unsafe { std::env::remove_var(ENCRYPTION_KEY_ENV) };
    }
}
