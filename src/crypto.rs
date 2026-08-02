//! Request signing (HMAC-SHA256) and signing-secret encryption at rest (XChaCha20-Poly1305).
//!
//! Two distinct concerns live here, both keyed off an API key's `signing_secret`:
//!
//! 1. **Request authentication** — every `/api/*` call carries `X-API-Key` (identity lookup),
//!    `X-Timestamp` (anti-replay) and `X-Signature-256` (proof of possession). The signature is an
//!    HMAC-SHA256 over the **CANONICAL_V1** string `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY` using the
//!    looked-up key's `signing_secret`, where `TARGET` is the **full request target including the
//!    query string**. See [`compute_signature`] and [`verify_signature`].
//!
//!    The same canonical string is used for outbound `CANONICAL_V1` webhook dispatches
//!    (`crate::webhooks`), so a `simply_ip_vault` instance can sign a request that another instance
//!    — or `simply_hook_executor` — verifies with identical code.
//! 2. **Secret confidentiality at rest** — unlike `key_hash` (a one-way hash), a `signing_secret`
//!    must be recoverable verbatim to verify a signature, so it cannot be hashed. It is therefore
//!    sealed with XChaCha20-Poly1305 under a key supplied out-of-band, so read access to the
//!    database alone is not enough to forge signatures. See [`SecretCipher`].

// `aes_gcm` and `chacha20poly1305` re-export the same `aead` traits, so one import serves both
// ciphers. The AES types are reached through the legacy read path only — see `open_legacy_gcm`.
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
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
///
/// The window bounds *how long* a captured request stays usable; it does not stop it being used
/// twice inside that window. [`crate::replay::ReplayGuard`] closes that second gap.
pub const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;

/// Name of the environment variable holding the master encryption key for `signing_secret` values.
pub const ENCRYPTION_KEY_ENV: &str = "VAULT_ENCRYPTION_KEY";

/// Accepted alias for [`ENCRYPTION_KEY_ENV`], matching the name `simply_hook_executor` uses so one
/// provisioning system can supply both services. [`ENCRYPTION_KEY_ENV`] wins when both are set.
pub const ENCRYPTION_KEY_ENV_ALIAS: &str = "SIGNING_SECRET_KEY";

/// Required encryption key width, in bytes.
const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce width, in bytes (192 bits).
const NONCE_LEN: usize = 24;

/// Prefix marking a value stored without encryption.
const PLAINTEXT_PREFIX: &str = "v1.plain.";
/// Prefix marking a value sealed with XChaCha20-Poly1305.
const SEALED_PREFIX: &str = "v1.xchacha20poly1305.";
/// Prefix marking a value sealed by an earlier version with AES-GCM-256. Read-only: nothing writes
/// this format any more.
const LEGACY_GCM_PREFIX: &str = "aesgcm256:";
/// AES-GCM nonce width, in bytes. Only used to open [`LEGACY_GCM_PREFIX`] values.
const LEGACY_GCM_NONCE_LEN: usize = 12;

/// Generates a fresh 32-byte HMAC signing secret, hex-encoded.
///
/// Deliberately the same shape and entropy as [`crate::api::generate_random_key`] — but a wholly
/// independent value: knowing a key's public `X-API-Key` must never reveal its signing secret.
pub fn generate_signing_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Builds the **CANONICAL_V1** byte string that gets signed:
/// `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`.
///
/// The four fields are joined by a single `\n` (LF), with no trailing newline. `method` is expected
/// uppercase. `target` is the request target **including the query string** when one is present —
/// see [`verify_signature`] for why.
///
/// The newline delimiter is what makes the encoding *unambiguous*: with plain concatenation, the
/// pair `("POST", "/api/ban")` and `("POS", "T/api/ban")` produce identical bytes, so a signature
/// over one is a valid signature over the other. A delimiter that cannot appear in a method or a URL
/// target removes that whole class of boundary confusion. It is also the format
/// `simply_hook_executor` speaks, so one canonical string now serves both the inbound API and
/// outbound `CANONICAL_V1` webhook dispatches.
///
/// Outbound webhook templates (`webhook_configs.hmac_template`) build their own string and pass
/// whatever `{path}` resolves to; this function does not care which of the two it is handed.
pub fn canonical_v1_payload(method: &str, target: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(method.len() + target.len() + timestamp.len() + body.len() + 3);
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(target.as_bytes());
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
    target: &str,
    timestamp: &str,
    body: &[u8],
) -> Result<String, AppError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|e| {
        tracing::error!("Failed to build HMAC from signing secret: {}", e);
        AppError::Internal
    })?;
    mac.update(&canonical_v1_payload(method, target, timestamp, body));
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Verifies a caller-supplied `X-Signature-256` against the expected HMAC.
///
/// # Constant-time comparison
///
/// The digest comparison goes through `Mac::verify_slice`, whose implementation chain is
/// `Mac::verify_slice → CtOutput::eq → subtle::ConstantTimeEq::ct_eq`. It rejects a tag of the wrong
/// length first — that leaks only the digest width, a public constant — and then compares all 32
/// bytes in constant time. Comparing the hex strings with `==` instead would let an attacker recover
/// a valid signature one byte at a time by measuring response latency, so this must never be
/// "simplified" into an equality check on the decoded bytes or the hex text.
///
/// # Why the query string is covered
///
/// `target` is the **full request target**, query string included. An earlier revision signed the
/// path alone, on the reasoning that reverse proxies reorder or append query parameters and that
/// query parameters on `/api/*` were read-only filters. That second half stopped being true: `?hard=true`
/// on `DELETE /api/ips/{id}` escalates a reversible soft delete into an irreversible purge, and
/// `?include_deleted=true` widens `GET /api/ips` to the master trash view. With the query outside
/// the signed material, an on-path attacker who cannot forge a signature could still rewrite a
/// captured `DELETE /api/ips/{id}` into `…?hard=true` inside the replay window. Signing the whole
/// target closes that; a proxy that rewrites query strings must now be configured not to.
///
/// A `sha256=` prefix on `provided` is accepted and stripped, matching the format this project
/// already uses for outbound webhook signatures, so one signing helper can serve both directions.
///
/// # Return value
///
/// `Some(digest)` on success, carrying the **raw decoded digest bytes**, and `None` on any failure
/// (malformed hex, wrong tag width, wrong secret, tampered payload).
///
/// Returning the bytes rather than a bare `bool` is what lets [`crate::replay::ReplayGuard`] key on
/// canonical material without re-parsing the header. It also normalizes spelling by construction:
/// `sha256=AB…` and `sha256=ab…` are the same signature and decode to the same bytes, so they can
/// never be recorded as two distinct single uses. The previous `bool` shape forced the middleware to
/// re-derive a token from the header text, which upheld the same property only indirectly.
pub fn verify_signature(
    secret: &str,
    method: &str,
    target: &str,
    timestamp: &str,
    body: &[u8],
    provided: &str,
) -> Option<Vec<u8>> {
    let provided = provided
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or(provided.trim());

    let provided_bytes = hex::decode(provided).ok()?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(&canonical_v1_payload(method, target, timestamp, body));
    mac.verify_slice(&provided_bytes).ok()?;

    Some(provided_bytes)
}

/// Failure modes for building the cipher or opening a stored secret.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The configured encryption key is not exactly 64 hex characters.
    #[error(
        "{ENCRYPTION_KEY_ENV} must be exactly {} hex characters ({KEY_LEN} bytes); generate one \
         with `openssl rand -hex {KEY_LEN}`",
        KEY_LEN * 2
    )]
    InvalidKey,
    /// The stored value is not in any recognized format.
    #[error("Stored signing secret is malformed or was written by a newer version")]
    MalformedCiphertext,
    /// The ciphertext failed authentication — wrong key, or the row was tampered with.
    #[error(
        "Stored signing secret could not be decrypted. This usually means {ENCRYPTION_KEY_ENV} \
         does not match the key the secret was written with"
    )]
    DecryptionFailed,
    /// The cipher itself failed.
    #[error("Encryption failed")]
    EncryptionFailed,
}

impl From<CryptoError> for AppError {
    /// Every decryption failure is an operator problem, never a caller problem, so it becomes a
    /// generic `500` rather than anything a client could learn from.
    fn from(e: CryptoError) -> Self {
        tracing::error!("Signing-secret cipher error: {e}");
        AppError::Internal
    }
}

/// How recoverable secrets are protected at rest.
///
/// Constructed **once** at startup and carried in [`crate::state::AppState`]. An earlier revision
/// re-read `VAULT_ENCRYPTION_KEY` from the environment and re-derived the key on every seal and
/// open — that is once per authenticated request, and it meant the key backing an authorization
/// decision could change under a running process.
pub enum SecretCipher {
    /// No encryption key configured: secrets are stored hex-encoded but unencrypted.
    ///
    /// Kept as a supported mode so the daemon still runs with zero configuration, but it means
    /// database confidentiality is the *only* thing protecting signing secrets.
    Plaintext,
    /// Secrets are sealed with XChaCha20-Poly1305 under the configured key.
    ///
    /// `legacy_gcm` is the AES-GCM-256 key derived the way earlier versions derived it — SHA-256 of
    /// the raw environment value — so rows already written as `aesgcm256:` stay readable. It is
    /// never used to write.
    Sealed {
        /// The cipher used for every new seal.
        cipher: Box<XChaCha20Poly1305>,
        /// Read-only key material for opening pre-existing AES-GCM rows.
        legacy_gcm: [u8; KEY_LEN],
    },
}

impl std::fmt::Debug for SecretCipher {
    /// Never renders key material, so a `{:?}` of application state cannot leak it into a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plaintext => f.write_str("SecretCipher::Plaintext"),
            Self::Sealed { .. } => f.write_str("SecretCipher::Sealed(<redacted>)"),
        }
    }
}

impl SecretCipher {
    /// Builds the cipher from [`ENCRYPTION_KEY_ENV`] (or [`ENCRYPTION_KEY_ENV_ALIAS`]).
    ///
    /// A malformed key is a **hard error**, not a fallback to plaintext: an operator who set the
    /// variable believes their secrets are encrypted, and silently writing them in the clear would
    /// betray that belief at exactly the wrong moment. `main` propagates this, so the daemon refuses
    /// to start rather than degrading quietly.
    pub fn from_env() -> Result<Self, CryptoError> {
        let configured = std::env::var(ENCRYPTION_KEY_ENV)
            .ok()
            .filter(|raw| !raw.trim().is_empty())
            .or_else(|| {
                std::env::var(ENCRYPTION_KEY_ENV_ALIAS)
                    .ok()
                    .filter(|raw| !raw.trim().is_empty())
            });

        match configured {
            Some(raw) => Self::from_hex_key(raw.trim()),
            None => Ok(Self::Plaintext),
        }
    }

    /// Builds a cipher from a hex-encoded 32-byte key.
    ///
    /// The legacy AES-GCM key is derived from the *raw hex text* rather than the decoded bytes,
    /// because that is precisely what the previous implementation hashed. Keeping the same
    /// `VAULT_ENCRYPTION_KEY` value therefore keeps existing `aesgcm256:` rows readable across the
    /// upgrade — provided that value was already 64 hex characters. If it was a free-form
    /// passphrase, startup now fails with [`CryptoError::InvalidKey`], which is the honest outcome:
    /// an unbounded passphrase run through a single SHA-256 has whatever entropy the operator typed,
    /// and the old code could not tell `openssl rand -hex 32` from `password`.
    pub fn from_hex_key(hex_key: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_key).map_err(|_| CryptoError::InvalidKey)?;
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        let key = Key::try_from(bytes.as_slice()).map_err(|_| CryptoError::InvalidKey)?;

        let mut hasher = Sha256::new();
        hasher.update(hex_key.as_bytes());
        let legacy_gcm: [u8; KEY_LEN] = hasher.finalize().into();

        Ok(Self::Sealed {
            cipher: Box::new(XChaCha20Poly1305::new(&key)),
            legacy_gcm,
        })
    }

    /// Whether secrets are actually being encrypted.
    pub fn is_encrypting(&self) -> bool {
        matches!(self, Self::Sealed { .. })
    }

    /// Encodes a secret for storage.
    ///
    /// Even the unencrypted mode hex-encodes, so the raw secret is never a substring of the stored
    /// column and a casual `grep` of a database dump does not surface it.
    pub fn seal(&self, plaintext: &str) -> Result<String, CryptoError> {
        match self {
            Self::Plaintext => Ok(format!("{PLAINTEXT_PREFIX}{}", hex::encode(plaintext))),
            Self::Sealed { cipher, .. } => {
                // A fresh random nonce per secret. XChaCha20's 192-bit nonce is wide enough that
                // random generation is collision-safe with no counter state to persist — which is
                // the whole reason for preferring it over AES-GCM's 96-bit nonce here.
                let nonce_bytes: [u8; NONCE_LEN] = rand::rng().random();
                let nonce = XNonce::from(nonce_bytes);
                let ciphertext = cipher
                    .encrypt(&nonce, plaintext.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed)?;
                Ok(format!(
                    "{SEALED_PREFIX}{}.{}",
                    hex::encode(nonce_bytes),
                    hex::encode(ciphertext)
                ))
            }
        }
    }

    /// Recovers a secret from storage.
    ///
    /// Exactly three shapes are accepted, and **anything else is an error**:
    ///
    /// 1. `v1.xchacha20poly1305.<nonce>.<ct>` — the current format.
    /// 2. `v1.plain.<hex>` — the current unencrypted format.
    /// 3. `aesgcm256:<nonce><ct>` — written by earlier versions; readable, never rewritten.
    ///
    /// Rows only move to the current format when the key is next rotated, which keeps the upgrade
    /// non-destructive: no migration touches secret material, and a downgrade still reads everything
    /// it wrote itself.
    ///
    /// # Why an unprefixed value is now rejected
    ///
    /// A fourth shape used to be accepted: an unprefixed string was returned **verbatim**, on the
    /// reasoning that it was a bare secret written before any prefix existed. That fallback was a
    /// silent failure mode wearing a compatibility costume, because "no recognized prefix" is not
    /// evidence of an old row — it is evidence of *nothing in particular*, and every other cause is
    /// worse:
    ///
    /// - A `v1.plain.` or `v1.xchacha20poly1305.` value whose prefix was lost or corrupted — by a
    ///   botched migration, a truncated column, a bad restore — would be fed to `Hmac::new_from_slice`
    ///   as though the surviving hex text were the secret. Every request would then fail signature
    ///   verification with `401`, pointing the operator at the *client* rather than at the row.
    /// - A partially-written sealed value would be used as HMAC key material.
    /// - Anything an attacker managed to write into the column through an unrelated defect would be
    ///   accepted as a signing secret rather than refused.
    ///
    /// Returning [`CryptoError::MalformedCiphertext`] instead makes the failure loud and attributable:
    /// it surfaces as a `500` with the row's identity in the log, which is what an operator needs to
    /// see. The recovery path is `POST /api/keys/{id}/rotate-secret`, which is master-only and
    /// replaces just the signing secret.
    ///
    /// **Upgrade note:** any deployment still holding an unprefixed bare secret must rotate that key's
    /// secret before upgrading, or it stops authenticating. `AGENT.MD` §1 and `SCHEMA.MD` §1 both
    /// previously documented the bare shape as readable and have been amended.
    pub fn open(&self, stored: &str) -> Result<String, CryptoError> {
        if let Some(encoded) = stored.strip_prefix(PLAINTEXT_PREFIX) {
            let bytes = hex::decode(encoded).map_err(|_| CryptoError::MalformedCiphertext)?;
            return String::from_utf8(bytes).map_err(|_| CryptoError::MalformedCiphertext);
        }

        if let Some(body) = stored.strip_prefix(SEALED_PREFIX) {
            let (nonce_hex, ciphertext_hex) =
                body.split_once('.').ok_or(CryptoError::MalformedCiphertext)?;
            let nonce_bytes =
                hex::decode(nonce_hex).map_err(|_| CryptoError::MalformedCiphertext)?;
            if nonce_bytes.len() != NONCE_LEN {
                return Err(CryptoError::MalformedCiphertext);
            }
            let ciphertext =
                hex::decode(ciphertext_hex).map_err(|_| CryptoError::MalformedCiphertext)?;

            let Self::Sealed { cipher, .. } = self else {
                // A sealed row with no key configured. Reported as a key mismatch rather than as
                // corruption, because the fix is to set VAULT_ENCRYPTION_KEY, and because handing
                // ciphertext back as if it were the secret would surface as a misleading 401 on
                // every request instead of the real misconfiguration.
                return Err(CryptoError::DecryptionFailed);
            };
            let nonce =
                XNonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::MalformedCiphertext)?;
            let plaintext = cipher
                .decrypt(&nonce, ciphertext.as_ref())
                .map_err(|_| CryptoError::DecryptionFailed)?;
            return String::from_utf8(plaintext).map_err(|_| CryptoError::MalformedCiphertext);
        }

        if let Some(sealed) = stored.strip_prefix(LEGACY_GCM_PREFIX) {
            return self.open_legacy_gcm(sealed);
        }

        // Fail closed. See the "Why an unprefixed value is now rejected" note above: an unrecognized
        // shape is not evidence of a pre-prefix row, and treating it as one turns a damaged column
        // into silently-wrong HMAC key material.
        Err(CryptoError::MalformedCiphertext)
    }

    /// Opens an `aesgcm256:` value written by an earlier version.
    ///
    /// Exists solely so upgrading does not invalidate every key issued while AES-GCM was in use.
    /// There is no corresponding write path.
    fn open_legacy_gcm(&self, sealed: &str) -> Result<String, CryptoError> {
        let Self::Sealed { legacy_gcm, .. } = self else {
            return Err(CryptoError::DecryptionFailed);
        };

        let raw = hex::decode(sealed).map_err(|_| CryptoError::MalformedCiphertext)?;
        if raw.len() <= LEGACY_GCM_NONCE_LEN {
            return Err(CryptoError::MalformedCiphertext);
        }
        let (nonce_bytes, ciphertext) = raw.split_at(LEGACY_GCM_NONCE_LEN);

        let cipher = Aes256Gcm::new_from_slice(legacy_gcm).map_err(|_| CryptoError::InvalidKey)?;
        let nonce = GcmNonce::try_from(nonce_bytes).map_err(|_| CryptoError::MalformedCiphertext)?;
        let plaintext = cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)?;

        tracing::debug!(
            "Opened a legacy AES-GCM signing secret; it will move to XChaCha20-Poly1305 on the next \
             rotation."
        );
        String::from_utf8(plaintext).map_err(|_| CryptoError::MalformedCiphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

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

    /// The query string is part of the signed target, so tampering with it invalidates the
    /// signature. This is the property that stops a captured `DELETE /api/ips/{id}` from being
    /// rewritten into `…?hard=true` on the wire.
    #[test]
    fn the_query_string_is_covered_by_the_signature() {
        let bare = compute_signature("secret", "DELETE", "/api/ips/42", "1700000000", b"");
        let escalated =
            compute_signature("secret", "DELETE", "/api/ips/42?hard=true", "1700000000", b"");
        assert_ne!(bare.as_deref().ok(), escalated.as_deref().ok());

        // Reordering or adding a filter is equally covered.
        let listing = compute_signature("secret", "GET", "/api/ips?limit=10", "1700000000", b"");
        let widened = compute_signature(
            "secret",
            "GET",
            "/api/ips?limit=10&include_deleted=true",
            "1700000000",
            b"",
        );
        assert_ne!(listing.as_deref().ok(), widened.as_deref().ok());
    }

    #[test]
    fn verify_accepts_valid_and_rejects_tampered() {
        let sig = compute_signature("s3cret", "POST", "/api/ban", "1700000000", b"body")
            .expect("HMAC of a non-empty secret cannot fail");

        assert!(verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", &sig).is_some());
        // The `sha256=` prefix used by outbound webhook signatures is accepted too.
        assert!(verify_signature(
            "s3cret",
            "POST",
            "/api/ban",
            "1700000000",
            b"body",
            &format!("sha256={sig}")
        ).is_some());

        // Wrong secret, mutated body, and non-hex garbage must all fail closed.
        assert!(verify_signature("other", "POST", "/api/ban", "1700000000", b"body", &sig).is_none());
        assert!(verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body!", &sig).is_none());
        assert!(verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", "zzz").is_none());
        assert!(verify_signature("s3cret", "POST", "/api/ban", "1700000000", b"body", "").is_none());
    }

    /// A tag of the wrong width must be rejected outright rather than compared against a truncated
    /// expectation — the failure mode a hand-rolled comparison would introduce.
    #[test]
    fn tags_of_the_wrong_length_are_rejected() {
        let sig = compute_signature("s3cret", "GET", "/api/ips", "1700000000", b"")
            .expect("HMAC of a non-empty secret cannot fail");
        for wrong in [&sig[..62], &sig[..2], "", &format!("{sig}00")] {
            assert!(
                verify_signature("s3cret", "GET", "/api/ips", "1700000000", b"", wrong).is_none(),
                "a {}-character tag must be rejected",
                wrong.len()
            );
        }
        assert!(verify_signature("s3cret", "GET", "/api/ips", "1700000000", b"", &sig).is_some());
    }

    #[test]
    fn plaintext_mode_round_trips_without_exposing_the_secret() {
        let cipher = SecretCipher::Plaintext;
        assert!(!cipher.is_encrypting());

        let sealed = cipher.seal("s3cr3t").expect("sealing succeeds");
        assert!(sealed.starts_with(PLAINTEXT_PREFIX));
        // Even unencrypted storage is hex-encoded, so `grep` over a dump does not surface it.
        assert!(!sealed.contains("s3cr3t"));
        assert_eq!(cipher.open(&sealed).expect("opening succeeds"), "s3cr3t");
    }

    #[test]
    fn sealed_mode_round_trips_and_hides_the_secret() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        assert!(cipher.is_encrypting());

        let sealed = cipher.seal("s3cr3t").expect("sealing succeeds");
        assert!(sealed.starts_with(SEALED_PREFIX));
        assert!(!sealed.contains("s3cr3t"));
        assert_eq!(cipher.open(&sealed).expect("opening succeeds"), "s3cr3t");
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let first = cipher.seal("same-input").expect("sealing succeeds");
        let second = cipher.seal("same-input").expect("sealing succeeds");
        assert_ne!(first, second, "identical plaintexts must not seal identically");
        assert_eq!(cipher.open(&first).expect("opens"), cipher.open(&second).expect("opens"));
    }

    #[test]
    fn a_wrong_key_cannot_open_a_sealed_secret() {
        let writer = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let other = SecretCipher::from_hex_key(
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        )
        .expect("valid key");

        let sealed = writer.seal("s3cr3t").expect("sealing succeeds");
        assert!(matches!(other.open(&sealed), Err(CryptoError::DecryptionFailed)));
        // Nor can a daemon that lost its key entirely.
        assert!(matches!(
            SecretCipher::Plaintext.open(&sealed),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let sealed = cipher.seal("s3cr3t").expect("sealing succeeds");

        // Flip the final ciphertext nibble; Poly1305 authentication must reject it.
        let mut chars: Vec<char> = sealed.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();

        assert!(matches!(cipher.open(&tampered), Err(CryptoError::DecryptionFailed)));
    }

    /// Fail closed at startup: a key that is not exactly 32 bytes of hex is an error, never a
    /// silent downgrade to writing secrets in the clear.
    #[test]
    fn malformed_keys_are_rejected_rather_than_falling_back() {
        for bad in [
            "not-hex",
            "00ff",                                                               // too short
            "",                                                                   // empty
            &format!("{TEST_KEY}00"),                                             // too long
            "zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",   // bad nibble
        ] {
            assert!(
                matches!(SecretCipher::from_hex_key(bad), Err(CryptoError::InvalidKey)),
                "{bad:?} must be rejected"
            );
        }
        assert!(SecretCipher::from_hex_key(TEST_KEY).is_ok());
    }

    #[test]
    fn malformed_stored_values_are_rejected() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        for malformed in [
            "v1.xchacha20poly1305.nodot",
            "v1.xchacha20poly1305.zz.zz",
            "v1.xchacha20poly1305.00ff.aabb", // nonce too short
            "v1.plain.zz",
            "aesgcm256:zz",
            "aesgcm256:00",
        ] {
            assert!(cipher.open(malformed).is_err(), "{malformed:?} should not open");
        }
    }

    /// An unprefixed row is **refused**, reversing what this test used to assert.
    ///
    /// The old contract returned such a value verbatim, on the reasoning that it was a bare secret
    /// written before any prefix existed. That traded a real failure mode for a hypothetical one: a
    /// pre-prefix row is only one of the ways a value can arrive without a prefix, and every other
    /// way — a truncated column, a botched migration, a partially-written seal, a value an attacker
    /// wrote through an unrelated defect — ends with unknown bytes used as HMAC key material and no
    /// signal that anything is wrong. Failing closed makes the damaged row say so.
    ///
    /// Operators still holding a bare secret must rotate it (`POST /api/keys/{id}/rotate-secret`)
    /// before upgrading; `AGENT.MD` §1 and `SCHEMA.MD` §1 record that.
    #[test]
    fn an_unprefixed_row_is_refused_rather_than_read_verbatim() {
        for cipher in [SecretCipher::Plaintext, SecretCipher::from_hex_key(TEST_KEY).expect("valid key")] {
            assert!(
                matches!(cipher.open("bare-legacy-secret"), Err(CryptoError::MalformedCiphertext)),
                "an unprefixed value must not be accepted as a signing secret"
            );
            // The empty column — the shape a failed write leaves behind — is refused on the same path
            // rather than becoming an empty HMAC key, which would verify forgeable signatures.
            assert!(matches!(cipher.open(""), Err(CryptoError::MalformedCiphertext)));
        }
    }

    /// The upgrade path that matters: a secret sealed by the previous AES-GCM implementation, under
    /// the same `VAULT_ENCRYPTION_KEY`, must still open. Written here exactly as the old code wrote
    /// it — SHA-256 of the raw env text as the key, 12-byte nonce, `aesgcm256:` prefix — so this
    /// test would catch a change to the derivation that silently orphaned every existing row.
    #[test]
    fn a_legacy_aes_gcm_row_still_opens_under_the_same_key() {
        let mut hasher = Sha256::new();
        hasher.update(TEST_KEY.as_bytes());
        let legacy_key: [u8; KEY_LEN] = hasher.finalize().into();

        let legacy_cipher = Aes256Gcm::new_from_slice(&legacy_key).expect("valid AES key");
        let nonce_bytes = [7u8; LEGACY_GCM_NONCE_LEN];
        let nonce = GcmNonce::from(nonce_bytes);
        let ciphertext = legacy_cipher
            .encrypt(&nonce, b"issued-under-aes".as_ref())
            .expect("legacy encryption succeeds");
        let stored = format!(
            "{LEGACY_GCM_PREFIX}{}{}",
            hex::encode(nonce_bytes),
            hex::encode(&ciphertext)
        );

        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        assert_eq!(cipher.open(&stored).expect("legacy row opens"), "issued-under-aes");

        // ...and a different key cannot open it, so the legacy path is not a bypass.
        let other = SecretCipher::from_hex_key(
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        )
        .expect("valid key");
        assert!(matches!(other.open(&stored), Err(CryptoError::DecryptionFailed)));
        // Nor can a daemon with no key at all.
        assert!(matches!(
            SecretCipher::Plaintext.open(&stored),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    /// Nothing writes AES-GCM any more: a re-seal of a legacy value produces the current format.
    #[test]
    fn resealing_moves_a_legacy_value_to_xchacha20() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let resealed = cipher.seal("issued-under-aes").expect("sealing succeeds");
        assert!(resealed.starts_with(SEALED_PREFIX));
        assert!(!resealed.starts_with(LEGACY_GCM_PREFIX));
    }

    /// `Debug` must never render key material — an `AppState` dump would otherwise leak it.
    #[test]
    fn debug_redacts_key_material() {
        let cipher = SecretCipher::from_hex_key(TEST_KEY).expect("valid key");
        let rendered = format!("{cipher:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains(TEST_KEY));
        assert_eq!(format!("{:?}", SecretCipher::Plaintext), "SecretCipher::Plaintext");
    }
}
