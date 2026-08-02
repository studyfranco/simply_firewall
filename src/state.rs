//! Application state: the database handle, the background webhook channel, and the three security
//! primitives every request consults — the trusted-proxy set, the at-rest cipher, and the
//! anti-replay guard.
//!
//! All three are built **once at startup** and carried here rather than re-derived per request.
//! That is deliberate: each is an input to an authorization decision, and a value that can change
//! under a running process (an environment variable re-read mid-flight, a cipher rebuilt from a key
//! that may since have been edited) is one that cannot be reasoned about.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::TrustedProxies;
use crate::crypto::{MAX_TIMESTAMP_SKEW_SECS, SecretCipher};

/// Milliseconds SQLite waits on a locked database before returning `SQLITE_BUSY`.
const SQLITE_BUSY_TIMEOUT_MS: u32 = 5000;

/// Applies SQLite's concurrency pragmas, if and only if the backend is SQLite.
///
/// Two settings, both about the same problem — SQLite's default rollback journal takes a database-
/// wide exclusive lock for every write:
///
/// - **`journal_mode=WAL`** lets readers proceed during a write instead of blocking on it. This
///   service reads far more than it writes (every authenticated request does a key lookup; the
///   dashboard polls listings) while the webhook worker and retention sweep write from background
///   tasks, so without WAL a single slow write stalls unrelated reads.
/// - **`busy_timeout=5000`** makes a writer that finds the database locked wait up to 5s rather
///   than failing instantly with `SQLITE_BUSY`. Concurrent writes are rare here but not impossible
///   (a burst of bans, or a sweep overlapping a dispatch), and a transient lock should cost latency,
///   not a `500`.
///
/// The two differ in scope, which is worth stating precisely rather than implying both are
/// pool-wide: **`journal_mode` is persistent** — recorded in the database file header, so setting it
/// once applies to every future connection and every future run — while **`busy_timeout` is
/// per-connection**, and the pool-wide guarantee comes from SQLx applying its own five-second
/// default to each SQLite connection it opens. This call makes that intent explicit rather than
/// being the sole mechanism.
///
/// Guarded on the backend rather than on the URL string: `PRAGMA` is SQLite-specific and would be a
/// syntax error on PostgreSQL or MySQL. This is the one deliberate exception to the SQL-agnostic
/// rule in `AGENT.MD` — it configures the *engine*, not a query, and every other backend skips it.
///
/// # Failure handling
///
/// **Never fatal.** Every failure is logged and swallowed, and the function still returns `Ok`. Two
/// reasons. The benign one: an in-memory database (`sqlite::memory:`, which the whole test suite
/// uses) reports `journal_mode=memory` and cannot be switched to WAL, since there is no file to
/// write a log beside — SQLite declines silently rather than erroring, which is why the mode is read
/// back instead of inferred from a clean return. The important one: refusing to boot over a
/// concurrency setting that did not apply would trade a real outage for a theoretical slowdown, on a
/// read-only mount or an exotic filesystem that is otherwise perfectly serviceable.
pub async fn apply_sqlite_pragmas(db: &DatabaseConnection) {
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return;
    }

    match db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA journal_mode=WAL;",
        ))
        .await
    {
        Ok(Some(row)) => match row.try_get::<String>("", "journal_mode") {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => {
                tracing::info!("SQLite journal_mode=WAL enabled (readers proceed during writes).");
            }
            Ok(mode) => tracing::info!(
                "SQLite journal_mode is '{mode}' rather than WAL; this is normal for in-memory and \
                 read-only databases. Continuing."
            ),
            Err(e) => tracing::warn!("Could not read back the SQLite journal mode: {e}. Continuing."),
        },
        Ok(None) => tracing::warn!("PRAGMA journal_mode returned no row; leaving the default."),
        Err(e) => tracing::warn!("Could not enable SQLite WAL mode: {e}. Continuing without it."),
    }

    match db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!("PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};"),
        ))
        .await
    {
        Ok(_) => tracing::info!("SQLite busy_timeout set to {SQLITE_BUSY_TIMEOUT_MS}ms."),
        Err(e) => tracing::warn!(
            "Could not set the SQLite busy timeout: {e}. Continuing with the driver default."
        ),
    }
}

/// Upper bound on how many signatures the [`ReplayGuard`] remembers at once.
///
/// Entries expire on their own after [`MAX_TIMESTAMP_SKEW_SECS`], so in steady state this is never
/// reached — 300 seconds of traffic would have to exceed it. It exists as a backstop: an
/// authenticated client issuing signed requests faster than that is either pathological or hostile,
/// and unbounded growth in a map that lives for the process's lifetime is the wrong failure mode.
/// On overflow the guard prunes expired entries first and, if that is not enough, clears the map —
/// which loses replay protection for the current window rather than the service.
const MAX_TRACKED_SIGNATURES: usize = 100_000;

/// Rejects a validly-signed request that has already been seen inside the anti-replay window.
///
/// The timestamp window alone is necessary but not sufficient. It bounds *how long* a captured
/// request stays usable; it says nothing about using it *twice*. An attacker who observes one
/// authentic signed request — on a plain-HTTP LAN link, in a proxy log, in a mirrored packet
/// capture — can resend it verbatim as many times as they like for the next 300 seconds, and every
/// copy verifies because every field it covers is unchanged. For `POST /api/ban` that is a duplicate
/// entry; for anything non-idempotent it is a repeated side effect the caller never asked for.
///
/// The guard remembers each accepted `(key, signature)` pair until its timestamp leaves the window,
/// at which point the freshness check takes over and the entry is no longer needed. Both halves are
/// required: the window bounds the memory the guard needs, and the guard closes the window's gap.
///
/// Cheap to clone — the map is shared behind an [`Arc`].
///
/// # Ordering
///
/// This must be consulted **after** the HMAC verifies, never before. Recording unverified
/// signatures would let any unauthenticated caller fill the map with garbage (a memory-exhaustion
/// path that needs no credentials) and, worse, pre-insert a signature it expects a legitimate client
/// to send, turning the replay guard into a denial-of-service tool against that client.
#[derive(Clone, Debug, Default)]
pub struct ReplayGuard {
    seen: Arc<Mutex<HashMap<String, i64>>>,
}

impl ReplayGuard {
    /// Builds an empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a freshly-verified signature, returning `false` if it had already been seen.
    ///
    /// `timestamp` is the request's own `X-Timestamp`, already validated to be inside the window;
    /// it is what decides when the entry may be forgotten. Keying on the key id as well as the
    /// signature keeps two keys' namespaces separate without relying on HMAC collision resistance
    /// for a property that costs nothing to guarantee directly.
    ///
    /// A poisoned mutex is treated as "cannot prove this is fresh" and the request is rejected:
    /// failing closed on a replay check is the only safe direction, and the condition means a thread
    /// panicked while holding the map, which is not a state to keep authenticating through.
    pub fn observe(&self, key_id: Uuid, signature: &str, timestamp: i64) -> bool {
        let now = chrono::Utc::now().timestamp();
        let Ok(mut seen) = self.seen.lock() else {
            tracing::error!("Replay guard mutex poisoned; rejecting the request rather than \
                             authenticating without replay protection.");
            return false;
        };

        if seen.len() >= MAX_TRACKED_SIGNATURES {
            tracing::warn!(
                "Replay guard exceeded {MAX_TRACKED_SIGNATURES} tracked signatures within the \
                 {MAX_TIMESTAMP_SKEW_SECS}s window; clearing it. Replay protection is degraded for \
                 the current window."
            );
            seen.clear();
        }

        // `insert` returns the previous value, so a replay is precisely a `Some`.
        let is_new = seen.insert(format!("{key_id}:{signature}"), timestamp).is_none();

        // Amortized cleanup, run *after* the insert so it also drops the entry just added when that
        // entry is itself outside the window. Such a request cannot be replayed successfully — the
        // freshness check rejects it before this guard is ever consulted — so remembering it would
        // be pure growth. The map therefore only ever retains in-window entries, which is what
        // bounds it by the window rather than by uptime.
        seen.retain(|_, ts| (now - *ts).abs() <= MAX_TIMESTAMP_SKEW_SECS);

        is_new
    }

    /// How many signatures are currently remembered. Test-facing.
    pub fn tracked(&self) -> usize {
        self.seen.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// Represents a webhook event triggered by the system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// The action that occurred: `"IP_ADD"`, `"IP_UPDATE"`, or `"IP_DELETE"` — matches
    /// `audit_log::Model::action`'s vocabulary and is what `webhook_config::Model::events`
    /// filters against in the dispatcher.
    pub action: String,
    /// Target address
    pub address: String,
    /// Is whitelist
    pub is_whitelist: bool,
    /// Associated group ID
    pub group_id: Option<Uuid>,
    /// Cause for the event
    pub cause: Option<String>,
}

/// Global application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub db: DatabaseConnection,
    /// Channel sender for webhook events
    pub webhook_tx: mpsc::Sender<WebhookEvent>,
    /// Peers allowed to set `X-Forwarded-For`/`X-Real-IP`, from
    /// [`TRUSTED_PROXIES`](crate::config::TRUSTED_PROXIES_ENV) — literal CIDRs and/or hostnames
    /// resolved at request time.
    ///
    /// **Empty means no proxy is trusted**, so forwarding headers are ignored entirely. See
    /// [`crate::config::resolve_client_ip`].
    pub trusted_proxies: TrustedProxies,
    /// The at-rest cipher for `signing_secret`, built once from the environment at startup.
    ///
    /// Shared behind an [`Arc`] because [`SecretCipher`] holds cipher state that is expensive to
    /// rebuild and must not be rebuilt per request.
    pub cipher: Arc<SecretCipher>,
    /// Signatures already accepted inside the current anti-replay window.
    pub replay: ReplayGuard,
}

impl AppState {
    /// Builds state with the trusted-proxy list and cipher read from the environment.
    ///
    /// Returns an error if the configured encryption key is malformed — see
    /// [`SecretCipher::from_env`]. That failure is deliberately not recoverable here: falling back
    /// to plaintext would write signing secrets in the clear for an operator who believes they are
    /// encrypted.
    pub fn new(
        db: DatabaseConnection,
        webhook_tx: mpsc::Sender<WebhookEvent>,
    ) -> Result<Self, crate::crypto::CryptoError> {
        Ok(Self {
            db,
            webhook_tx,
            trusted_proxies: TrustedProxies::from_env(),
            cipher: Arc::new(SecretCipher::from_env()?),
            replay: ReplayGuard::new(),
        })
    }

    /// Builds state from explicit parts, bypassing the environment.
    ///
    /// Exists for tests, which need to exercise both the trusted and untrusted proxy paths — and
    /// both cipher modes — within one process, something process-wide environment variables cannot
    /// express.
    pub fn with_parts(
        db: DatabaseConnection,
        webhook_tx: mpsc::Sender<WebhookEvent>,
        trusted_proxies: Vec<crate::config::ProxyMatcher>,
        cipher: SecretCipher,
    ) -> Self {
        Self {
            db,
            webhook_tx,
            trusted_proxies: TrustedProxies::new(trusted_proxies),
            cipher: Arc::new(cipher),
            replay: ReplayGuard::new(),
        }
    }

    /// Builds state with an explicit trusted-proxy list and the zero-config plaintext cipher.
    ///
    /// The common test constructor; prefer [`AppState::with_parts`] when the cipher matters.
    pub fn with_trusted_proxies(
        db: DatabaseConnection,
        webhook_tx: mpsc::Sender<WebhookEvent>,
        trusted_proxies: Vec<crate::config::ProxyMatcher>,
    ) -> Self {
        Self::with_parts(db, webhook_tx, trusted_proxies, SecretCipher::Plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_is_accepted_once_and_refused_thereafter() {
        let guard = ReplayGuard::new();
        let key = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        assert!(guard.observe(key, "abc123", now), "the first use is fresh");
        assert!(!guard.observe(key, "abc123", now), "the same signature is a replay");
        assert!(!guard.observe(key, "abc123", now), "...and stays one");
    }

    #[test]
    fn distinct_signatures_and_distinct_keys_do_not_collide() {
        let guard = ReplayGuard::new();
        let now = chrono::Utc::now().timestamp();
        let (first, second) = (Uuid::new_v4(), Uuid::new_v4());

        assert!(guard.observe(first, "sig-a", now));
        assert!(guard.observe(first, "sig-b", now), "a different signature is independent");
        assert!(
            guard.observe(second, "sig-a", now),
            "the same signature under a different key is a different request"
        );
    }

    /// Entries leave the map once their timestamp is outside the window — at which point the
    /// freshness check rejects them anyway, so remembering them would be pure memory growth.
    #[test]
    fn entries_outside_the_window_are_forgotten() {
        let guard = ReplayGuard::new();
        let key = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        assert!(guard.observe(key, "old", now - MAX_TIMESTAMP_SKEW_SECS - 1));
        assert_eq!(guard.tracked(), 0, "an already-stale entry is pruned immediately");

        assert!(guard.observe(key, "fresh", now));
        assert_eq!(guard.tracked(), 1);
        // A stale entry recorded alongside a fresh one does not keep the fresh one from being
        // tracked, and does not itself survive.
        assert!(guard.observe(key, "old", now - MAX_TIMESTAMP_SKEW_SECS - 1));
        assert_eq!(guard.tracked(), 1);
    }
}
