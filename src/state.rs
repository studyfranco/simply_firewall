//! Application state: the database handle, the background webhook channel, and the three security
//! primitives every request consults — the trusted-proxy set, the at-rest cipher, and the
//! anti-replay guard.
//!
//! All three are built **once at startup** and carried here rather than re-derived per request.
//! That is deliberate: each is an input to an authorization decision, and a value that can change
//! under a running process (an environment variable re-read mid-flight, a cipher rebuilt from a key
//! that may since have been edited) is one that cannot be reasoned about.

use std::sync::Arc;

use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::TrustedProxies;
use crate::crypto::SecretCipher;
use crate::replay::ReplayGuard;

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
    ///
    /// Shared behind an [`Arc`] rather than cloned per handler: a per-clone guard would accept a
    /// replay on any request served through a different clone, which is to say most of them. See
    /// [`crate::replay`].
    pub replay: Arc<ReplayGuard>,
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
            replay: Arc::new(ReplayGuard::default()),
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
            replay: Arc::new(ReplayGuard::default()),
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
