//! Application State

use sea_orm::DatabaseConnection;

use crate::config::TrustedProxies;
use tokio::sync::mpsc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

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
/// Guarded on the backend rather than on the URL string: `PRAGMA` is SQLite-specific and would be a
/// syntax error on PostgreSQL or MySQL. This is the one deliberate exception to the SQL-agnostic
/// rule in `AGENT.MD` — it configures the *engine*, not a query, and every other backend simply
/// skips it.
///
/// `journal_mode` is a no-op for `sqlite::memory:` (an in-memory database has no WAL file and stays
/// in `memory` mode), which is exactly what the test suite uses; the call is harmless there and the
/// result is logged rather than treated as a failure.
pub async fn apply_sqlite_pragmas(db: &DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Ok(());
    }

    // `journal_mode` returns the mode actually in force, which is worth logging: it can legitimately
    // come back as something other than `wal` (in-memory databases, or a filesystem that cannot
    // support shared memory), and an operator debugging lock contention needs to know which.
    let applied = db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA journal_mode=WAL;",
        ))
        .await?
        .and_then(|row| row.try_get::<String>("", "journal_mode").ok());

    match applied.as_deref() {
        Some("wal") => tracing::info!("SQLite journal_mode=WAL enabled."),
        Some(other) => tracing::info!(
            "SQLite journal_mode is '{other}' (WAL unavailable for this database — normal for \
             in-memory databases)."
        ),
        None => tracing::debug!("SQLite journal_mode pragma returned no row."),
    }

    db.execute_unprepared(&format!("PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};")).await?;
    tracing::info!("SQLite busy_timeout set to {SQLITE_BUSY_TIMEOUT_MS}ms.");

    Ok(())
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
    /// Parsed once at startup and carried in state rather than re-read from the environment per
    /// request: this is an authorization input, and a value that can change under a running process
    /// is one that cannot be reasoned about. (Hostname *resolution* is deliberately dynamic — see
    /// [`TrustedProxies`] — because a container's address changes while its name does not.)
    ///
    /// **Empty means no proxy is trusted**, so forwarding headers are ignored entirely. See
    /// [`crate::config::resolve_client_ip`].
    pub trusted_proxies: TrustedProxies,
}

impl AppState {
    /// Builds state with the trusted-proxy list read from the environment. The normal constructor.
    pub fn new(db: DatabaseConnection, webhook_tx: mpsc::Sender<WebhookEvent>) -> Self {
        Self { db, webhook_tx, trusted_proxies: TrustedProxies::from_env() }
    }

    /// Builds state with an explicit trusted-proxy list, bypassing the environment.
    ///
    /// Exists for tests, which need to exercise both the trusted and untrusted paths within one
    /// process — something a process-wide environment variable cannot express.
    pub fn with_trusted_proxies(
        db: DatabaseConnection,
        webhook_tx: mpsc::Sender<WebhookEvent>,
        trusted_proxies: Vec<crate::config::ProxyMatcher>,
    ) -> Self {
        Self { db, webhook_tx, trusted_proxies: TrustedProxies::new(trusted_proxies) }
    }
}
