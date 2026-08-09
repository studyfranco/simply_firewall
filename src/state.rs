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

/// A security-relevant environment variable was malformed, so the daemon must not start.
///
/// Both variants share one property that makes them fatal rather than recoverable: each configures a
/// *security boundary*, and for each the only alternative to aborting is to silently apply a
/// boundary different from the one the operator wrote. Everything else this service reads from the
/// environment — the bind address, the port — falls back to a documented default, because a default
/// listen port is unambiguous in a way that "some subset of your trusted proxies" is not.
#[derive(Debug, thiserror::Error)]
pub enum StartupConfigError {
    /// `VAULT_ENCRYPTION_KEY` (or its alias) is not a usable key.
    #[error(transparent)]
    EncryptionKey(#[from] crate::crypto::CryptoError),
    /// At least one `TRUSTED_PROXIES` entry is not a valid address, CIDR, or hostname.
    #[error(transparent)]
    TrustedProxies(#[from] crate::config::InvalidTrustedProxies),
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
    /// The id of the one key permitted to act as Master, resolved once and then immutable.
    ///
    /// # What this defends against
    ///
    /// `api_keys.is_master` is a column, and a column can be edited by anyone holding a database
    /// prompt, a restored backup, or a stray migration. Every guard in `src/api.rs` reads that flag,
    /// so before this existed, `UPDATE api_keys SET is_master = true WHERE id = <mine>` was a
    /// complete privilege escalation that no amount of HTTP-layer authorization could see.
    ///
    /// §5's uniqueness constraint does not close it. The derived `master_marker` guarantees *at most
    /// one* master row, which stops an attacker from **adding** a master — but it does not stop one
    /// from demoting the legitimate master and promoting itself, which keeps the count at one and
    /// satisfies the index perfectly. Uniqueness and identity are different properties.
    ///
    /// So the identity is fixed at boot, before the listener accepts anything, and the middleware
    /// treats `is_master` as authoritative only for this id. A row promoted afterwards is an
    /// ordinary key for the life of the process, no matter what its column says.
    ///
    /// # Why `OnceLock` rather than a plain `Uuid`
    ///
    /// Write-once is the property being bought, not laziness. A plain field would be assignable by
    /// any code holding `&mut AppState`, and "the master is whoever we last decided it was" is the
    /// mutable state this module's header rules out for exactly this class of value. `OnceLock`
    /// makes a second assignment impossible rather than merely discouraged, so the pin cannot drift
    /// under a running process even by accident.
    ///
    /// Shared behind an [`Arc`] so every clone of the state observes the same pin; a per-clone
    /// `OnceLock` would let each handler resolve its own, which is the bug this field exists to
    /// prevent, reintroduced one `#[derive(Clone)]` at a time.
    master_key_id: Arc<std::sync::OnceLock<Uuid>>,
}

/// Why [`AppState::pin_master_key`] refused to let the service start.
///
/// Every variant is a database state that makes "the Master key" ambiguous or absent. None is
/// recoverable by retrying, and none should be papered over at runtime: a service that starts
/// without knowing which key is Master is a service whose most powerful credential is decided by
/// whichever row a query happens to return first.
#[derive(Debug, thiserror::Error)]
pub enum MasterPinError {
    /// The `api_keys` table holds no row with `is_master = true`.
    #[error(
        "No master key exists. The service mints one at first boot; if this database was restored \
         or edited, delete nothing and investigate — starting without a master would leave every \
         master-only operation permanently unreachable."
    )]
    NoMaster,

    /// More than one row claims `is_master`, so there is no single answer to pin.
    #[error(
        "{} keys have is_master = true ({}), but RBAC_MODEL.md §5 requires exactly one. This is \
         only reachable if the uniqueness constraint was dropped or bypassed. Decide which key is \
         legitimate and demote the others, then restart. Refusing to start rather than guessing.",
        .0.len(),
        .0.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
    )]
    MultipleMasters(Vec<Uuid>),

    /// The unique index backing §5 is absent from the live schema.
    #[error(
        "The master-uniqueness index '{MASTER_MARKER_INDEX}' is missing from api_keys. RBAC_MODEL.md \
         §5 requires master uniqueness to be enforced by the database rather than by application \
         logic; without it a second master can be written at any time. Note that re-running \
         migrations will NOT restore it — m20260808_000009_derive_master_marker is already recorded \
         as applied and will be skipped. Recreate it directly:\n  \
         CREATE UNIQUE INDEX \"{MASTER_MARKER_INDEX}\" ON api_keys (master_marker);"
    )]
    MissingUniquenessIndex,

    /// The schema or key lookup itself failed.
    #[error("Could not read the database while pinning the master key: {0}")]
    Query(#[from] sea_orm::DbErr),
}

/// The unique index over the engine-derived `master_marker`, created by
/// `migration::m20260808_000009_derive_master_marker`.
///
/// Named here as well as there because this is the one place that checks it still exists at
/// *runtime*: a migration proves the index was created once, and this proves nobody has dropped it
/// since.
pub const MASTER_MARKER_INDEX: &str = "idx-api_keys-master_marker";

impl AppState {
    /// Builds state with the trusted-proxy list and cipher read from the environment.
    ///
    /// Returns an error if either security-relevant variable is malformed, and neither failure is
    /// recoverable here:
    ///
    /// - A bad `VAULT_ENCRYPTION_KEY` — see [`SecretCipher::from_env`] — because falling back to
    ///   plaintext would write signing secrets in the clear for an operator who believes they are
    ///   encrypted.
    /// - A bad `TRUSTED_PROXIES` entry — see [`crate::config::InvalidTrustedProxies`] — because
    ///   dropping it silently leaves the set of peers allowed to rewrite the client address
    ///   different from the set the operator wrote down.
    pub fn new(
        db: DatabaseConnection,
        webhook_tx: mpsc::Sender<WebhookEvent>,
    ) -> Result<Self, StartupConfigError> {
        Ok(Self {
            db,
            webhook_tx,
            trusted_proxies: TrustedProxies::from_env()?,
            cipher: Arc::new(SecretCipher::from_env()?),
            replay: Arc::new(ReplayGuard::default()),
            master_key_id: Arc::new(std::sync::OnceLock::new()),
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
            master_key_id: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Establishes which key is Master, once, and refuses to return anything else afterwards.
    ///
    /// Called by `main.rs` **before the listener is bound**, so the pin is in place before a single
    /// request can be served. Three checks, in the order that gives the most useful error:
    ///
    /// 1. Exactly one row has `is_master = true`. Zero and many are both fatal and are reported
    ///    differently, because the remedies have nothing in common — one means the bootstrap never
    ///    ran, the other means someone must decide which key is legitimate.
    /// 2. The §5 uniqueness index still exists. A migration proves it was created once; this proves
    ///    nobody has dropped it since.
    /// 3. That row's id becomes the pin.
    ///
    /// # Why this is not redundant with the uniqueness constraint
    ///
    /// The constraint guarantees *at most one* master row. It says nothing about **which** row, and
    /// an attacker with database access does not need two masters — demoting the real one and
    /// promoting itself keeps the count at exactly one and leaves every constraint satisfied. The
    /// index defends the cardinality; this defends the identity. Both are needed, and neither
    /// substitutes for the other.
    ///
    /// # Idempotent by construction
    ///
    /// Calling it twice returns the already-pinned id and does not re-query. That is not a
    /// convenience: it is what makes the guarantee hold. If a second call could re-resolve, then
    /// anything able to trigger one — a reconnect, a reload, a future admin endpoint — would be able
    /// to move the pin, and "fixed at boot" would be true only until the first such event.
    pub async fn pin_master_key(&self) -> Result<Uuid, MasterPinError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};
        use sea_orm_migration::SchemaManager;

        if let Some(pinned) = self.master_key_id.get() {
            return Ok(*pinned);
        }

        // `select_only` + one column: the master row carries a signing secret, and there is no
        // reason for a startup check to pull a credential into memory to count to one.
        let masters: Vec<Uuid> = crate::entities::prelude::ApiKey::find()
            .select_only()
            .column(crate::entities::api_key::Column::Id)
            .filter(crate::entities::api_key::Column::IsMaster.eq(true))
            .into_tuple()
            .all(&self.db)
            .await?;

        let pinned = match masters.as_slice() {
            [only] => *only,
            [] => return Err(MasterPinError::NoMaster),
            many => return Err(MasterPinError::MultipleMasters(many.to_vec())),
        };

        // The index check comes *after* the count, and the ordering was the other way round until a
        // test showed why it should not be. Two masters is only reachable once the index is gone, so
        // checking the index first meant `MultipleMasters` could never be reported — the operator was
        // told to recreate an index while two masters sat in the table unmentioned. Counting first
        // surfaces the more urgent fact; the index error is then reported on the next start, once the
        // ambiguity the service cannot resolve for itself has been resolved.
        let manager = SchemaManager::new(&self.db);
        if !manager.has_index("api_keys", MASTER_MARKER_INDEX).await? {
            return Err(MasterPinError::MissingUniquenessIndex);
        }

        // `set` losing a race is not an error: two callers resolving concurrently necessarily read
        // the same single row, so the winner's value is the loser's value. `get_or_init` would be
        // equivalent; this spelling keeps the fallible query outside the closure.
        let _ = self.master_key_id.set(pinned);
        Ok(pinned)
    }

    /// The pinned Master id, resolving it on first use if `pin_master_key` has not already run.
    ///
    /// **Fail-closed.** Returns `None` — meaning *no key is Master* — whenever the identity cannot be
    /// established: no master row, several, a missing index, or an unreadable database. `None` is
    /// strictly more restrictive than any answer it replaces, so a failure here removes authority
    /// rather than granting it.
    ///
    /// The lazy path exists for tests, which build their state before seeding any key and would
    /// otherwise have to be rewritten around a startup sequence they are not testing. It is
    /// unreachable in production: `main.rs` pins before binding the listener, so by the time any
    /// request arrives the `OnceLock` is set and this is a load with no query behind it.
    ///
    /// That ordering is the whole defence, and it is worth being exact about what it buys. Tampering
    /// *after* boot has zero effect, because the pin is already fixed. Tampering *before* boot is
    /// caught by [`pin_master_key`](Self::pin_master_key), which aborts startup rather than pinning
    /// a key the operator did not intend.
    pub async fn resolve_master_key_id(&self) -> Option<Uuid> {
        match self.pin_master_key().await {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::error!(
                    "Master identity is unresolvable, so no caller will be treated as Master: {e}"
                );
                None
            }
        }
    }

    /// Whether this key may act as Master: it must claim the flag **and** be the pinned key.
    ///
    /// The conjunction is the point. `key.is_master` alone is a column an attacker with database
    /// access can set on any row; `id == pinned` alone would promote whichever key was pinned even
    /// if its flag were later cleared. Requiring both means a promoted impostor is an ordinary key
    /// and a demoted master stops being one, which are the two directions tampering can go.
    pub async fn is_effective_master(&self, key: &crate::entities::api_key::Model) -> bool {
        key.is_master && self.resolve_master_key_id().await == Some(key.id)
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
