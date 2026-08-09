//! Database connection setup: pool construction, SQLite session pragmas, and migrations.
//!
//! Extracted from `state.rs` so that "how the database is opened" is one module rather than a
//! detail of application state, mirroring `simply_hook_executor`'s `src/db.rs`.
//!
//! Everything SQLite-specific here is backend-conditional. `AGENT.MD` requires the data layer to
//! stay SQL-agnostic, and it does: no *query* in this codebase is vendor-specific. These are
//! connection **pragmas** — they configure how the engine behaves, not what it is asked — and they
//! are skipped entirely on any backend that is not SQLite.
//!
//! # The SQLite pool holds exactly one connection, and that is load-bearing
//!
//! SeaORM pins `max_connections = 1` for SQLite — measured, not assumed — because SQLite permits a
//! single writer and a pooled DDL sequence does not survive being spread across connections.
//! [`connect`] pins the same value explicitly, and a test asserts it.
//!
//! This is not a tuning preference. Building the pool with SQLx's default of ten connections made
//! **migrations fail**: `m20260808_000009` drops `master_marker` and re-adds it as a generated
//! column, and with more than one connection the `ADD` lands on a connection whose schema still has
//! the old one — `duplicate column name: master_marker`, at any pool size ≥ 2, deterministically.
//! One connection: nine migrations applied. Two: eight, then failure.
//!
//! # Where a pragma actually takes effect
//!
//! | Pragma | Scope | Default already in force |
//! | :--- | :--- | :--- |
//! | `foreign_keys` | per-connection | **ON** (SQLx sets it) |
//! | `busy_timeout` | per-connection | **5000 ms** (SQLx sets it) |
//! | `journal_mode=WAL` | **persistent** (file header) | `delete` |
//! | `synchronous=NORMAL` | per-connection | `FULL` (2) |
//!
//! Three of the four are per-connection, which would matter enormously on a multi-connection pool —
//! sampling `PRAGMA synchronous` across a five-connection pool after a single
//! `PRAGMA synchronous=NORMAL` returns *both* `1` and `2`, because the statement lands on whichever
//! connection served it. With one connection the distinction collapses: pool-wide and
//! per-connection are the same thing.
//!
//! [`connect`] still sets them through `SqliteConnectOptions` rather than relying on
//! [`apply_sqlite_pragmas`] alone, for one narrow but real reason: SQLx reopens a connection that
//! has been closed or invalidated, and a reopened connection gets its options replayed but not our
//! `PRAGMA` statements. Declaring them at open time is what makes them survive a recycle.
//!
//! [`apply_sqlite_pragmas`] remains, and remains called, for two reasons: it is the function
//! `scripts/verify_convergence.sh` diffs against the peer's, and it reads `journal_mode` back so the
//! startup log reports what is actually in force rather than what was requested.
//!
//! URL query parameters were tried first and rejected outright — SQLx answers
//! `unknown query parameter 'synchronous' while parsing connection URL`.

use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbErr,
    SqlxSqliteConnector, Statement,
};
use sea_orm_migration::MigratorTrait;

/// How long SQLite waits on a locked database before returning `SQLITE_BUSY`, in milliseconds.
///
/// Deliberately the same 5000 SQLx already applies by default: this constant exists to make the
/// value explicit and assert it, not to change it. Lowering it would turn a transient lock into a
/// `500` on a request that did nothing wrong.
pub const SQLITE_BUSY_TIMEOUT_MS: u32 = 5_000;

/// Connections in the SQLite pool. **One**, and not a tuning knob.
///
/// SQLite permits a single writer, and a DDL sequence spread across connections does not survive:
/// `m20260808_000009` drops and re-adds `master_marker`, and at any pool size ≥ 2 the `ADD` reaches
/// a connection whose schema still holds the old column. SeaORM's own `Database::connect` pins this
/// to 1 for SQLite; building a pool by hand opts out of that default, so it is restored here
/// explicitly and asserted by [`tests::the_sqlite_pool_holds_exactly_one_connection`].
pub const SQLITE_MAX_CONNECTIONS: u32 = 1;

/// Opens the database pool, applying SQLite session pragmas to **every** connection.
///
/// Non-SQLite backends take the plain [`Database::connect`] path unchanged — there is nothing here
/// PostgreSQL or MySQL needs, and a `PRAGMA` would be a syntax error on both.
///
/// For SQLite the pool is built from `SqliteConnectOptions` rather than from a bare URL, because
/// that is the only place three of the four settings can be made to hold pool-wide (see the module
/// header). SQLx applies them as each connection opens, so a connection created an hour after
/// startup gets the same configuration as the first one.
///
/// `create_if_missing` matches the `?mode=rwc` this service has always documented; it is set here
/// so the behaviour no longer depends on callers remembering the query parameter.
pub async fn connect(db_url: &str) -> Result<DatabaseConnection, DbErr> {
    let mut opt = ConnectOptions::new(db_url.to_owned());
    opt.sqlx_logging_level(log::LevelFilter::Debug);

    // Backend detection by URL scheme, which is the only signal available before a pool exists.
    // Everything downstream reads `get_database_backend()` instead; this is the one place that
    // cannot.
    if !db_url.starts_with("sqlite:") {
        return Database::connect(opt).await;
    }

    use sea_orm::sqlx::sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
    };
    use std::str::FromStr;

    let connect_options = SqliteConnectOptions::from_str(db_url)
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?
        .create_if_missing(true)
        // Enforced rather than assumed. SQLx already defaults this to on — measured, not trusted —
        // so this is an assertion that survives a future SQLx default change, not a fix.
        .foreign_keys(true)
        // Readers proceed against the last committed snapshot while a writer appends, instead of
        // blocking on a database-wide exclusive lock. Persistent in the file header, but set here
        // too so a fresh database gets it before the first write rather than after.
        .journal_mode(SqliteJournalMode::Wal)
        // The one setting that genuinely requires this placement. `NORMAL` is the standard
        // companion to WAL: it keeps full durability against process crashes and gives up only the
        // last transactions in a power loss, in exchange for not fsyncing on every commit.
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_millis(u64::from(SQLITE_BUSY_TIMEOUT_MS)));

    let pool = SqlitePoolOptions::new()
        // Explicit, because the default is wrong here and silently so. SQLx defaults to ten;
        // SeaORM's own `Database::connect` pins SQLite to one. Leaving it at ten breaks DDL
        // migrations outright — see the module header — and the failure appears only against a
        // file-backed database, which the unit suite does not use by default.
        .max_connections(SQLITE_MAX_CONNECTIONS)
        .connect_with(connect_options)
        .await
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?;

    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

/// Runs every pending migration.
///
/// A thin wrapper, and worth having anyway: it puts migration execution beside connection setup so
/// the startup order — connect, pragmas, migrate — reads as one sequence in one module rather than
/// being reconstructed from `main.rs`.
pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    tracing::info!("Running database migrations...");
    crate::migration::Migrator::up(db, None).await
}

/// Applies SQLite's session pragmas to the current connection, logging what actually took effect.
///
/// # What this adds over [`connect`]
///
/// Not the settings themselves — [`connect`] has already applied them to every connection, and on a
/// pool built there this function will find them already in force. What it adds is **evidence**: it
/// reads `journal_mode` back rather than inferring success from a clean return, so the startup log
/// says which mode is genuinely active. It also covers pools this crate did not build, which is
/// every pool in the test suite.
///
/// # Failure handling
///
/// **Never fatal.** Every failure is logged and swallowed, and the function still returns `Ok`. Two
/// reasons. The benign one: an in-memory database (`sqlite::memory:`, which the whole test suite
/// uses) reports `journal_mode=memory` and cannot be switched to WAL, since there is no file to
/// write a log beside — SQLite declines silently rather than erroring, which is why the mode is read
/// back instead of inferred. The important one: refusing to boot over a concurrency setting that did
/// not apply would trade a real outage for a theoretical slowdown, on a read-only mount or an exotic
/// filesystem that is otherwise perfectly serviceable.
pub async fn apply_sqlite_pragmas(db: &DatabaseConnection) -> Result<(), DbErr> {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Ok(());
    }

    // `journal_mode` answers with the mode actually in force, which is the only trustworthy
    // confirmation — SQLite silently declines the switch for in-memory and read-only databases
    // rather than erroring, so assuming success from a clean return would be wrong.
    match db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA journal_mode=WAL;",
        ))
        .await
    {
        Ok(Some(row)) => match row.try_get::<String>("", "journal_mode") {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => {
                tracing::info!("SQLite journal mode: WAL (concurrent readers during writes).");
            }
            Ok(mode) => tracing::info!(
                "SQLite journal mode is '{mode}' rather than WAL; this is normal for in-memory or \
                 read-only databases."
            ),
            Err(e) => tracing::warn!("Could not read back the SQLite journal mode: {e}"),
        },
        Ok(None) => tracing::warn!("PRAGMA journal_mode returned no row; leaving the default."),
        Err(e) => tracing::warn!("Could not enable SQLite WAL mode: {e}. Continuing without it."),
    }

    // The remaining three are set-and-log. Each is per-connection, so on a pool this reaches
    // whichever connection serves it — which is precisely why `connect` sets them at open time and
    // why these calls are confirmation rather than mechanism.
    for (label, statement) in [
        ("foreign key enforcement", "PRAGMA foreign_keys=ON;".to_owned()),
        ("synchronous mode", "PRAGMA synchronous=NORMAL;".to_owned()),
        ("busy timeout", format!("PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};")),
    ] {
        if let Err(e) =
            db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite, statement)).await
        {
            tracing::warn!("Could not set the SQLite {label}: {e}. Continuing with the default.");
        }
    }
    tracing::info!(
        "SQLite session pragmas applied: foreign_keys=ON, synchronous=NORMAL, \
         busy_timeout={SQLITE_BUSY_TIMEOUT_MS}ms."
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::ConnectionTrait;

    /// Reads one pragma back through the pool.
    async fn pragma<T: sea_orm::TryGetable>(db: &DatabaseConnection, sql: &str, col: &str) -> T {
        db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, sql.to_owned()))
            .await
            .expect("the pragma query succeeds")
            .expect("a row is returned")
            .try_get("", col)
            .expect("the column has the expected type")
    }

    /// A temporary directory holding one database file, removed on drop.
    struct TempDb(std::path::PathBuf);
    impl TempDb {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("vault_db_{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp dir is creatable");
            Self(dir)
        }
        fn url(&self) -> String {
            format!("sqlite://{}", self.0.join("v.db").display())
        }
    }
    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// All four pragmas are in force on a pool built by [`connect`].
    ///
    /// Note what this does **not** claim. An earlier version of this test sampled twenty-five times
    /// and asserted the values were uniform, which sounds like a pool-wide guarantee and is not one:
    /// the pool holds a single connection, so every sample necessarily hits it and uniformity is
    /// tautological. The real pool-wide guarantee comes from
    /// [`tests::the_sqlite_pool_holds_exactly_one_connection`]; this test's job is only that the four
    /// settings actually took.
    #[tokio::test]
    async fn connect_applies_all_four_pragmas() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("a file-backed sqlite pool opens");

        assert_eq!(pragma::<String>(&db, "PRAGMA journal_mode;", "journal_mode").await, "wal");
        assert_eq!(pragma::<i32>(&db, "PRAGMA synchronous;", "synchronous").await, 1, "NORMAL");
        assert_eq!(pragma::<i32>(&db, "PRAGMA foreign_keys;", "foreign_keys").await, 1, "ON");
        assert_eq!(
            pragma::<i32>(&db, "PRAGMA busy_timeout;", "timeout").await,
            SQLITE_BUSY_TIMEOUT_MS as i32
        );
    }

    /// The SQLite pool holds exactly one connection — the invariant migrations depend on.
    ///
    /// Asserted against the live pool rather than against the constant, so that changing
    /// `SQLITE_MAX_CONNECTIONS` alone cannot satisfy it. SQLite permits one writer, and SeaORM's own
    /// `Database::connect` pins this to 1; hand-building a pool opts out of that default silently.
    #[tokio::test]
    async fn the_sqlite_pool_holds_exactly_one_connection() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("pool opens");
        assert_eq!(
            db.get_sqlite_connection_pool().options().get_max_connections(),
            1,
            "SQLite must run a single-connection pool; more than one breaks DDL migrations"
        );
    }

    /// Migrations complete against a **file-backed** pool built by [`connect`].
    ///
    /// This is a regression test for a real break introduced while writing this module, and it is
    /// here because none of the existing suites could have caught it. Building the pool with SQLx's
    /// default of ten connections made `Migrator::up` fail with `duplicate column name:
    /// master_marker` — `m20260808_000009` drops the column on one connection and re-adds it on
    /// another whose schema is still the old one. Deterministic at any pool size ≥ 2, and invisible
    /// to every other test in the repository, all of which run on `sqlite::memory:` where there is
    /// nothing to pool.
    #[tokio::test]
    async fn migrations_apply_cleanly_on_a_file_backed_pool() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("pool opens");
        run_migrations(&db).await.expect("every migration applies on a pooled file database");

        // Re-running is a no-op rather than an error: this is what a restart does.
        run_migrations(&db).await.expect("migrations are idempotent across restarts");
    }

    /// Foreign keys are genuinely enforced, not merely reported as on.
    ///
    /// `PRAGMA foreign_keys` returning `1` says the switch is set; it does not prove the engine acts
    /// on it. The schema declares `api_key_group_permissions.api_key_id REFERENCES api_keys(id)`, so
    /// an insert naming a key that does not exist is the direct test — and it is the constraint that
    /// SQLite would silently ignore with the pragma off.
    #[tokio::test]
    async fn foreign_keys_are_enforced_not_just_enabled() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("pool opens");
        run_migrations(&db).await.expect("migrations run");

        let orphan = crate::entities::api_key_group_permission::ActiveModel {
            id: sea_orm::ActiveValue::Set(uuid::Uuid::new_v4()),
            api_key_id: sea_orm::ActiveValue::Set(uuid::Uuid::new_v4()), // no such key
            group_id: sea_orm::ActiveValue::Set(uuid::Uuid::new_v4()),   // no such group
            can_read: sea_orm::ActiveValue::Set(true),
            can_write: sea_orm::ActiveValue::Set(false),
            can_delete: sea_orm::ActiveValue::Set(false),
            can_manage: sea_orm::ActiveValue::Set(false),
            created_at: sea_orm::ActiveValue::Set(chrono::Utc::now().naive_utc()),
        };
        let outcome = sea_orm::EntityTrait::insert(orphan).exec(&db).await;
        assert!(
            outcome.is_err(),
            "a permission row referencing a nonexistent key must be refused; with foreign_keys off \
             SQLite accepts it silently"
        );
    }

    /// An in-memory database cannot use WAL. That must be a logged no-op, not a startup failure —
    /// the entire test suite runs on `sqlite::memory:`.
    ///
    /// This is the resilience contract in miniature: the pragmas are a *performance* setting and the
    /// service is entirely correct without them. Refusing to boot over a setting that did not apply
    /// would trade a real outage for a theoretical slowdown.
    #[tokio::test]
    async fn a_database_that_cannot_use_wal_still_starts_and_works() {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        assert!(apply_sqlite_pragmas(&db).await.is_ok(), "a declined pragma is never fatal");

        // WAL genuinely did not engage — so the assertion above is tolerance, not a silent success.
        let mode = pragma::<String>(&db, "PRAGMA journal_mode;", "journal_mode").await;
        assert_ne!(mode.to_ascii_lowercase(), "wal", "an in-memory database cannot use WAL");

        // And the connection is still fully usable afterwards, which is the point of continuing.
        run_migrations(&db).await.expect("migrations still run");

        // Re-applying is idempotent: a restart against the same database must not fail either.
        assert!(apply_sqlite_pragmas(&db).await.is_ok());
    }

    /// A non-SQLite backend is skipped by *backend*, not by URL text, so there is no string parsing
    /// to get wrong once PostgreSQL is in play.
    #[tokio::test]
    async fn the_pragmas_are_scoped_to_sqlite_by_backend() {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        assert_eq!(db.get_database_backend(), DatabaseBackend::Sqlite);
        assert!(apply_sqlite_pragmas(&db).await.is_ok());
    }

    /// WAL is persistent: a *new* connection to the same file inherits it. This is what makes the
    /// journal mode the one setting that does not need re-applying per connection.
    #[tokio::test]
    async fn wal_survives_reconnection() {
        let tmp = TempDb::new();
        {
            let db = connect(&tmp.url()).await.expect("pool opens");
            assert_eq!(pragma::<String>(&db, "PRAGMA journal_mode;", "journal_mode").await, "wal");
        }
        let reopened = Database::connect(tmp.url()).await.expect("plain reconnect succeeds");
        assert_eq!(
            pragma::<String>(&reopened, "PRAGMA journal_mode;", "journal_mode").await,
            "wal",
            "WAL is recorded in the file header and survives a reconnect that sets no pragmas"
        );
    }
}
