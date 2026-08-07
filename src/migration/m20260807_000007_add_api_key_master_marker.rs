//! Adds `api_keys.master_marker` — the database-level guarantee that exactly one Master key exists.
//!
//! `RBAC_MODEL.md` §5 requires Master uniqueness to be "enforced by a database constraint rather than
//! by application logic alone". Until now it was convention: `bootstrap_master_key` skips minting
//! when a master already exists, and `guard_scope_elevation` refuses a non-master handing out
//! `is_master` — but a master could mint a second master through `POST /api/keys`, and a direct
//! `UPDATE` could mint any number. Neither the application nor the schema said "one".
//!
//! # Why a marker column and not a partial unique index
//!
//! The obvious spelling is `CREATE UNIQUE INDEX ... ON api_keys (is_master) WHERE is_master = true`.
//! PostgreSQL and SQLite both support that; **MySQL does not**, and `AGENT.MD` requires the data
//! layer to stay SQL-agnostic across all three drivers this crate enables. `RBAC_MODEL.md` §5
//! anticipates exactly this and names the portable substitute: a nullable column carrying a single
//! non-null value under a plain unique index. Null values do not collide in a unique index on any of
//! the three engines, so every non-master row is free to leave it `NULL` while at most one row may
//! ever hold `'master'`.
//!
//! The column is *derived* from `is_master`, not a replacement for it: `is_master` remains the flag
//! every guard reads, and `master_marker` exists solely so the database can refuse a second one.
//! [`crate::api::MASTER_MARKER`] is the single non-null value, and `bootstrap_master_key` is now the
//! only writer of either column — `is_master` is no longer reachable through any API payload.
//!
//! # A pre-existing second master stops the migration
//!
//! If the database already contains more than one master, this migration fails with an error naming
//! the offending ids rather than picking a winner. Demoting a key silently would strip an operator's
//! authority without asking; failing loudly is recoverable in one `UPDATE`, and the message says
//! which one to run. A single master (the overwhelmingly common case) backfills silently.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{ConnectionTrait, Statement};

/// The one non-null value `master_marker` ever carries. Duplicated from [`crate::api::MASTER_MARKER`]
/// rather than imported so this migration stays a self-contained description of the schema at this
/// point in history — a later refactor of the API constant must not silently rewrite what an already
/// applied migration did. A unit test in `src/api.rs` asserts the two agree.
const MASTER_MARKER: &str = "master";

/// Identifiers this migration touches. `Table` is re-declared locally rather than imported from the
/// initial-schema migration so that module can stay private; `DeriveIden` maps the variants to the
/// same snake_case names, so they address the same table.
#[derive(DeriveIden)]
enum ApiKeys {
    /// The `api_keys` table.
    Table,
    /// The uniqueness marker: `'master'` on the Master key, `NULL` on every other key.
    MasterMarker,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        // Checked *before* the column is added, so a database with two masters is left exactly as it
        // was found rather than half-migrated. `is_master` is a boolean on every backend, and
        // comparing against `true` rather than `1` keeps PostgreSQL happy without a cast.
        let duplicates = db
            .query_all_raw(Statement::from_string(
                backend,
                "SELECT id FROM api_keys WHERE is_master = true".to_owned(),
            ))
            .await?;
        if duplicates.len() > 1 {
            let ids: Vec<String> = duplicates
                .iter()
                .map(|row| {
                    row.try_get::<uuid::Uuid>("", "id")
                        .map(|id| id.to_string())
                        .unwrap_or_else(|_| "<unreadable id>".to_owned())
                })
                .collect();
            return Err(DbErr::Custom(format!(
                "Refusing to migrate: {} keys have is_master = true ({}), but RBAC_MODEL.md §5 \
                 requires exactly one. Decide which key is the Master and demote the others with \
                 `UPDATE api_keys SET is_master = false WHERE id IN (...);`, then restart. This \
                 migration will not choose for you.",
                duplicates.len(),
                ids.join(", ")
            )));
        }

        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    // `string_len(16)` rather than a bare `string()`: MySQL cannot index a `TEXT`
                    // column without a prefix length, and a short `VARCHAR` sidesteps the InnoDB key
                    // length ceiling entirely. The value is a fixed 6-character literal.
                    .add_column(ColumnDef::new(ApiKeys::MasterMarker).string_len(16).null())
                    .to_owned(),
            )
            .await?;

        // Backfill before the index exists. Guaranteed to touch at most one row by the check above.
        db.execute_raw(Statement::from_string(
            backend,
            format!("UPDATE api_keys SET master_marker = '{MASTER_MARKER}' WHERE is_master = true"),
        ))
        .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-api_keys-master_marker")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::MasterMarker)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx-api_keys-master_marker")
                    .table(ApiKeys::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::MasterMarker)
                    .to_owned(),
            )
            .await
    }
}
