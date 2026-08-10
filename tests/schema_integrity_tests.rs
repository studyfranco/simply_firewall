//! Referential-integrity tests: what the **engine** does when a row goes away.
//!
//! # Why these are integration tests and not unit tests
//!
//! Every one of them depends on `PRAGMA foreign_keys=ON`, and in SQLite that pragma is
//! **per-connection and off by default**. A cascade is therefore not a property of the schema alone;
//! it is a property of the schema *plus the connection that was opened*. So each test here builds its
//! database through [`simply_ip_vault::db::connect`] — the real production path, the one that sets the
//! pragma — rather than through `Database::connect`, which would leave foreign keys disabled and make
//! every assertion below pass or fail for reasons unrelated to the schema.
//!
//! That is also why they are **file-backed**. `sqlite::memory:` is what the rest of the suite uses,
//! and it is fine for behaviour, but it cannot exercise the pool that `connect` actually builds.
//!
//! # What a cascade test is worth
//!
//! `PRAGMA foreign_keys` returning `1` says the switch is set. It does not say the engine acted on it,
//! and it says nothing at all about *which* action each constraint declares. `ON DELETE CASCADE` and
//! `ON DELETE SET NULL` are one word apart in a migration and produce opposite outcomes — one erases
//! an audit trail, the other preserves it — and no type in Rust distinguishes them. The only way to
//! know which is deployed is to delete a row and look.
//!
//! # Deletes here are direct, and that is deliberate
//!
//! Nothing below goes through an API handler. `RBAC_MODEL.md` §6 forbids the service from destroying
//! data implicitly, and `delete_api_key` enforces that with a pre-flight inventory and a refusal —
//! so the *application* never reaches these constraints in the first place. These tests are about the
//! layer underneath: what the database would do if a row were removed by a restore, an operator, a
//! future migration, or a handler written by someone who had not read §6. Testing that through the
//! handler would prove only that the handler refuses, which is a different fact and is already
//! covered in `tests/security_tests.rs`.

use chrono::Utc;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    EntityTrait, PaginatorTrait, QueryFilter, Statement,
};
use uuid::Uuid;

use simply_ip_vault::entities::{
    api_key, api_key_group_permission, audit_log, ip_group, ip_record,
    ip_record_group_membership, webhook_config,
};

/// A temporary directory holding one database file, removed on drop.
///
/// Every test gets its own. That is what makes "orphaned rows from a prior test run" structurally
/// impossible here rather than something to clean up: there is no shared database to inherit state
/// from, and a panicking test leaves nothing behind for the next one to trip over.
struct TempDb(std::path::PathBuf);

impl TempDb {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("vault_fk_{}", Uuid::new_v4()));
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

/// A migrated, file-backed database opened the way production opens it.
async fn fresh_db(tmp: &TempDb) -> DatabaseConnection {
    let db = simply_ip_vault::db::connect(&tmp.url())
        .await
        .expect("a file-backed sqlite pool opens");
    simply_ip_vault::db::run_migrations(&db).await.expect("every migration applies");
    db
}

/// Seeds a non-master key. `parent` threads the `parent_key_id` chain when a test needs one.
async fn seed_key(db: &DatabaseConnection, name: &str, parent: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    api_key::Entity::insert(api_key::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(Some("secret".to_owned())),
        prefix: Set(plaintext[..8].to_owned()),
        bound_ips: Set(None),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        parent_key_id: Set(parent),
        created_at: Set(Utc::now().naive_utc()),
        updated_at: Set(Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the key inserts");
    id
}

/// Seeds a group owned by `owner`.
async fn seed_group(db: &DatabaseConnection, name: &str, owner: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    ip_group::Entity::insert(ip_group::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        group_type: Set("blacklist".to_owned()),
        description: Set(None),
        owner_key_id: Set(owner),
        created_at: Set(Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the group inserts");
    id
}

/// Seeds an IP record and places it in `group`.
async fn seed_record_in_group(db: &DatabaseConnection, address: &str, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let now = Utc::now().naive_utc();
    ip_record::Entity::insert(ip_record::ActiveModel {
        id: Set(id),
        target_address: Set(address.to_owned()),
        cause: Set(None),
        is_locked: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    })
    .exec(db)
    .await
    .expect("the record inserts");

    ip_record_group_membership::Entity::insert(ip_record_group_membership::ActiveModel {
        ip_record_id: Set(id),
        group_id: Set(group),
    })
    .exec(db)
    .await
    .expect("the membership inserts");
    id
}

/// Grants `key` a permission row on `group`.
async fn seed_permission(db: &DatabaseConnection, key: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    api_key_group_permission::Entity::insert(api_key_group_permission::ActiveModel {
        id: Set(id),
        api_key_id: Set(key),
        group_id: Set(group),
        can_read: Set(true),
        can_write: Set(true),
        can_delete: Set(false),
        can_manage: Set(false),
        created_at: Set(Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the permission inserts");
    id
}

/// Seeds a webhook config bound to `group`.
async fn seed_webhook(db: &DatabaseConnection, name: &str, group: Uuid, owner: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    webhook_config::Entity::insert(webhook_config::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        target_url: Set("https://example.invalid/hook".to_owned()),
        secret_token: Set("token".to_owned()),
        auth_mode: Set("none".to_owned()),
        api_key: Set(None),
        hmac_template: Set(None),
        headers_json: Set(None),
        payload_template: Set("{}".to_owned()),
        group_id: Set(group),
        is_active: Set(true),
        events: Set(None),
        owner_key_id: Set(owner),
        created_at: Set(Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the webhook inserts");
    id
}

/// Writes an audit row attributed to `key`, denormalizing its name and prefix as the service does.
async fn seed_audit_log(db: &DatabaseConnection, key: Uuid, name: &str, action: &str) -> Uuid {
    let id = Uuid::new_v4();
    audit_log::Entity::insert(audit_log::ActiveModel {
        id: Set(id),
        api_key_id: Set(Some(key)),
        api_key_name: Set(Some(name.to_owned())),
        api_key_prefix: Set(Some("abcd1234".to_owned())),
        client_ip: Set(Some("203.0.113.7".to_owned())),
        action: Set(action.to_owned()),
        target_address: Set(Some("198.51.100.4".to_owned())),
        group_names: Set(None),
        details: Set(None),
        timestamp: Set(Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the audit row inserts");
    id
}

// ─────────────────────────────────────────────────────────────
// Deleting an API key
// ─────────────────────────────────────────────────────────────

/// Deleting a key removes its group grants — `fk-akgp-api_key_id`, `ON DELETE CASCADE`.
///
/// A grant is a statement about a key that no longer exists. Leaving it behind would be worse than
/// untidy: `api_key_group_permissions` is what every §2 authorization check reads, and a stale row
/// becomes live authority again the moment a new key is minted with the recycled id.
///
/// The unrelated key's grant is asserted to survive in the same test, because "cascade deleted
/// everything" and "cascade deleted the right thing" are different outcomes and only one is correct.
#[tokio::test]
async fn deleting_an_api_key_cascades_to_its_group_permissions() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let group = seed_group(&db, "blocked", None).await;
    let doomed = seed_key(&db, "doomed", None).await;
    let bystander = seed_key(&db, "bystander", None).await;
    seed_permission(&db, doomed, group).await;
    seed_permission(&db, bystander, group).await;

    assert_eq!(
        api_key_group_permission::Entity::find().count(&db).await.unwrap(),
        2,
        "both grants exist before the delete"
    );

    api_key::Entity::delete_by_id(doomed).exec(&db).await.expect("the key deletes");

    assert_eq!(
        api_key_group_permission::Entity::find()
            .filter(api_key_group_permission::Column::ApiKeyId.eq(doomed))
            .count(&db)
            .await
            .unwrap(),
        0,
        "the deleted key's grants must not survive it — with foreign_keys off they would, and a \
         recycled id would silently inherit them"
    );
    assert_eq!(
        api_key_group_permission::Entity::find()
            .filter(api_key_group_permission::Column::ApiKeyId.eq(bystander))
            .count(&db)
            .await
            .unwrap(),
        1,
        "an unrelated key's grant is untouched: the cascade is scoped, not a table wipe"
    );
}

/// Deleting a key **nulls** its audit rows and keeps them — `fk-audit_logs-api_key_id`,
/// `ON DELETE SET NULL`.
///
/// This is the one constraint in the schema where `CASCADE` would be actively harmful, and it is the
/// reason this test exists as a separate assertion rather than a variation of the one above. An audit
/// log whose rows vanish when the acting key is deleted is an audit log an attacker can erase by
/// deleting their own credential — the single cheapest way to destroy the evidence of what they did.
///
/// The denormalized `api_key_name` and `api_key_prefix` are asserted to survive too. They are why the
/// nulled FK is acceptable: the trail stays legible as a point-in-time snapshot ("key 'worker_bot'
/// did this") rather than degrading to an anonymous row once the join target is gone.
#[tokio::test]
async fn deleting_an_api_key_preserves_its_audit_trail_and_nulls_the_reference() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let key = seed_key(&db, "worker_bot", None).await;
    let entry = seed_audit_log(&db, key, "worker_bot", "IP_ADD").await;

    api_key::Entity::delete_by_id(key).exec(&db).await.expect("the key deletes");

    let row = audit_log::Entity::find_by_id(entry)
        .one(&db)
        .await
        .unwrap()
        .expect("the audit row must survive the deletion of the key that wrote it");

    assert_eq!(row.api_key_id, None, "the dangling reference is nulled, not left pointing nowhere");
    assert_eq!(
        row.api_key_name.as_deref(),
        Some("worker_bot"),
        "the denormalized name survives — this is what keeps the trail readable after the join \
         target is gone"
    );
    assert_eq!(row.api_key_prefix.as_deref(), Some("abcd1234"));
    assert_eq!(row.action, "IP_ADD");
}

/// A key's *children* are not destroyed by deleting it.
///
/// `api_keys.parent_key_id` carries **no** foreign key: it was added by a later migration, and SQLite
/// cannot add a constraint to an existing table without rebuilding it. That is a deliberate outcome
/// and worth pinning, because the alternatives are both wrong. `CASCADE` would make deleting a parent
/// silently destroy an entire subtree of credentials, which §6 forbids in the strongest terms. Even
/// `SET NULL` would quietly re-root daughters at the top level, promoting them out of the subtree that
/// bounded their visibility under §4.
///
/// So the database does nothing here, and `delete_api_key` does the work instead — refusing with an
/// inventory until the caller resolves each affected entity explicitly. This test asserts the
/// database's half of that arrangement: the row survives with its parent reference intact, leaving
/// the decision to the application rather than pre-empting it.
#[tokio::test]
async fn deleting_a_parent_key_does_not_touch_its_daughters_at_the_database_layer() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let parent = seed_key(&db, "parent", None).await;
    let daughter = seed_key(&db, "daughter", Some(parent)).await;

    api_key::Entity::delete_by_id(parent).exec(&db).await.expect("the parent deletes");

    let row = api_key::Entity::find_by_id(daughter)
        .one(&db)
        .await
        .unwrap()
        .expect("a daughter key is never destroyed as a side effect — RBAC_MODEL.md §6");
    assert_eq!(
        row.parent_key_id,
        Some(parent),
        "the parent reference is left exactly as it was: neither cascaded nor silently re-rooted, \
         because both would be decisions the database is not entitled to make"
    );
}

// ─────────────────────────────────────────────────────────────
// Deleting a group
// ─────────────────────────────────────────────────────────────

/// Deleting a group cascades to all three tables that reference it, and to nothing else.
///
/// Three constraints fire at once — `fk-akgp-group_id`, `fk-irgm-group_id`, and
/// `fk-webhook_configs-group_id` — which is exactly why they are asserted together: a migration that
/// rebuilt this table and dropped one of the three would leave the other two working, and a test
/// covering only one of them would stay green.
///
/// The IP **records** are asserted to survive. Only the membership rows are collection-scoped; a
/// record can belong to several groups, and destroying the address itself because one of its groups
/// was removed would be the implicit data loss §6 rules out.
#[tokio::test]
async fn deleting_a_group_cascades_to_permissions_memberships_and_webhooks() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let key = seed_key(&db, "operator", None).await;
    let doomed = seed_group(&db, "doomed", Some(key)).await;
    let survivor = seed_group(&db, "survivor", Some(key)).await;

    seed_permission(&db, key, doomed).await;
    seed_permission(&db, key, survivor).await;
    let record = seed_record_in_group(&db, "198.51.100.9", doomed).await;
    seed_webhook(&db, "doomed_hook", doomed, Some(key)).await;
    seed_webhook(&db, "surviving_hook", survivor, Some(key)).await;

    // The record also belongs to the surviving group, so its own row must outlive the delete.
    ip_record_group_membership::Entity::insert(ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record),
        group_id: Set(survivor),
    })
    .exec(&db)
    .await
    .expect("a record may belong to several groups");

    ip_group::Entity::delete_by_id(doomed).exec(&db).await.expect("the group deletes");

    assert_eq!(
        api_key_group_permission::Entity::find()
            .filter(api_key_group_permission::Column::GroupId.eq(doomed))
            .count(&db)
            .await
            .unwrap(),
        0,
        "grants on a group that no longer exists must not survive it"
    );
    assert_eq!(
        ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::GroupId.eq(doomed))
            .count(&db)
            .await
            .unwrap(),
        0,
        "memberships in a deleted group are removed"
    );
    assert_eq!(
        webhook_config::Entity::find()
            .filter(webhook_config::Column::GroupId.eq(doomed))
            .count(&db)
            .await
            .unwrap(),
        0,
        "a webhook whose only subject is gone would fire on nothing"
    );

    assert!(
        ip_record::Entity::find_by_id(record).one(&db).await.unwrap().is_some(),
        "the IP record itself survives: it is a member of another group, and an address is not \
         owned by any one collection"
    );
    assert_eq!(
        ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::GroupId.eq(survivor))
            .count(&db)
            .await
            .unwrap(),
        1,
        "the surviving group keeps its membership"
    );
    assert_eq!(
        webhook_config::Entity::find()
            .filter(webhook_config::Column::GroupId.eq(survivor))
            .count(&db)
            .await
            .unwrap(),
        1,
        "the surviving group keeps its webhook"
    );
}

/// Deleting an IP record removes its memberships — `fk-irgm-ip_record_id`, `ON DELETE CASCADE`.
///
/// The mirror of the group case, and it matters for the same reason: `ip_record_group_memberships`
/// has a composite primary key over both columns, so a membership orphaned by a deleted record would
/// block re-inserting that record into the same group afterwards with a primary-key collision on a
/// row nothing can see.
#[tokio::test]
async fn deleting_an_ip_record_cascades_to_its_group_memberships() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let group = seed_group(&db, "blocked", None).await;
    let record = seed_record_in_group(&db, "198.51.100.20", group).await;

    ip_record::Entity::delete_by_id(record).exec(&db).await.expect("the record deletes");

    assert_eq!(
        ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.eq(record))
            .count(&db)
            .await
            .unwrap(),
        0,
        "memberships of a deleted record are removed"
    );
    assert!(
        ip_group::Entity::find_by_id(group).one(&db).await.unwrap().is_some(),
        "the group survives: a cascade travels from the referenced row to the referencing one, \
         never the other way"
    );
}

// ─────────────────────────────────────────────────────────────
// Orphans
// ─────────────────────────────────────────────────────────────

/// **ADVERSARIAL.** An orphan cannot be written, even by a writer that bypasses the entity layer.
///
/// Every other test in this file deletes through SeaORM and checks the aftermath, which proves the
/// constraints fire but not that they cannot be *evaded*. This one goes around the entity API
/// entirely and issues the `INSERT` as raw SQL — the shape a restore script, a migration, or a second
/// process sharing the file would take. A constraint that only holds for cooperative writers is not a
/// constraint, and with `foreign_keys` off SQLite accepts every statement below without a word.
#[tokio::test]
async fn raw_sql_cannot_write_a_row_referencing_a_nonexistent_parent() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let ghost = Uuid::new_v4();

    let orphan_grant = db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "INSERT INTO api_key_group_permissions \
                 (id, api_key_id, group_id, can_read, can_write, can_delete, can_manage, created_at) \
                 VALUES ('{}', '{ghost}', '{ghost}', 1, 0, 0, 0, '2026-01-01 00:00:00')",
                Uuid::new_v4()
            ),
        ))
        .await;
    assert!(
        orphan_grant.is_err(),
        "a grant naming a key and group that do not exist must be refused at the engine"
    );

    let orphan_membership = db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "INSERT INTO ip_record_group_memberships (ip_record_id, group_id) \
                 VALUES ('{ghost}', '{ghost}')"
            ),
        ))
        .await;
    assert!(orphan_membership.is_err(), "a membership naming neither a record nor a group is refused");

    let orphan_webhook = db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "INSERT INTO webhook_configs \
                 (id, name, target_url, secret_token, auth_mode, payload_template, group_id, \
                  is_active, created_at) \
                 VALUES ('{}', 'ghost', 'https://x.invalid', 't', 'none', '{{}}', '{ghost}', 1, \
                  '2026-01-01 00:00:00')",
                Uuid::new_v4()
            ),
        ))
        .await;
    assert!(orphan_webhook.is_err(), "a webhook bound to a group that does not exist is refused");
}

/// A freshly migrated database contains no violated references, by the engine's own reckoning.
///
/// `PRAGMA foreign_key_check` walks every foreign key in the schema and returns one row per
/// violation. An empty result is the strongest available statement that the migration chain — nine
/// migrations, including one that rebuilds `api_keys` to add the generated `master_marker` column —
/// leaves the database referentially clean.
///
/// This is the check that catches the failure mode the others cannot. SQLite enforces foreign keys
/// only on connections that asked it to, so a migration run with the pragma off can write orphans
/// that no later statement will ever notice; and `PRAGMA foreign_keys` is a **no-op inside a
/// transaction**, which is where migrations run. Asserting the outcome directly is worth more than
/// reasoning about whether it could have happened.
#[tokio::test]
async fn a_migrated_database_has_no_orphaned_rows() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let violations = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA foreign_key_check;".to_owned(),
        ))
        .await
        .expect("the integrity check runs");

    assert!(
        violations.is_empty(),
        "the migration chain must leave no dangling references; {} row(s) reported",
        violations.len()
    );
}

/// The same check, after a realistic sequence of writes and deletes.
///
/// A schema can be clean when empty and dirty in use. This seeds the full shape the service produces
/// — keys with daughters, groups, records in several groups, grants, webhooks, audit rows — then
/// deletes from the middle of it and asks the engine to walk every constraint again.
#[tokio::test]
async fn deletes_across_the_whole_schema_leave_no_orphans() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let parent = seed_key(&db, "parent", None).await;
    let daughter = seed_key(&db, "daughter", Some(parent)).await;
    let group_a = seed_group(&db, "group_a", Some(parent)).await;
    let group_b = seed_group(&db, "group_b", Some(daughter)).await;

    seed_permission(&db, parent, group_a).await;
    seed_permission(&db, daughter, group_a).await;
    seed_permission(&db, daughter, group_b).await;

    let record = seed_record_in_group(&db, "198.51.100.30", group_a).await;
    ip_record_group_membership::Entity::insert(ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record),
        group_id: Set(group_b),
    })
    .exec(&db)
    .await
    .expect("the second membership inserts");

    seed_webhook(&db, "hook_a", group_a, Some(parent)).await;
    seed_webhook(&db, "hook_b", group_b, Some(daughter)).await;
    seed_audit_log(&db, parent, "parent", "IP_ADD").await;
    seed_audit_log(&db, daughter, "daughter", "IP_DELETE").await;

    // Delete from the middle: a group with dependents, then a key with grants and audit rows.
    ip_group::Entity::delete_by_id(group_a).exec(&db).await.expect("the group deletes");
    api_key::Entity::delete_by_id(daughter).exec(&db).await.expect("the key deletes");

    let violations = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA foreign_key_check;".to_owned(),
        ))
        .await
        .expect("the integrity check runs");
    assert!(
        violations.is_empty(),
        "cascading deletes must leave the database referentially clean; {} violation(s)",
        violations.len()
    );

    // And the audit trail is still there, which is the property worth the most in this file.
    assert_eq!(
        audit_log::Entity::find().count(&db).await.unwrap(),
        2,
        "no audit row is destroyed by deleting the key that wrote it"
    );
}
