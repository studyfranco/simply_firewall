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
        api_key_name: Set(name.to_owned()),
        api_key_prefix: Set("abcd1234".to_owned()),
        client_ip: Set("203.0.113.7".to_owned()),
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
        row.api_key_name,
        "worker_bot",
        "the denormalized name survives — this is what keeps the trail readable after the join \
         target is gone"
    );
    assert_eq!(row.api_key_prefix, "abcd1234");
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

// ─────────────────────────────────────────────────────────────
// Join tables: no orphan may survive a delete
// ─────────────────────────────────────────────────────────────

/// Every row in both join tables whose referenced parent no longer exists.
///
/// Deliberately **not** `PRAGMA foreign_key_check`. That pragma asks SQLite whether SQLite is
/// satisfied, which is a circular question to put to the engine whose enforcement is under test — if
/// the constraints were declared wrongly, or dropped by a table rebuild, `foreign_key_check` would
/// walk whatever constraints remain and cheerfully report nothing. This walks the data instead, from
/// the application's own idea of what the parents are, so it holds an opinion the schema cannot
/// silently change. Both checks are worth having; they fail for different reasons.
async fn join_table_orphans(db: &DatabaseConnection) -> Vec<String> {
    let mut orphans = Vec::new();

    let key_ids: Vec<Uuid> = api_key::Entity::find()
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.id)
        .collect();
    let group_ids: Vec<Uuid> = ip_group::Entity::find()
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    let record_ids: Vec<Uuid> = ip_record::Entity::find()
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();

    for perm in api_key_group_permission::Entity::find().all(db).await.unwrap() {
        if !key_ids.contains(&perm.api_key_id) {
            orphans.push(format!("api_key_group_permissions {} -> missing key {}", perm.id, perm.api_key_id));
        }
        if !group_ids.contains(&perm.group_id) {
            orphans.push(format!("api_key_group_permissions {} -> missing group {}", perm.id, perm.group_id));
        }
    }

    for m in ip_record_group_membership::Entity::find().all(db).await.unwrap() {
        if !record_ids.contains(&m.ip_record_id) {
            orphans.push(format!("ip_record_group_memberships -> missing record {}", m.ip_record_id));
        }
        if !group_ids.contains(&m.group_id) {
            orphans.push(format!("ip_record_group_memberships -> missing group {}", m.group_id));
        }
    }

    orphans
}

/// Deleting a key, then a group, leaves **no orphan row in either join table** — checked by walking
/// the data rather than by asking the engine.
///
/// The two join tables are where a missed cascade does the most damage, and they fail differently.
/// A stale `api_key_group_permissions` row is *live authority*: it is what every §2 check reads, so
/// it grants access again the moment its id is reused. A stale `ip_record_group_memberships` row is
/// a phantom membership — the address still appears in a group that no longer exists, and because
/// the table's primary key spans both columns, it also blocks ever re-adding that record to a group
/// with the same id.
#[tokio::test]
async fn deleting_a_key_and_a_group_leaves_no_orphans_in_either_join_table() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let doomed_key = seed_key(&db, "doomed_key", None).await;
    let surviving_key = seed_key(&db, "surviving_key", None).await;
    let doomed_group = seed_group(&db, "doomed_group", Some(surviving_key)).await;
    let surviving_group = seed_group(&db, "surviving_group", Some(surviving_key)).await;

    // Four grants across the two-by-two matrix, so each delete has both a victim and a bystander.
    seed_permission(&db, doomed_key, doomed_group).await;
    seed_permission(&db, doomed_key, surviving_group).await;
    seed_permission(&db, surviving_key, doomed_group).await;
    seed_permission(&db, surviving_key, surviving_group).await;

    let record = seed_record_in_group(&db, "198.51.100.40", doomed_group).await;
    ip_record_group_membership::Entity::insert(ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record),
        group_id: Set(surviving_group),
    })
    .exec(&db)
    .await
    .expect("the record joins the surviving group too");

    assert_eq!(api_key_group_permission::Entity::find().count(&db).await.unwrap(), 4);
    assert_eq!(ip_record_group_membership::Entity::find().count(&db).await.unwrap(), 2);
    assert!(join_table_orphans(&db).await.is_empty(), "the fixture starts clean");

    api_key::Entity::delete_by_id(doomed_key).exec(&db).await.expect("the key deletes");
    assert_eq!(
        join_table_orphans(&db).await,
        Vec::<String>::new(),
        "deleting a key must leave no grant pointing at it"
    );
    assert_eq!(
        api_key_group_permission::Entity::find().count(&db).await.unwrap(),
        2,
        "exactly the two grants belonging to the deleted key are gone"
    );

    ip_group::Entity::delete_by_id(doomed_group).exec(&db).await.expect("the group deletes");
    assert_eq!(
        join_table_orphans(&db).await,
        Vec::<String>::new(),
        "deleting a group must leave no grant and no membership pointing at it"
    );
    assert_eq!(
        api_key_group_permission::Entity::find().count(&db).await.unwrap(),
        1,
        "only the surviving key's grant on the surviving group remains"
    );
    assert_eq!(
        ip_record_group_membership::Entity::find().count(&db).await.unwrap(),
        1,
        "only the membership in the surviving group remains"
    );

    // The record itself is untouched by either delete: an address is not owned by a key, and it
    // belongs to more than one group.
    assert!(ip_record::Entity::find_by_id(record).one(&db).await.unwrap().is_some());
}

/// Deleting a key does **not** disturb `ip_record_group_memberships`.
///
/// The complement of the cascades above, and it guards a plausible over-correction rather than an
/// omission. `api_keys` has no relationship to memberships at all — a key *administers* groups, it
/// does not own the addresses in them — so a future migration that added a cascade from keys to
/// memberships would silently erase banlist entries when a credential was rotated out. That would
/// look tidy and be data loss, exactly what §6 forbids.
#[tokio::test]
async fn deleting_a_key_does_not_touch_ip_record_memberships() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let key = seed_key(&db, "operator", None).await;
    let group = seed_group(&db, "blocked", Some(key)).await;
    seed_permission(&db, key, group).await;
    let record = seed_record_in_group(&db, "198.51.100.50", group).await;

    api_key::Entity::delete_by_id(key).exec(&db).await.expect("the key deletes");

    assert_eq!(
        api_key_group_permission::Entity::find().count(&db).await.unwrap(),
        0,
        "the key's own grant is gone"
    );
    assert_eq!(
        ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::GroupId.eq(group))
            .count(&db)
            .await
            .unwrap(),
        1,
        "the membership survives: deleting a credential must never erase the banlist it maintained"
    );
    assert!(ip_record::Entity::find_by_id(record).one(&db).await.unwrap().is_some());
    assert!(ip_group::Entity::find_by_id(group).one(&db).await.unwrap().is_some());
    assert!(join_table_orphans(&db).await.is_empty());
}

/// **The control.** With `foreign_keys` OFF, the same delete leaves orphans behind.
///
/// Every other test in this file asserts that a cascade happened. None of them, alone, says *why* —
/// and "SQLite would have done that anyway" is a real possibility a reader is entitled to rule out.
/// This opens a pool identical to the production one except for `.foreign_keys(false)`, runs the same
/// group delete, and shows the grants and memberships surviving as dangling rows.
///
/// That makes the pragma the attributable cause rather than a setting the suite merely happens to
/// have on. It is worth the extra test because the failure it guards is silent in the worst way:
/// SQLite does not warn when foreign keys are off, it simply stops enforcing them, and the resulting
/// `api_key_group_permissions` rows are live authority that no application-level test would notice.
///
/// This is also the one place in the suite that builds a connection by hand rather than through
/// `db::connect`, which is precisely the point — it is demonstrating what `db::connect` buys.
#[tokio::test]
async fn with_foreign_keys_off_the_same_delete_leaves_dangling_rows() {
    use sea_orm::sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    let tmp = TempDb::new();

    // Identical to `db::connect` except for the one line under test. `max_connections(1)` is kept
    // because migrations need it; the journal and synchronous settings are irrelevant here.
    let options = SqliteConnectOptions::from_str(&tmp.url())
        .expect("the url parses")
        .create_if_missing(true)
        .foreign_keys(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("the pool opens");
    let db = sea_orm::SqlxSqliteConnector::from_sqlx_sqlite_pool(pool);
    simply_ip_vault::db::run_migrations(&db).await.expect("every migration applies");

    // Sanity: the switch really is off. Without this the test could pass because the fixture broke.
    let pragma = db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA foreign_keys;".to_owned(),
        ))
        .await
        .expect("the pragma reads")
        .expect("a row is returned");
    assert_eq!(
        pragma.try_get::<i32>("", "foreign_keys").unwrap(),
        0,
        "this test is meaningless unless foreign keys are genuinely off"
    );

    let key = seed_key(&db, "operator", None).await;
    let group = seed_group(&db, "doomed", Some(key)).await;
    seed_permission(&db, key, group).await;
    seed_record_in_group(&db, "198.51.100.60", group).await;

    ip_group::Entity::delete_by_id(group).exec(&db).await.expect("the group deletes");

    assert_eq!(
        api_key_group_permission::Entity::find().count(&db).await.unwrap(),
        1,
        "with foreign keys off the grant survives its group — this is the orphan the pragma prevents"
    );
    assert_eq!(
        ip_record_group_membership::Entity::find().count(&db).await.unwrap(),
        1,
        "and so does the membership"
    );

    let orphans = join_table_orphans(&db).await;
    assert_eq!(
        orphans.len(),
        2,
        "both join tables are left dangling; with the pragma on this list is empty: {orphans:?}"
    );
}

// ─────────────────────────────────────────────────────────────
// Audit attribution: NOT NULL, and what the rebuild had to preserve
// ─────────────────────────────────────────────────────────────
//
// `m20260811_000010` makes `api_key_name`, `api_key_prefix` and `client_ip` NOT NULL. On SQLite that
// is not an `ALTER COLUMN` — the engine has none — but a full table rebuild: create, copy, drop,
// rename. A rebuild is the most dangerous shape of migration there is, because everything it forgets
// to recreate simply stops existing, and nothing fails. The tests below pin each thing it had to
// carry across.

/// The constraint is enforced by the **engine**, against a writer that bypasses the entity layer.
///
/// The Rust type says `String`, so no application path can produce a NULL — but the type is not what
/// is deployed, and a restore, an operator, or a future migration writes SQL directly. This asserts
/// the column, not the struct.
#[tokio::test]
async fn audit_attribution_columns_reject_null_from_raw_sql() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;
    let key = seed_key(&db, "operator", None).await;

    for column in ["api_key_name", "api_key_prefix", "client_ip"] {
        // Every other column is supplied; only the one under test is NULL, so a refusal can only be
        // that column's constraint rather than an incidental error.
        let sql = format!(
            "INSERT INTO audit_logs \
             (id, api_key_id, api_key_name, api_key_prefix, client_ip, action, timestamp) \
             VALUES (x'{}', x'{}', {}, {}, {}, 'IP_ADD', '2026-01-01 00:00:00')",
            Uuid::new_v4().simple(),
            key.simple(),
            if column == "api_key_name" { "NULL" } else { "'n'" },
            if column == "api_key_prefix" { "NULL" } else { "'p'" },
            if column == "client_ip" { "NULL" } else { "'203.0.113.1'" },
        );
        let outcome = db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite, sql)).await;
        assert!(
            outcome.is_err(),
            "a NULL {column} must be refused — an audit row with no actor records an action nobody \
             performed"
        );
    }

    // The control: the same statement with every column supplied must succeed. Without it, a
    // malformed INSERT would make all three assertions above pass for the wrong reason forever.
    let ok = db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "INSERT INTO audit_logs \
                 (id, api_key_id, api_key_name, api_key_prefix, client_ip, action, timestamp) \
                 VALUES (x'{}', x'{}', 'n', 'p', '203.0.113.1', 'IP_ADD', '2026-01-01 00:00:00')",
                Uuid::new_v4().simple(),
                key.simple()
            ),
        ))
        .await;
    assert!(ok.is_ok(), "a fully attributed row must still insert: {ok:?}");
}

/// The rebuild preserved `ON DELETE SET NULL` on `api_key_id`.
///
/// The single highest-risk thing about this migration. That cascade is what lets a key be deleted
/// without erasing what it did; a rebuild that dropped the foreign key, or recreated it as `CASCADE`,
/// would turn deleting a credential into deleting its own audit trail — and the only symptom would be
/// rows quietly disappearing.
#[tokio::test]
async fn the_audit_rebuild_preserved_the_set_null_cascade() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let key = seed_key(&db, "worker_bot", None).await;
    let entry = seed_audit_log(&db, key, "worker_bot", "IP_ADD").await;

    api_key::Entity::delete_by_id(key).exec(&db).await.expect("the key deletes");

    let row = audit_log::Entity::find_by_id(entry)
        .one(&db)
        .await
        .unwrap()
        .expect("the audit row must survive the key that wrote it");
    assert_eq!(row.api_key_id, None, "the dangling reference is nulled");
    assert_eq!(
        row.api_key_name, "worker_bot",
        "and the denormalized attribution survives — which is now NOT NULL, so this is the only \
         record of who acted"
    );
    assert_eq!(row.api_key_prefix, "abcd1234");
}

/// The rebuild preserved both indexes.
///
/// They are dropped with the old table and must be recreated by hand. Losing one turns every audit
/// listing into a table scan — a regression no functional test would ever notice.
#[tokio::test]
async fn the_audit_rebuild_preserved_both_indexes() {
    use sea_orm_migration::SchemaManager;

    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;
    let manager = SchemaManager::new(&db);

    for index in ["idx-audit_logs-action", "idx-audit_logs-timestamp"] {
        assert!(
            manager.has_index("audit_logs", index).await.unwrap(),
            "{index} did not survive the table rebuild"
        );
    }
}

/// Historical rows survive the constraint, and say so honestly.
///
/// Migrations 1–9 are applied, a row with NULL attribution is written the way the old schema allowed,
/// and only then is migration 10 applied. This is the upgrade path a real deployment takes, and it is
/// the one path the rest of the suite cannot exercise — every other test starts from a fully migrated
/// database where such a row is already impossible.
#[tokio::test]
async fn rows_written_before_the_constraint_are_backfilled_not_dropped() {
    use sea_orm_migration::MigratorTrait;

    let tmp = TempDb::new();
    let db = simply_ip_vault::db::connect(&tmp.url()).await.expect("pool opens");

    // Everything up to and including m20260808_000009, but not m20260811_000010.
    simply_ip_vault::migration::Migrator::up(&db, Some(9)).await.expect("nine migrations apply");

    let key = seed_key(&db, "legacy", None).await;
    let legacy = Uuid::new_v4();
    db.execute_raw(Statement::from_string(
        DatabaseBackend::Sqlite,
        format!(
            "INSERT INTO audit_logs (id, api_key_id, action, timestamp) \
             VALUES (x'{}', x'{}', 'IP_ADD', '2020-01-01 00:00:00')",
            legacy.simple(),
            key.simple()
        ),
    ))
    .await
    .expect("the old schema permitted unattributed rows");

    // Now the constraint lands.
    simply_ip_vault::migration::Migrator::up(&db, None).await.expect("the backfill migration applies");

    let row = audit_log::Entity::find_by_id(legacy)
        .one(&db)
        .await
        .unwrap()
        .expect("a historical row must be backfilled, never discarded");

    assert_eq!(row.api_key_name, "(unknown)");
    assert_eq!(row.api_key_prefix, "(unknown)");
    assert_eq!(row.client_ip, "(unknown)");
    assert_eq!(row.action, "IP_ADD", "the rest of the row is carried across untouched");
    assert_eq!(row.api_key_id, Some(key), "including the foreign key");
    assert!(
        row.client_ip.parse::<std::net::IpAddr>().is_err(),
        "the fallback must not be mistakable for a real address — a reader has to be able to tell \
         'not recorded' from 'recorded as this'"
    );
}

/// The copy is by column name, not by position.
///
/// A rebuild that copies positionally looks correct until a column order changes, at which point
/// names land in the address column and every type still checks out. Asserted with values that make
/// a transposition visible.
#[tokio::test]
async fn the_audit_rebuild_did_not_transpose_columns() {
    use sea_orm_migration::MigratorTrait;

    let tmp = TempDb::new();
    let db = simply_ip_vault::db::connect(&tmp.url()).await.expect("pool opens");
    simply_ip_vault::migration::Migrator::up(&db, Some(9)).await.expect("nine migrations apply");

    let key = seed_key(&db, "before", None).await;
    let id = Uuid::new_v4();
    db.execute_raw(Statement::from_string(
        DatabaseBackend::Sqlite,
        format!(
            "INSERT INTO audit_logs \
             (id, api_key_id, api_key_name, api_key_prefix, client_ip, action, target_address, \
              group_names, details, timestamp) \
             VALUES (x'{}', x'{}', 'NAME', 'PREFIX', '198.51.100.7', 'ACTION', 'TARGET', \
              'GROUPS', 'DETAILS', '2021-02-03 04:05:06')",
            id.simple(),
            key.simple()
        ),
    ))
    .await
    .expect("the row inserts");

    simply_ip_vault::migration::Migrator::up(&db, None).await.expect("the rebuild applies");

    let row = audit_log::Entity::find_by_id(id).one(&db).await.unwrap().expect("row survives");
    assert_eq!(row.api_key_name, "NAME");
    assert_eq!(row.api_key_prefix, "PREFIX");
    assert_eq!(row.client_ip, "198.51.100.7");
    assert_eq!(row.action, "ACTION");
    assert_eq!(row.target_address.as_deref(), Some("TARGET"));
    assert_eq!(row.group_names.as_deref(), Some("GROUPS"));
    assert_eq!(row.details.as_deref(), Some("DETAILS"));
    assert_eq!(row.api_key_id, Some(key));
}
