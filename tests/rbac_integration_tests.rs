use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter};
use sea_orm_migration::MigratorTrait;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use simply_ip_vault::{create_app, migration, state::AppState};

async fn setup_test_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();
    db
}

fn inject_connect_info(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
}

// ─────────────────────────────────────────────────────────────
// HMAC request signing helpers
//
// Every `/api/*` request now needs `X-Timestamp` and an `X-Signature-256` over
// `METHOD + PATH + TIMESTAMP + RAW_BODY`. Rather than thread a second credential through each of
// the ~100 request-building sites below, keys seeded directly into the database follow a fixed
// convention (see `test_signing_secret`) that lets `signed()` recover the right secret from the
// request's own `X-API-Key` header.
// ─────────────────────────────────────────────────────────────

/// Test-only convention: a database-seeded key's signing secret is derived from its plaintext API
/// key, so [`signed`] can rediscover it from the `X-API-Key` header alone.
///
/// Only valid for keys inserted by these tests. Keys minted through `POST /api/keys` (or rotated via
/// `POST /api/keys/{id}/rotate`) get a server-generated random secret returned in the response body,
/// and must be signed with [`signed_with`] instead.
fn test_signing_secret(api_key: &str) -> String {
    format!("signing-secret-for-{api_key}")
}

/// Builds a signed request, deriving the signing secret from the builder's own `X-API-Key` header.
///
/// A builder carrying no `X-API-Key` still gets an `X-Timestamp` but no signature — exactly what the
/// "missing key is rejected" cases need, since they must fail on authentication rather than on a
/// missing timestamp.
fn signed(builder: axum::http::request::Builder, body: impl Into<String>) -> Request<Body> {
    let derived = builder
        .headers_ref()
        .and_then(|h| h.get("X-API-Key"))
        .and_then(|v| v.to_str().ok())
        .map(test_signing_secret);
    build_signed(builder, derived.as_deref(), body.into())
}

/// Builds a signed request using an explicitly supplied signing secret, for keys whose secret was
/// generated server-side and read back out of a `POST /api/keys` or `/rotate` response.
fn signed_with(
    builder: axum::http::request::Builder,
    signing_secret: &str,
    body: impl Into<String>,
) -> Request<Body> {
    build_signed(builder, Some(signing_secret), body.into())
}

/// Builds a request signed at an explicit `X-Timestamp`, for exercising the anti-replay window.
///
/// The signature is computed over the same (possibly stale) timestamp that is sent, so these
/// requests are cryptographically valid and can only be rejected by the freshness check itself —
/// which is precisely what makes them a test of the anti-replay guard rather than of the HMAC.
fn signed_at(
    builder: axum::http::request::Builder,
    signing_secret: &str,
    timestamp: i64,
    body: impl Into<String>,
) -> Request<Body> {
    build_signed_at(builder, Some(signing_secret), timestamp.to_string(), body.into())
}

/// Attaches `X-Timestamp` (and, when a secret is available, `X-Signature-256`) and finishes the
/// request. The timestamp is always "now", so these requests sit comfortably inside the server's
/// 300-second anti-replay window.
fn build_signed(
    builder: axum::http::request::Builder,
    signing_secret: Option<&str>,
    body: String,
) -> Request<Body> {
    let timestamp = chrono::Utc::now().timestamp().to_string();
    build_signed_at(builder, signing_secret, timestamp, body)
}

/// Shared implementation behind [`build_signed`] and [`signed_at`].
fn build_signed_at(
    builder: axum::http::request::Builder,
    signing_secret: Option<&str>,
    timestamp: String,
    body: String,
) -> Request<Body> {
    // Read method/path back off the builder so the signature always matches what is actually sent.
    // The query string is deliberately excluded, mirroring `crypto::verify_signature`.
    let method = builder
        .method_ref()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "GET".to_owned());
    let path = builder
        .uri_ref()
        .map(|u| u.path().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    let mut builder = builder.header("X-Timestamp", &timestamp);
    if let Some(secret) = signing_secret {
        let signature = simply_ip_vault::crypto::compute_signature(
            secret,
            &method,
            &path,
            &timestamp,
            body.as_bytes(),
        )
        .unwrap();
        builder = builder.header("X-Signature-256", signature);
    }

    builder.body(Body::from(body)).unwrap()
}

/// `ALLOW_PRIVATE_WEBHOOKS` and `VAULT_ENCRYPTION_KEY` are process-wide global state. Any test that
/// mutates it must hold this lock for the duration, so two such tests running on different libtest
/// threads can never interleave their `set_var` calls (which is itself a data race, hence why
/// `set_var` is `unsafe`).
///
/// Tests that mint a key through `POST /api/keys` (or `/rotate`) and then authenticate as it must
/// hold this lock too, even though they set nothing themselves: whether that key's signing secret
/// gets sealed is decided by `VAULT_ENCRYPTION_KEY` *at creation time*, so a concurrent test
/// clearing the variable in between would leave them unable to decrypt their own secret.
static ENV_MUTATION_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[tokio::test]
async fn test_auth_and_cidr_rejection() {
    let db = setup_test_db().await;
    let (webhook_tx, _) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);

    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        name: Set("Test Key".to_owned()),
        bound_ips: Set(Some("192.168.1.1/32".to_owned())),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    // 1. Missing Key -> 401
    let req = signed(inject_connect_info(Request::builder().uri("/api/ips")), "");
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid CIDR -> 403 (Client IP matches 127.0.0.1 from ConnectInfo, not 192.168.1.1)
    let req = signed(inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &plaintext)), "");
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // 3. Valid CIDR (simulated via X-Forwarded-For) -> 200
    let req = signed(inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &plaintext).header("X-Forwarded-For", "192.168.1.1")), "");
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_tenant_isolation_mn_rbac() {
    let db = setup_test_db().await;
    let (webhook_tx, _) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    // Create a group
    let group_a_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_a_id),
        name: Set("Group A".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);

    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        name: Set("Tenant Key".to_owned()),
        bound_ips: Set(Some("0.0.0.0/0".to_owned())),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    // Key has NO explicit junction mapping yet.
    
    // Attempt POST to Group A without permissions -> 403
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "8.8.8.8", "group_name": "Group A" }).to_string());
    
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Assign M:N Read/Write permissions
    simply_ip_vault::entities::api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key_id),
        group_id: Set(group_a_id),
        can_read: Set(true),
        can_write: Set(true),
        can_delete: Set(false),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    // POST to Group A -> Should Work
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "8.8.8.8", "group_name": "Group A" }).to_string());
    
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auto_provisioning_on_group_creation() {
    let db = setup_test_db().await;
    let (webhook_tx, _) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);

    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        name: Set("Creator Key".to_owned()),
        bound_ips: Set(Some("0.0.0.0/0".to_owned())),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(true), // CAN CREATE GROUPS
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    // Post to an completely new group
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "4.4.4.4", "group_name": "Dynamic Group" }).to_string());
    
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Verify it automatically gave us 'can_delete' in the M:N binding
    let perms = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .all(&db).await.unwrap();
    
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].api_key_id, key_id);
    assert!(perms[0].can_read);
    assert!(perms[0].can_write);
    assert!(perms[0].can_delete);
}

/// Same auto-provisioning guarantee as `test_auto_provisioning_on_group_creation`, but exercised
/// via the EXPLICIT `POST /api/groups` endpoint rather than an implicit ban/white auto-create —
/// AGENT.MD's rule ("When an API Key creates a new IpGroup...") applies to both paths, and only
/// the implicit one had coverage before this test.
#[tokio::test]
async fn test_explicit_group_creation_grants_full_permissions_to_creator() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (key_id, plaintext) = insert_key(&db, "Group Creator", false, false, false, true).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/groups")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "name": "explicitly-created-group" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let group_id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();

    let perm = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(key_id))
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::GroupId.eq(group_id))
        .one(&db)
        .await
        .unwrap()
        .expect("creator should have an auto-granted permission row on the group it just created");

    assert!(perm.can_read);
    assert!(perm.can_write);
    assert!(perm.can_delete);
}

/// RBAC must be checked BEFORE group-type validation: a key with no permission mapping at all on
/// an existing (whitelist-typed) group must get 403, never 400 — a caller with no access to a
/// group shouldn't learn anything about it, including its type, and should get the same denial
/// it would get for any other group it can't touch.
#[tokio::test]
async fn test_rbac_denial_precedes_group_type_validation() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (_key_b_id, key_b) = insert_key(&db, "No-Access Key", false, false, false, false).await;

    // Master creates a whitelist-typed group.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/white")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.9", "group_name": "precedence-whitelist" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // key_b has NO permission mapping at all on this group — must get 403, not 400, even though
    // the group is also the "wrong" type for a ban.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json")), json!({ "target_address": "198.51.100.5", "group_name": "precedence-whitelist" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("Permission denied"));
}

/// Once RBAC clears a key for write access, group-type mismatches are still rejected — in both
/// directions — with the exact, actionable message naming the group and pointing at the correct
/// endpoint/group type.
#[tokio::test]
async fn test_group_type_mismatch_rejected_with_exact_message_for_authorized_key() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_b_id, key_b) = insert_key(&db, "Key_B", false, false, false, false).await;

    // Master creates a whitelist group and a banlist group, each seeded with an address.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/white")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.10", "group_name": "type-check-whitelist" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.11", "group_name": "type-check-banlist" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Grant Key_B full read+write on BOTH groups.
    for group_name in ["type-check-whitelist", "type-check-banlist"] {
        let req = signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri(format!("/api/keys/{key_b_id}/groups"))
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({
                "group_name": group_name,
                "can_read": true,
                "can_write": true,
                "can_delete": false
            }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    // Banning into the whitelist group is rejected with the exact specified message.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json")), json!({ "target_address": "198.51.100.20", "group_name": "type-check-whitelist" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["error"],
        "Cannot ban IP into group 'type-check-whitelist': group type is 'whitelist'. Use /api/white or target a banlist group."
    );

    // Whitelisting into the banlist group is rejected with the exact specified (reverse) message.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/white")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json")), json!({ "target_address": "198.51.100.21", "group_name": "type-check-banlist" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["error"],
        "Cannot whitelist IP into group 'type-check-banlist': group type is 'banlist'. Use /api/ban or target a whitelist group."
    );
}

#[tokio::test]
async fn test_explicit_key_group_manipulation() {
    let db = setup_test_db().await;
    let (webhook_tx, _) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let master_id = Uuid::new_v4();
    let master_plaintext = simply_ip_vault::api::generate_random_key();
    let master_hash = simply_ip_vault::api::hash_key(&master_plaintext);

    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(master_id),
        key_hash: Set(master_hash),
        signing_secret: Set(Some(test_signing_secret(&master_plaintext))),
        name: Set("System Master".to_owned()),
        bound_ips: Set(Some("0.0.0.0/0".to_owned())),
        is_master: Set(true), // CAN MANAGE KEYS
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let target_id = Uuid::new_v4();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(target_id),
        key_hash: Set(simply_ip_vault::api::hash_key("dummy")),
        signing_secret: Set(Some(test_signing_secret("dummy"))),
        name: Set("Target Sub-Key".to_owned()),
        bound_ips: Set(Some("192.168.1.1/32".to_owned())),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{}/groups", target_id))
        .header("X-API-Key", &master_plaintext)
        .header("Content-Type", "application/json")), json!({
            "group_name": "Dynamic Access Hub",
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string());

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let perms = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .all(&db)
        .await
        .unwrap();

    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].api_key_id, target_id);
    assert!(perms[0].can_read);
    assert!(!perms[0].can_write);
}

/// AGENT.MD mandates verifying multi-group and temporal (`max_age`/`since`) query filtering on
/// `GET /api/v1/ips`.
#[tokio::test]
async fn test_multi_group_and_temporal_filtering() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        name: Set("Master".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    // A fresh record, created "now" through the API, in "group-fresh".
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "9.9.9.9", "group_name": "group-fresh" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // A stale record inserted directly with an old `last_seen_at`, in "group-old".
    let old_group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(old_group_id),
        name: Set("group-old".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let old_record_id = Uuid::new_v4();
    let old_time = chrono::Utc::now().naive_utc() - chrono::Duration::hours(2);
    simply_ip_vault::entities::ip_record::ActiveModel {
        id: Set(old_record_id),
        target_address: Set("8.8.4.4".to_owned()),
        cause: Set(None),
        is_locked: Set(false),
        created_at: Set(old_time),
        updated_at: Set(old_time),
        last_seen_at: Set(old_time),
    }
    .insert(&db)
    .await
    .unwrap();

    simply_ip_vault::entities::ip_record_group_membership::ActiveModel {
        ip_record_id: Set(old_record_id),
        group_id: Set(old_group_id),
    }
    .insert(&db)
    .await
    .unwrap();

    // `groups` filter: only the fresh record's group should be returned.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=group-fresh")
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["target_address"], "9.9.9.9");

    // `max_age` filter: a 60-second window must exclude the 2-hour-old record but keep the
    // fresh one, and the exclusion must happen in the query (not just be truncated by paging).
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?max_age=60")
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(items.iter().any(|i| i["target_address"] == "9.9.9.9"));
    assert!(items.iter().all(|i| i["target_address"] != "8.8.4.4"));

    // `since` filter: a very recent Unix timestamp must also exclude the stale record.
    let since_ts = (chrono::Utc::now() - chrono::Duration::minutes(5)).timestamp();
    let req = signed(inject_connect_info(Request::builder()
        .uri(format!("/api/ips?since={since_ts}"))
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(items.iter().any(|i| i["target_address"] == "9.9.9.9"));
    assert!(items.iter().all(|i| i["target_address"] != "8.8.4.4"));
}

/// AGENT.MD mandates verifying webhook payload delivery and HMAC `X-Signature-256` validity via
/// a mock HTTP endpoint.
#[tokio::test]
async fn test_webhook_hmac_signature_and_delivery() {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use std::sync::{Arc, Mutex};

    let _env_guard = ENV_MUTATION_LOCK.lock().await;

    #[derive(Default)]
    struct Captured {
        body: Option<String>,
        signature: Option<String>,
    }

    let captured: Arc<Mutex<Captured>> = Arc::new(Mutex::new(Captured::default()));
    let captured_for_handler = captured.clone();

    let hook_app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
            let captured = captured_for_handler.clone();
            async move {
                let sig = headers
                    .get("X-Signature-256")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_owned());
                let mut c = captured.lock().unwrap();
                c.body = Some(body);
                c.signature = sig;
                StatusCode::OK
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = listener.local_addr().unwrap();
    let _hook_server = tokio::spawn(async move {
        axum::serve(listener, hook_app).await.unwrap();
    });

    // The mock hook above lives on loopback, which SSRF protection blocks by default; this test
    // explicitly opts in to private targets to exercise the signing/delivery path.
    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true");
    }

    let db = setup_test_db().await;
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::channel(100);
    let db_for_worker = db.clone();
    let _worker_handle = tokio::spawn(async move {
        simply_ip_vault::webhooks::run_webhook_worker(db_for_worker, webhook_rx).await;
    });

    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        name: Set("Webhook Tester".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("hook-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let secret = "top-secret-webhook-key";
    let hook_url = format!("http://{hook_addr}/hook");
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "Test Hook",
            "target_url": hook_url,
            "secret_token": secret,
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "5.5.5.5", "group_name": "hook-group" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Dispatch is async (channel + background worker + spawned HTTP task); poll for delivery.
    let mut delivered = None;
    for _ in 0..40 {
        {
            let c = captured.lock().unwrap();
            if c.body.is_some() {
                delivered = Some((c.body.clone().unwrap(), c.signature.clone()));
            }
        }
        if delivered.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false");
    }

    let (body, signature) = delivered.expect("webhook was not delivered within timeout");
    let signature = signature.expect("missing X-Signature-256 header");

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    assert_eq!(signature, expected);
    assert!(body.contains("5.5.5.5"));
}

/// A webhook scoped to `events: "IP_ADD"` must fire for a genuinely new address (`IP_ADD`) but
/// must be skipped for a re-registration of that same address (`IP_UPDATE`) and for its deletion
/// (`IP_DELETE`) — the dispatcher's per-config event allowlist in `run_webhook_worker`.
#[tokio::test]
async fn test_webhook_event_filtering_skips_non_matching_actions() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let _env_guard = ENV_MUTATION_LOCK.lock().await;

    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_count_for_handler = hit_count.clone();

    let hook_app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move || {
            let hit_count = hit_count_for_handler.clone();
            async move {
                hit_count.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = listener.local_addr().unwrap();
    let _hook_server = tokio::spawn(async move {
        axum::serve(listener, hook_app).await.unwrap();
    });

    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true");
    }

    let db = setup_test_db().await;
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::channel(100);
    let db_for_worker = db.clone();
    let _worker_handle = tokio::spawn(async move {
        simply_ip_vault::webhooks::run_webhook_worker(db_for_worker, webhook_rx).await;
    });

    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        name: Set("Event Filter Tester".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("event-filter-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let hook_url = format!("http://{hook_addr}/hook");
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "Add-Only Hook",
            "target_url": hook_url,
            "secret_token": "irrelevant-for-this-test",
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
            "events": "IP_ADD",
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // A brand-new address is an IP_ADD — the webhook IS subscribed to this, so it must fire.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "9.9.9.9", "group_name": "event-filter-group" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let mut saw_add_delivery = false;
    for _ in 0..40 {
        if hit_count.load(Ordering::SeqCst) >= 1 {
            saw_add_delivery = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(saw_add_delivery, "IP_ADD should have been delivered to the events:\"IP_ADD\" webhook");
    assert_eq!(hit_count.load(Ordering::SeqCst), 1, "exactly one delivery so far");

    // Re-registering the SAME address in the SAME group is an IP_UPDATE — not subscribed, must
    // be skipped. There's no "it happened" signal to poll for here, so wait a fixed, generous
    // window (dispatch to a local loopback listener normally completes in low single-digit ms)
    // and confirm the hit count did NOT advance.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "9.9.9.9", "group_name": "event-filter-group", "cause": "updated" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(hit_count.load(Ordering::SeqCst), 1, "IP_UPDATE must NOT be delivered to an events:\"IP_ADD\"-only webhook");

    // Deleting it is an IP_DELETE — also not subscribed, must also be skipped.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips?target_address=9.9.9.9&group_name=event-filter-group")
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false");
    }

    assert_eq!(hit_count.load(Ordering::SeqCst), 1, "IP_DELETE must NOT be delivered to an events:\"IP_ADD\"-only webhook");
}

/// Regression test for a bug found by manual exploratory testing: re-banning an address into a
/// group it already belongs to used `Entity::insert(..).on_conflict(..).do_nothing().exec(db)`
/// for the membership row, which raises `DbErr::RecordNotInserted` ("None of the records are
/// inserted") whenever the `DO NOTHING` branch actually fires, turning AGENT.MD's mandatory
/// "re-registering an existing IP updates `last_seen_at` rather than failing" behavior into a
/// 500 on the single most common real-world firewall operation. The fix uses
/// `exec_without_returning`, which doesn't require a row back.
#[tokio::test]
async fn test_reban_into_same_group_does_not_500() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        name: Set("Master".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let ban = |cause: &'static str| {
        json!({ "target_address": "77.77.77.77", "group_name": "reban-group", "cause": cause }).to_string()
    };

    // First ban: creates the record and the membership row (no conflict).
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), ban("first offense"));
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Second ban into the SAME group: the membership insert hits the conflict path. Must still
    // return 200, not 500.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), ban("second offense"));
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Exactly one record and one membership row must exist, with the cause updated.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=reban-group")
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["cause"], "second offense");
}

/// Regression test for a bug found by manual exploratory testing: `POST /api/webhooks` accepted
/// any string as `target_url`, including "not a url", creating a webhook that could never
/// possibly be delivered with no feedback to the caller (it would only ever fail silently, once
/// per matching event, at dispatch time). `create_webhook` now validates the URL eagerly.
#[tokio::test]
async fn test_create_webhook_rejects_invalid_url() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        name: Set("Master".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("webhook-validation-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let make_req = |url: &str| {
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/webhooks")
            .header("X-API-Key", &plaintext)
            .header("Content-Type", "application/json")), json!({
                "name": "Test",
                "target_url": url,
                "secret_token": "s",
                "payload_template": "{}",
                "group_id": group_id.to_string(),
            }).to_string())
    };

    let res = app.clone().oneshot(make_req("not a url")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let res = app.clone().oneshot(make_req("ftp://example.com/hook")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let res = app.clone().oneshot(make_req("https://example.com/hook")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

// ─────────────────────────────────────────────────────────────
// API Key lifecycle & RBAC permission enforcement
// ─────────────────────────────────────────────────────────────

async fn insert_key(
    db: &DatabaseConnection,
    name: &str,
    is_master: bool,
    can_manage_keys: bool,
    can_manage_webhooks: bool,
    can_create_groups: bool,
) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(hash),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        name: Set(name.to_owned()),
        bound_ips: Set(None),
        is_master: Set(is_master),
        can_manage_keys: Set(can_manage_keys),
        can_manage_webhooks: Set(can_manage_webhooks),
        can_create_groups: Set(can_create_groups),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    (id, plaintext)
}

/// Covers: a master key can create a new API key with specific global flags and `bound_ips`; a
/// non-privileged key gets `403 Forbidden` attempting the same.
#[tokio::test]
async fn test_key_creation_lifecycle() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/keys")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "name": "CI Bot",
            "bound_ips": "10.0.0.0/8",
            "can_manage_keys": true,
            "can_manage_webhooks": true
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(created["plaintext_key"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(created["bound_ips"], "10.0.0.0/8");
    let new_key_id = created["id"].as_str().unwrap();

    // Confirm the persisted flags actually match what was requested (not just the create
    // response echoing the input back).
    let stored = simply_ip_vault::entities::api_key::Entity::find_by_id(Uuid::parse_str(new_key_id).unwrap())
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.can_manage_keys);
    assert!(stored.can_manage_webhooks);
    assert!(!stored.can_create_groups);
    assert_eq!(stored.bound_ips.as_deref(), Some("10.0.0.0/8"));

    // A non-privileged key (no is_master, no can_manage_keys) must be forbidden from creating keys.
    let (_plain_id, plain_key) = insert_key(&db, "Plain", false, false, false, false).await;
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/keys")
        .header("X-API-Key", &plain_key)
        .header("Content-Type", "application/json")), json!({ "name": "Should Not Exist" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// Covers: a key with zero global rights, scoped only via `ApiKeyGroupPermission`, is correctly
/// gated by `can_read`/`can_write` independently, and a live permission upgrade takes effect
/// immediately on the next request (no caching/staleness).
#[tokio::test]
async fn test_group_permission_assignment_boundaries() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_b_id, key_b) = insert_key(&db, "Key_B", false, false, false, false).await;

    // Master grants Key_B read-only rights on "Group_X" (auto-provisions the group).
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_b_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "Group_X",
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Master seeds an address into Group_X so there is something for Key_B to read.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.1", "group_name": "Group_X" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Key_B can read Group_X.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=Group_X")
        .header("X-API-Key", &key_b)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["target_address"], "203.0.113.1");

    // Key_B cannot write to Group_X yet.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.2", "group_name": "Group_X" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    // Master upgrades Key_B to can_write = true.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_b_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "Group_X",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Key_B can now write to Group_X.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.2", "group_name": "Group_X" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// Covers: deleting an API key immediately invalidates it (`401` on next use, not just "no longer
/// listed"), and the FK `ON DELETE CASCADE` on `api_key_group_permissions.api_key_id` leaves no
/// orphaned permission rows behind.
#[tokio::test]
async fn test_key_deletion_revokes_access_and_cascades_permissions() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_b_id, key_b) = insert_key(&db, "Key_B", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_b_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "Group_X",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Sanity check: Key_B actually works before deletion.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_b)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let perms_before = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(key_b_id))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(perms_before.len(), 1);

    // Master deletes Key_B.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{key_b_id}"))
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Immediately, any request using Key_B's header must be rejected as unauthorized.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_b)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=Group_X")
        .header("X-API-Key", &key_b)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // No orphaned api_key_group_permissions rows survive the deleted key.
    let perms_after = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(key_b_id))
        .all(&db)
        .await
        .unwrap();
    assert!(perms_after.is_empty());
}

// ─────────────────────────────────────────────────────────────
// Concurrency, reverse-proxy security, and CIDR boundary tests
// ─────────────────────────────────────────────────────────────

async fn insert_key_with_bound_ips(db: &DatabaseConnection, name: &str, bound_ips: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(hash),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        name: Set(name.to_owned()),
        bound_ips: Set(Some(bound_ips.to_owned())),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    (id, plaintext)
}

/// Fail2ban-style simulation: 10 concurrent tasks re-ban the exact same address into the exact
/// same group at once. SeaORM's SQLite driver forces a single-connection pool by default (there is
/// no `cache=shared` in play here — without that forced serialization, concurrent connections to
/// `sqlite::memory:` would each see their own empty database), so this also doubles as a
/// concurrency-level regression test for the `exec_without_returning` fix: under real contention,
/// several of these requests *will* hit the `ON CONFLICT DO NOTHING` branch for the membership
/// insert at the same moment.
#[tokio::test]
async fn test_concurrent_burst_ban_requests() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let mut handles = Vec::with_capacity(10);
    for _ in 0..10 {
        let app = app.clone();
        let master_key = master_key.clone();
        handles.push(tokio::spawn(async move {
            let req = signed(inject_connect_info(Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &master_key)
                .header("Content-Type", "application/json")), json!({
                    "target_address": "44.44.44.44",
                    "group_name": "burst-group",
                    "cause": "fail2ban burst"
                }).to_string());
            app.oneshot(req).await.unwrap().status()
        }));
    }

    let mut ok_count = 0;
    for handle in handles {
        // A per-task timeout turns a hang/deadlock into a clear test failure instead of an
        // indefinitely stuck `cargo test` run.
        let status = tokio::time::timeout(std::time::Duration::from_secs(10), handle)
            .await
            .expect("task did not complete in time (possible deadlock)")
            .unwrap();
        if status == StatusCode::OK {
            ok_count += 1;
        }
    }
    assert_eq!(ok_count, 10, "all 10 concurrent re-bans of the same address/group must return 200 OK");

    // Exactly one record must exist in exactly one membership row — no duplicates, no partial
    // failures, despite 10 simultaneous writers targeting the same (address, group) pair.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=burst-group")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["target_address"], "44.44.44.44");

    // last_seen_at must reflect one of the concurrent requests, not be stale/missing.
    let last_seen: chrono::NaiveDateTime = serde_json::from_value(items[0]["last_seen_at"].clone()).unwrap();
    let age = chrono::Utc::now().naive_utc() - last_seen;
    assert!(age < chrono::Duration::seconds(30), "last_seen_at should have just been updated, age was {age}");
}

/// Security regression test: a forged `X-Forwarded-For` prefix must not bypass `bound_ips`. Only
/// the rightmost hop (the one *your own* reverse proxy appended) is trustworthy — anything to its
/// left is attacker-supplied and must be ignored, per AGENT.MD's "Resilient IP Extraction" rule.
#[tokio::test]
async fn test_reverse_proxy_xff_extracts_rightmost_trusted_hop() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    const FORGED_CLAIM: &str = "8.8.8.8";
    const TRUSTED_HOP: &str = "10.0.0.1";
    let xff_header = format!("{FORGED_CLAIM}, {TRUSTED_HOP}");

    // A key bound to the rightmost (trusted-proxy-appended) address must be let through.
    let (_id, key_trusted) = insert_key_with_bound_ips(&db, "trusted-hop", "10.0.0.1/32").await;
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_trusted)
        .header("X-Forwarded-For", &xff_header)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // A key bound to the leftmost, client-forgeable claim must NOT be let through: if it were,
    // any client could bypass CIDR restriction just by prepending an allowed address to the
    // header.
    let (_id2, key_forged) = insert_key_with_bound_ips(&db, "forged-claim", "8.8.8.8/32").await;
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_forged)
        .header("X-Forwarded-For", &xff_header)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

/// `POST /api/ban` must reject malformed CIDRs with `400` and accept valid IPv6 CIDRs cleanly.
#[tokio::test]
async fn test_cidr_and_ipv6_boundary_validation() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let ban = |addr: &str| {
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "target_address": addr, "group_name": "cidr-boundary-group" }).to_string())
    };

    // Octet out of range (> 255).
    let res = app.clone().oneshot(ban("256.0.0.1/32")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Prefix length out of range for an IPv4 address (max is /32).
    let res = app.clone().oneshot(ban("10.0.0.1/35")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Free-form garbage.
    let res = app.clone().oneshot(ban("definitely-not-an-ip")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // A valid, non-private IPv6 CIDR must parse and be accepted.
    let res = app.clone().oneshot(ban("2001:db8::/32")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// `normalize_ip_or_cidr` must strip a single-host CIDR suffix (`/32` for IPv4, `/128` for IPv6)
/// down to the plain address, leave genuine subnets — including their original, possibly
/// non-network-aligned host bits — untouched, and pass unparseable input through unchanged rather
/// than erroring: it's a normalization helper, not a validator.
#[tokio::test]
async fn test_normalize_ip_or_cidr_strips_single_host_prefixes_only() {
    use simply_ip_vault::api::normalize_ip_or_cidr;

    assert_eq!(normalize_ip_or_cidr("188.190.74.128/32"), "188.190.74.128");
    assert_eq!(normalize_ip_or_cidr("188.190.74.128"), "188.190.74.128");
    assert_eq!(normalize_ip_or_cidr("::1/128"), "::1");
    assert_eq!(normalize_ip_or_cidr("2001:db8::1"), "2001:db8::1");

    // Genuine subnets keep their CIDR notation, including non-network-aligned host bits (not
    // masked down to the network address).
    assert_eq!(normalize_ip_or_cidr("10.0.0.0/24"), "10.0.0.0/24");
    assert_eq!(normalize_ip_or_cidr("188.190.74.130/24"), "188.190.74.130/24");
    assert_eq!(normalize_ip_or_cidr("2001:db8::/64"), "2001:db8::/64");

    // Unparseable input (garbage, or a genuine partial substring fragment as used by the
    // /api/ips filter) passes through unchanged rather than being rejected.
    assert_eq!(normalize_ip_or_cidr("not-an-ip"), "not-an-ip");
    assert_eq!(normalize_ip_or_cidr("74.128"), "74.128");
}

/// End-to-end proof that canonicalization actually prevents the duplicate-storage bug it exists
/// to fix: banning the same address once as "X/32" and once as bare "X" must produce exactly one
/// stored record (not two), in canonical (bare) form — and DELETE must find and remove a record
/// regardless of which representation it was originally created with vs. looked up by.
#[tokio::test]
async fn test_ban_deduplicates_slash_32_and_bare_ip_representations() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    // Ban the /32 form first.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "188.190.74.128/32", "group_name": "canon-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Ban the bare form of the SAME address — must update the same row, not create a second one.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "188.190.74.128", "group_name": "canon-group", "cause": "re-banned bare" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=canon-group")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1, "the /32 and bare forms must be treated as the SAME address, not two records");
    assert_eq!(items[0]["target_address"], "188.190.74.128", "stored in canonical (bare) form");
    assert_eq!(items[0]["cause"], "re-banned bare", "the second call updated the same row");

    // Deleting via the bare form must find and remove the record, even though nothing was ever
    // literally stored or requested with that exact string until now — canonicalization, not
    // string luck, is what makes this work.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips?target_address=188.190.74.128&group_name=canon-group")
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // And deleting via the /32 form of an address that was actually stored bare must ALSO work.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.77", "group_name": "canon-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips?target_address=203.0.113.77/32&group_name=canon-group")
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);
}

/// Proves webhook dispatch is genuinely non-blocking: `POST /api/ban` must return almost
/// immediately even when the only registered webhook for that group targets an endpoint that
/// takes several seconds to respond. The handler only ever hands the event off over an mpsc
/// channel (`state.webhook_tx.send(event).await`, capacity 100, effectively never full here) — the
/// slow HTTP dispatch itself happens later, in the separate `run_webhook_worker` background task.
#[tokio::test]
async fn test_webhook_dispatch_does_not_block_api_response() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;

    let slow_app = axum::Router::new().route(
        "/slow-hook",
        axum::routing::post(|| async {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            StatusCode::OK
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = listener.local_addr().unwrap();
    let _slow_server = tokio::spawn(async move {
        axum::serve(listener, slow_app).await.unwrap();
    });

    // The slow mock above lives on loopback, which SSRF protection blocks unless explicitly
    // allowed; opt in so the dispatch genuinely reaches (and hangs on) the slow endpoint rather
    // than being short-circuited immediately.
    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true");
    }

    let db = setup_test_db().await;
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::channel(100);
    let db_for_worker = db.clone();
    let _worker_handle = tokio::spawn(async move {
        simply_ip_vault::webhooks::run_webhook_worker(db_for_worker, webhook_rx).await;
    });

    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("slow-hook-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "name": "Slow Hook",
            "target_url": format!("http://{slow_addr}/slow-hook"),
            "secret_token": "s",
            "payload_template": "{}",
            "group_id": group_id.to_string(),
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let start = std::time::Instant::now();
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "66.66.66.66", "group_name": "slow-hook-group" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    let elapsed = start.elapsed();

    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false");
    }

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        elapsed < std::time::Duration::from_millis(50),
        "expected POST /api/ban to return in under 50ms regardless of webhook speed, took {elapsed:?}"
    );
}

// ─────────────────────────────────────────────────────────────
// Unified group identification, flexible DELETE, key rotation/update,
// permission revocation, and audit log querying
// ─────────────────────────────────────────────────────────────

/// `DELETE /api/ips` must accept `target_address`/`group_name` from the URL query string (the
/// original, documented shape) as well as from a JSON request body (previously a guaranteed
/// deserialization failure, since `Query<DeleteIpQuery>` only ever looked at the URL).
#[tokio::test]
async fn test_delete_ip_accepts_query_or_json_body() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    for addr in ["55.55.55.1", "55.55.55.2"] {
        let req = signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "target_address": addr, "group_name": "delete-shape-group" }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    // Delete via URL query string.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips?target_address=55.55.55.1&group_name=delete-shape-group")
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Delete via JSON body instead — previously this failed before the handler even ran.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "55.55.55.2", "group_name": "delete-shape-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=delete-shape-group")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(items.is_empty(), "both records should be gone: {items:?}");
}

/// A group granted/looked-up by `group_id` and one looked up by `group_name` must be the same
/// group and behave identically. Also covers the required-exactly-one-of validation and that an
/// unknown `group_id` 404s rather than silently auto-creating (unlike an unknown `group_name`).
#[tokio::test]
async fn test_group_identification_by_id_and_name_are_interchangeable() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_c_id, key_c) = insert_key(&db, "Key_C", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.1", "group_name": "interop-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let group_id = simply_ip_vault::entities::ip_group::Entity::find()
        .filter(simply_ip_vault::entities::ip_group::Column::Name.eq("interop-group"))
        .one(&db).await.unwrap().unwrap().id;

    // Grant Key_C rights on the group BY ID.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_c_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "group_id": group_id, "can_read": true, "can_write": true, "can_delete": false }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Key_C bans an address identifying the group BY NAME...
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.2", "group_name": "interop-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // ...and another identifying it BY ID.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.3", "group_id": group_id }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Supplying both is rejected.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.4", "group_id": group_id, "group_name": "interop-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    // Supplying neither is rejected.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.5" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    // An unknown group_id is 404 — unlike group_name, an ID is never auto-creatable.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.6", "group_id": Uuid::new_v4() }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND);
}

/// `POST /api/keys/{id}/rotate` must generate a new secret and immediately invalidate the old one.
#[tokio::test]
async fn test_key_rotation_invalidates_old_secret() {
    // Serialized against the VAULT_ENCRYPTION_KEY test: this key's secret is sealed (or not)
    // according to the variable's value at creation time. See ENV_MUTATION_LOCK.
    let _guard = ENV_MUTATION_LOCK.lock().await;
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (rotate_id, old_secret) = insert_key(&db, "Rotate_Me", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &old_secret)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{rotate_id}/rotate"))
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_secret = parsed["plaintext_key"].as_str().unwrap().to_owned();
    assert_ne!(new_secret, old_secret);
    // Rotation mints a fresh signing secret alongside the key; it is returned exactly once, here.
    // From now on this key must be signed with `signed_with`, since its secret is server-generated
    // rather than following the seeded-key convention.
    let new_signing_secret = parsed["signing_secret"].as_str().unwrap().to_owned();
    assert_ne!(new_signing_secret, test_signing_secret(&old_secret));

    // Old secret immediately stops working.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &old_secret)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // The old *signing* secret is invalidated too: presenting the new key with the pre-rotation
    // secret must fail, or rotation would leave a working credential behind after a compromise.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &new_secret)), &test_signing_secret(&old_secret), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // New secret works.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &new_secret)), &new_signing_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // A non-privileged key cannot rotate someone else's key.
    let (other_id, _) = insert_key(&db, "Other", false, false, false, false).await;
    let req = signed_with(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{other_id}/rotate"))
        .header("X-API-Key", &new_secret)), &new_signing_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

/// `PUT /api/keys/{id}` updates name/bound_ips/global scopes in place, and the change is visible
/// on the next request using that key (permission enforcement isn't cached).
#[tokio::test]
async fn test_update_api_key_changes_take_effect_immediately() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (target_id, target_key) = insert_key(&db, "Before", false, false, false, false).await;

    // Not yet allowed to manage webhooks.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/webhooks")
        .header("X-API-Key", &target_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    let req = signed(inject_connect_info(Request::builder()
        .method("PUT")
        .uri(format!("/api/keys/{target_id}"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "name": "After",
            "bound_ips": "0.0.0.0/0",
            "can_manage_webhooks": true
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let updated: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(updated["name"], "After");
    assert_eq!(updated["bound_ips"], "0.0.0.0/0");
    assert_eq!(updated["can_manage_webhooks"], true);

    // Now allowed, immediately, with the same (unrotated) secret.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/webhooks")
        .header("X-API-Key", &target_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// `DELETE /api/keys/{id}/permissions/{group_identifier}` removes exactly the targeted grant,
/// accepts either a group name or a group ID as the identifier, and 404s on a second attempt.
#[tokio::test]
async fn test_revoke_group_permission_by_name_and_by_id() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_id, key_plain) = insert_key(&db, "Key_D", false, false, false, false).await;

    for group_name in ["revoke-by-name-group", "revoke-by-id-group"] {
        let req = signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri(format!("/api/keys/{key_id}/permissions"))
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "group_name": group_name, "can_read": true, "can_write": true, "can_delete": true }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    let group_id_2 = simply_ip_vault::entities::ip_group::Entity::find()
        .filter(simply_ip_vault::entities::ip_group::Column::Name.eq("revoke-by-id-group"))
        .one(&db).await.unwrap().unwrap().id;

    // Revoke the first by name.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/keys/".to_owned() + &key_id.to_string() + "/permissions/revoke-by-name-group")
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Revoke the second by ID.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{key_id}/permissions/{group_id_2}"))
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Revoking again is 404 — the grant is already gone.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/keys/".to_owned() + &key_id.to_string() + "/permissions/revoke-by-name-group")
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND);

    // The key can no longer read either group.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=revoke-by-name-group,revoke-by-id-group")
        .header("X-API-Key", &key_plain)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(items.is_empty());
}

/// `GET /api/audit-logs` is master-only and returns populated entries after mutations, filterable
/// by action.
#[tokio::test]
async fn test_audit_log_query_returns_entries_after_mutations() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (_sub_id, sub_key) = insert_key(&db, "Sub", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "88.1.1.1", "group_name": "audit-check-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Non-master keys cannot view audit logs, even with other broad global scopes.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/audit-logs")
        .header("X-API-Key", &sub_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/audit-logs?action=IP_ADD")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["action"], "IP_ADD");
    assert_eq!(items[0]["target_address"], "88.1.1.1");
    assert_eq!(items[0]["group_names"], "audit-check-group");
}

// ─────────────────────────────────────────────────────────────
// Regression tests: duplicate group creation, flexible group_id,
// and the write/delete-requires-read invariant
// ─────────────────────────────────────────────────────────────

/// `POST /api/groups` must not `500` on a duplicate name — the raw `UNIQUE constraint failed`
/// `DbErr` should be caught and turned into a clean `409 Conflict`.
#[tokio::test]
async fn test_create_duplicate_group_returns_conflict_not_500() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let make_req = || {
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/groups")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "name": "duplicate-group-test" }).to_string())
    };

    let res = app.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "duplicate group name must be 409, not 500");

    // Only one row actually exists — the failed second attempt didn't leave anything behind.
    let count = simply_ip_vault::entities::ip_group::Entity::find()
        .filter(simply_ip_vault::entities::ip_group::Column::Name.eq("duplicate-group-test"))
        .all(&db)
        .await
        .unwrap()
        .len();
    assert_eq!(count, 1);
}

/// `POST /api/keys/{id}/groups` (and its `/permissions` alias) must accept a group's UUID *or*
/// its literal name in the `group_id` field — previously `group_id` was strictly typed as `Uuid`,
/// so a name-shaped string there failed Axum's deserialization with `422` before the handler ran.
#[tokio::test]
async fn test_group_permission_assignment_accepts_uuid_or_name_in_group_id_field() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_e_id, _key_e) = insert_key(&db, "Key_E", false, false, false, false).await;
    let (key_f_id, _key_f) = insert_key(&db, "Key_F", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/groups")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "name": "flex-id-group" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let group_uuid = created["id"].as_str().unwrap().to_owned();

    // A NAME string in the group_id field — previously a guaranteed 422.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_e_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_id": "flex-id-group",
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // An actual UUID string in the group_id field, via the /permissions alias.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_f_id}/permissions"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_id": group_uuid,
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Both grants landed on the exact same group.
    let perms = simply_ip_vault::entities::api_key_group_permission::Entity::find().all(&db).await.unwrap();
    let group_ids: std::collections::HashSet<String> = perms.iter().map(|p| p.group_id.to_string()).collect();
    assert_eq!(group_ids.len(), 1);
    assert_eq!(group_ids.into_iter().next().unwrap(), group_uuid);
}

/// `can_write`/`can_delete` without `can_read` violates AGENT.MD's least-privilege rule and must
/// be rejected with `400`, not silently persisted as a nonsensical grant.
#[tokio::test]
async fn test_group_permission_write_or_delete_requires_read() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_id, _key_plain) = insert_key(&db, "Key_G", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "no-read-group",
            "can_read": false,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "no-read-group",
            "can_read": false,
            "can_write": false,
            "can_delete": true
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    // can_read alone, or read+write together, are both fine.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "no-read-group",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

// ─────────────────────────────────────────────────────────────
// Conflict detection, group_name assignment, audit log pagination,
// and a dedicated strict bound-IP rejection scenario
// ─────────────────────────────────────────────────────────────

/// The same address can legitimately belong to a `banlist` group and a `whitelist` group at
/// once; `GET /api/ips` must expose both memberships as separate rows (one per group), each
/// carrying its own `group_type`, so the dashboard's client-side conflict indicator
/// (`findConflictingAddresses` in `static/app.js`) has the data it needs to flag it. A response
/// that deduplicated/merged the two memberships into one row would silently break that feature.
#[tokio::test]
async fn test_multi_group_overlap_exposes_both_memberships_for_conflict_detection() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "target_address": "192.0.2.200",
            "group_name": "conflict-banlist",
            "cause": "flagged as hostile"
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/white")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "target_address": "192.0.2.200",
            "group_name": "conflict-whitelist",
            "cause": "also a trusted partner"
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?ip=192.0.2.200")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

    assert_eq!(items.len(), 2, "both memberships must be exposed as separate rows: {items:?}");
    assert!(items.iter().all(|i| i["target_address"] == "192.0.2.200"));
    let mut group_types: Vec<&str> = items.iter().map(|i| i["group_type"].as_str().unwrap()).collect();
    group_types.sort_unstable();
    assert_eq!(group_types, vec!["banlist", "whitelist"]);
}

/// Assigning group rights via a literal `group_name` (e.g. a realistic fail2ban jail name) must
/// work exactly as well as via `group_id`, including when both are used to grant different keys
/// access to the very same group in the same test.
#[tokio::test]
async fn test_group_permission_assignment_via_group_name_alongside_uuid() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (name_key_id, name_key) = insert_key(&db, "fail2ban-nginx-name-grant", false, false, false, false).await;
    let (uuid_key_id, uuid_key) = insert_key(&db, "fail2ban-nginx-uuid-grant", false, false, false, false).await;

    // Seed the group into existence via a normal ban, using a realistic fail2ban-style name.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "target_address": "198.51.100.77",
            "group_name": "fail2ban_nginx",
            "cause": "nginx probing"
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/groups")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let groups: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    let group_id = groups.iter().find(|g| g["name"] == "fail2ban_nginx").unwrap()["id"].as_str().unwrap().to_owned();

    // Grant via the literal group_name field.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{name_key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "fail2ban_nginx",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Grant a DIFFERENT key on the SAME group via its UUID, seamlessly alongside the name grant.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{uuid_key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_id": group_id,
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Both keys can now read the group, and both grants reference the identical group id.
    for key in [&name_key, &uuid_key] {
        let req = signed(inject_connect_info(Request::builder()
            .uri("/api/ips?group_name=fail2ban_nginx")
            .header("X-API-Key", key)), "");
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(items.len(), 1);
    }

    let perms = simply_ip_vault::entities::api_key_group_permission::Entity::find().all(&db).await.unwrap();
    let group_ids: std::collections::HashSet<String> = perms.iter().map(|p| p.group_id.to_string()).collect();
    assert_eq!(group_ids.len(), 1, "the name-grant and the uuid-grant must reference the same group");
    assert_eq!(group_ids.into_iter().next().unwrap(), group_id);
}

/// `GET /api/audit-logs` pagination (`limit`/`offset`) must actually advance the window: two
/// consecutive pages of the same filtered query must return disjoint sets of entries.
#[tokio::test]
async fn test_audit_log_pagination() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    // Six distinct GROUP_CREATE audit entries, so two limit=3 pages fully partition them.
    for i in 0..6 {
        let req = signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/groups")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "name": format!("pagination-group-{i}") }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    let fetch_page = |offset: u64| {
        let app = app.clone();
        let master_key = master_key.clone();
        async move {
            let req = signed(inject_connect_info(Request::builder()
                .uri(format!("/api/audit-logs?action=GROUP_CREATE&limit=3&offset={offset}"))
                .header("X-API-Key", &master_key)), "");
            let res = app.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            serde_json::from_slice::<Vec<serde_json::Value>>(&body).unwrap()
        }
    };

    let page1 = fetch_page(0).await;
    let page2 = fetch_page(3).await;

    assert_eq!(page1.len(), 3, "page 1 (offset=0) must have exactly `limit` entries: {page1:?}");
    assert_eq!(page2.len(), 3, "page 2 (offset=3) must have exactly `limit` entries: {page2:?}");

    let page1_ids: std::collections::HashSet<&str> = page1.iter().map(|e| e["id"].as_str().unwrap()).collect();
    let page2_ids: std::collections::HashSet<&str> = page2.iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert!(page1_ids.is_disjoint(&page2_ids), "page 1 and page 2 must not overlap: {page1_ids:?} vs {page2_ids:?}");
    assert_eq!(page1_ids.union(&page2_ids).count(), 6, "together the two pages cover all 6 entries exactly once");
}

/// Dedicated strict scenario: a key bound to `127.0.0.1/32` must be rejected — with exactly the
/// `403 Client IP not allowed` the middleware documents — when the (proxy-supplied) client
/// address is `203.0.113.50`, nowhere near the bound range.
#[tokio::test]
async fn test_bound_ip_strictly_rejects_out_of_cidr_forwarded_address() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_id, restricted_key) = insert_key_with_bound_ips(&db, "loopback-only", "127.0.0.1/32").await;

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &restricted_key)
        .header("X-Forwarded-For", "203.0.113.50")), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"], "Client IP not allowed");

    // Sanity check: the same key from the bound address itself is let through.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &restricted_key)
        .header("X-Forwarded-For", "127.0.0.1")), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// `GET /api/ips?format=iplist` (and its `mode=iplist` synonym) returns `{"ip_list": [...]}` —
/// just the addresses, de-duplicated, not full records. The same address banned into two
/// different groups must appear exactly once in the list, even though it matches two separate
/// `ip_record_group_membership` rows.
#[tokio::test]
async fn test_list_ips_iplist_format_returns_deduplicated_address_list() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let ban = |addr: &'static str, group: &'static str| {
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "target_address": addr, "group_name": group }).to_string())
    };

    assert_eq!(app.clone().oneshot(ban("198.51.100.1", "iplist-group-a")).await.unwrap().status(), StatusCode::OK);
    assert_eq!(app.clone().oneshot(ban("198.51.100.2", "iplist-group-a")).await.unwrap().status(), StatusCode::OK);
    // Same address as the first, but in a SECOND group — must still only appear once in ip_list.
    assert_eq!(app.clone().oneshot(ban("198.51.100.1", "iplist-group-b")).await.unwrap().status(), StatusCode::OK);

    for query in ["format=iplist", "mode=iplist"] {
        let req = signed(inject_connect_info(Request::builder()
            .uri(format!("/api/ips?groups=iplist-group-a,iplist-group-b&{query}"))
            .header("X-API-Key", &master_key)), "");
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "query string was `{query}`");
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ip_list = parsed["ip_list"].as_array().expect("ip_list must be an array");
        let addresses: Vec<&str> = ip_list.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(addresses.len(), 2, "query string was `{query}`: expected exactly 2 unique addresses, got {addresses:?}");
        assert!(addresses.contains(&"198.51.100.1"));
        assert!(addresses.contains(&"198.51.100.2"));
        // No other fields (id, cause, group_name, ...) leak into the lightweight response.
        assert!(parsed.get("id").is_none() && parsed.as_object().unwrap().len() == 1);
    }
}

/// `GET /api/ips` must order results by `updated_at DESC` — the most recently added or
/// re-registered record always sorts first, regardless of insertion order.
#[tokio::test]
async fn test_list_ips_orders_by_updated_at_descending() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let ban = |addr: &'static str| {
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "target_address": addr, "group_name": "ordering-group" }).to_string())
    };

    // Created in order A, B, C — freshly created, so C (most recent) should sort first.
    for addr in ["203.0.113.101", "203.0.113.102", "203.0.113.103"] {
        assert_eq!(app.clone().oneshot(ban(addr)).await.unwrap().status(), StatusCode::OK);
    }

    let list = |app: &axum::Router, master_key: &str| {
        let app = app.clone();
        let master_key = master_key.to_owned();
        async move {
            let req = signed(inject_connect_info(Request::builder()
                .uri("/api/ips?groups=ordering-group")
                .header("X-API-Key", &master_key)), "");
            let res = app.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
            items.into_iter().map(|i| i["target_address"].as_str().unwrap().to_owned()).collect::<Vec<_>>()
        }
    };

    let addresses = list(&app, &master_key).await;
    assert_eq!(addresses, vec!["203.0.113.103", "203.0.113.102", "203.0.113.101"], "most recently created sorts first");

    // Re-register the OLDEST one (.101) — it must now jump to the front, since its updated_at is
    // now the most recent of the three.
    assert_eq!(app.clone().oneshot(ban("203.0.113.101")).await.unwrap().status(), StatusCode::OK);

    let addresses = list(&app, &master_key).await;
    assert_eq!(addresses, vec!["203.0.113.101", "203.0.113.103", "203.0.113.102"], "re-registered record jumps to the front");
}

// ─────────────────────────────────────────────────────────────
// HMAC-SHA256 authentication & anti-replay guard
// ─────────────────────────────────────────────────────────────

/// Every one of the three auth headers is individually mandatory: dropping any single one must
/// produce `401`, so no combination of two can ever authenticate a request on its own.
#[tokio::test]
async fn test_each_auth_header_is_individually_required() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_id, key) = insert_key(&db, "Signer", true, true, true, true).await;
    let secret = test_signing_secret(&key);

    // Control: all three headers present and correct.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let now = chrono::Utc::now().timestamp().to_string();
    let signature = simply_ip_vault::crypto::compute_signature(
        &secret, "GET", "/api/auth/me", &now, b"",
    ).unwrap();

    // Missing X-API-Key (timestamp + signature present).
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-Timestamp", &now)
        .header("X-Signature-256", &signature))
        .body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // Missing X-Timestamp (key + signature present).
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key)
        .header("X-Signature-256", &signature))
        .body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // Missing X-Signature-256 (key + timestamp present) — i.e. exactly the pre-HMAC request shape,
    // which must no longer be sufficient.
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key)
        .header("X-Timestamp", &now))
        .body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // A malformed (non-numeric) timestamp is rejected rather than treated as 0 or as "now".
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key)
        .header("X-Timestamp", "not-a-number")
        .header("X-Signature-256", &signature))
        .body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

/// The anti-replay window is +/- 300 seconds and symmetric: a captured request replayed later is
/// rejected, and so is one timestamped in the future (which is what a replay attacker would forge
/// to extend a captured request's usable lifetime).
#[tokio::test]
async fn test_anti_replay_timestamp_window_is_enforced_in_both_directions() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_id, key) = insert_key(&db, "Replay", true, true, true, true).await;
    let secret = test_signing_secret(&key);
    let now = chrono::Utc::now().timestamp();

    let call = |offset: i64| {
        let app = app.clone();
        let key = key.clone();
        let secret = secret.clone();
        async move {
            let req = signed_at(inject_connect_info(Request::builder()
                .uri("/api/auth/me")
                .header("X-API-Key", &key)), &secret, now + offset, "");
            app.oneshot(req).await.unwrap().status()
        }
    };

    // Comfortably inside the window, in both directions, is accepted.
    assert_eq!(call(0).await, StatusCode::OK);
    assert_eq!(call(-290).await, StatusCode::OK, "290s stale is within the 300s window");
    assert_eq!(call(290).await, StatusCode::OK, "290s ahead is within the 300s window");

    // Outside it, in both directions, is rejected — with a correct signature, proving the
    // rejection comes from the freshness check and not from the HMAC.
    assert_eq!(call(-301).await, StatusCode::UNAUTHORIZED, "stale request is a replay");
    assert_eq!(call(301).await, StatusCode::UNAUTHORIZED, "future-dated request is rejected");
    assert_eq!(call(-86_400).await, StatusCode::UNAUTHORIZED, "day-old capture is rejected");
}

/// The signature must genuinely bind method, path and body — not merely prove key possession.
/// Each case below replays an *authentic* signature against a different request.
#[tokio::test]
async fn test_signature_binds_method_path_and_body() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_id, key) = insert_key(&db, "Binder", true, true, true, true).await;
    let secret = test_signing_secret(&key);
    let now = chrono::Utc::now().timestamp().to_string();

    let body = json!({ "target_address": "51.51.51.51", "group_name": "sig-bind-group" }).to_string();
    let authentic = simply_ip_vault::crypto::compute_signature(
        &secret, "POST", "/api/ban", &now, body.as_bytes(),
    ).unwrap();

    // Sanity: the authentic signature works for the exact request it was made for.
    let req = inject_connect_info(Request::builder()
        .method("POST").uri("/api/ban")
        .header("X-API-Key", &key)
        .header("Content-Type", "application/json")
        .header("X-Timestamp", &now)
        .header("X-Signature-256", &authentic))
        .body(Body::from(body.clone())).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Same signature, tampered body: an attacker swapping the target address is caught.
    let tampered = json!({ "target_address": "9.9.9.9", "group_name": "sig-bind-group" }).to_string();
    let req = inject_connect_info(Request::builder()
        .method("POST").uri("/api/ban")
        .header("X-API-Key", &key)
        .header("Content-Type", "application/json")
        .header("X-Timestamp", &now)
        .header("X-Signature-256", &authentic))
        .body(Body::from(tampered)).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // Same signature, different path: a POST /api/ban signature cannot be replayed onto
    // /api/white, which would flip a ban into a whitelist entry.
    let req = inject_connect_info(Request::builder()
        .method("POST").uri("/api/white")
        .header("X-API-Key", &key)
        .header("Content-Type", "application/json")
        .header("X-Timestamp", &now)
        .header("X-Signature-256", &authentic))
        .body(Body::from(body.clone())).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // Garbage and empty signatures fail closed rather than erroring out.
    for bogus in ["", "not-hex", "deadbeef"] {
        let req = inject_connect_info(Request::builder()
            .method("POST").uri("/api/ban")
            .header("X-API-Key", &key)
            .header("Content-Type", "application/json")
            .header("X-Timestamp", &now)
            .header("X-Signature-256", bogus))
            .body(Body::from(body.clone())).unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "bogus signature {bogus:?} must be rejected"
        );
    }
}

/// A key signed with the *wrong* key's secret must not authenticate, even though both keys exist
/// and both secrets are individually valid. Guards against the signature ever being verified
/// against something other than the looked-up key's own secret.
#[tokio::test]
async fn test_signature_must_match_the_looked_up_key() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_a_id, key_a) = insert_key(&db, "Key A", true, true, true, true).await;
    let (_b_id, key_b) = insert_key(&db, "Key B", true, true, true, true).await;

    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_a)), &test_signing_secret(&key_b), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

/// A key row predating the `signing_secret` column (NULL) cannot authenticate at all — it fails
/// closed rather than skipping signature verification.
#[tokio::test]
async fn test_key_without_signing_secret_cannot_authenticate() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let plaintext = simply_ip_vault::api::generate_random_key();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(None), // as left by the additive migration on a pre-existing row
        name: Set("Legacy Key".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &plaintext)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

/// End-to-end credential lifecycle: a key minted through `POST /api/keys` comes back with a
/// signing secret that actually works for signing subsequent requests.
#[tokio::test]
async fn test_created_key_returns_a_usable_signing_secret() {
    // Serialized against the VAULT_ENCRYPTION_KEY test: this key's secret is sealed (or not)
    // according to the variable's value at creation time. See ENV_MUTATION_LOCK.
    let _guard = ENV_MUTATION_LOCK.lock().await;
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST").uri("/api/keys")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")),
        json!({ "name": "minted", "bound_ips": "0.0.0.0/0" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_key = created["plaintext_key"].as_str().unwrap().to_owned();
    let new_signing_secret = created["signing_secret"].as_str().unwrap().to_owned();
    assert!(!new_signing_secret.is_empty(), "creation must return a signing secret");
    assert_ne!(new_signing_secret, new_key, "the two credentials must be independent values");

    // The returned secret authenticates...
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &new_key)), &new_signing_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // ...and nothing else does.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &new_key)), "guessed-secret", "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

/// The signing secret must never appear in any read endpoint's output — only in the one-shot
/// create/rotate responses. `GET /api/keys` and `GET /api/auth/me` are the two that expose key
/// metadata and are therefore the realistic leak paths.
#[tokio::test]
async fn test_signing_secret_is_never_exposed_by_read_endpoints() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_id, key) = insert_key(&db, "Master", true, true, true, true).await;
    let secret = test_signing_secret(&key);

    for path in ["/api/auth/me", "/api/keys"] {
        let req = signed(inject_connect_info(Request::builder()
            .uri(path)
            .header("X-API-Key", &key)), "");
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(!text.contains(&secret), "{path} leaked the signing secret");
        assert!(!text.contains("signing_secret"), "{path} exposed a signing_secret field");
    }
}

/// With `VAULT_ENCRYPTION_KEY` set, a key created through the API stores its signing secret
/// encrypted at rest, yet still authenticates — proving the seal/open round trip is wired into the
/// real request path, not just the crypto unit tests.
#[tokio::test]
async fn test_signing_secret_is_encrypted_at_rest_when_vault_key_is_set() {
    let _guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("VAULT_ENCRYPTION_KEY", "integration-test-passphrase") };

    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST").uri("/api/keys")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")),
        json!({ "name": "sealed", "bound_ips": "0.0.0.0/0" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_key = created["plaintext_key"].as_str().unwrap().to_owned();
    let new_signing_secret = created["signing_secret"].as_str().unwrap().to_owned();

    // What landed in the database is ciphertext, not the secret the caller was handed.
    let stored = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::KeyHash
            .eq(simply_ip_vault::api::hash_key(&new_key)))
        .one(&db).await.unwrap().unwrap()
        .signing_secret.unwrap();
    assert!(stored.starts_with("aesgcm256:"), "stored secret must be sealed, got {stored}");
    assert!(!stored.contains(&new_signing_secret), "plaintext secret must not survive in the DB");

    // And it still authenticates, so decryption happens transparently in the middleware.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &new_key)), &new_signing_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    unsafe { std::env::remove_var("VAULT_ENCRYPTION_KEY") };
}

// ─────────────────────────────────────────────────────────────
// Webhook signature modes (BODY_ONLY / CANONICAL_V1)
// ─────────────────────────────────────────────────────────────

/// What a mock webhook receiver captured from a single dispatch.
#[derive(Default, Clone)]
struct CapturedHook {
    body: Option<String>,
    signature: Option<String>,
    timestamp: Option<String>,
}

/// Spawns a loopback mock receiver on an ephemeral port, returning its base URL and the shared slot
/// it records into. Used by the signature-mode tests below in place of the ad-hoc receiver that the
/// older webhook tests each built inline.
async fn spawn_capturing_receiver() -> (String, std::sync::Arc<std::sync::Mutex<CapturedHook>>) {
    use std::sync::{Arc, Mutex};

    let captured: Arc<Mutex<CapturedHook>> = Arc::new(Mutex::new(CapturedHook::default()));
    let for_handler = captured.clone();

    let hook_app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
            let captured = for_handler.clone();
            async move {
                let header = |name: &str| {
                    headers.get(name).and_then(|h| h.to_str().ok()).map(|s| s.to_owned())
                };
                let mut c = captured.lock().unwrap();
                c.signature = header("X-Signature-256");
                c.timestamp = header("X-Timestamp");
                c.body = Some(body);
                StatusCode::OK
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, hook_app).await.unwrap();
    });

    (format!("http://{addr}"), captured)
}

/// Polls until the receiver records a dispatch, or gives up. Dispatch is asynchronous (channel →
/// background worker → spawned HTTP task), so there is nothing to await directly.
async fn await_dispatch(
    captured: &std::sync::Arc<std::sync::Mutex<CapturedHook>>,
) -> Option<CapturedHook> {
    for _ in 0..40 {
        {
            let c = captured.lock().unwrap();
            if c.body.is_some() {
                return Some(c.clone());
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    None
}

/// Boilerplate shared by the signature-mode tests: a master key, a group, and a running webhook
/// worker wired to the app.
async fn setup_webhook_fixture(
    group_name: &str,
) -> (axum::Router, DatabaseConnection, String, Uuid) {
    let db = setup_test_db().await;
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::channel(100);
    let db_for_worker = db.clone();
    tokio::spawn(async move {
        simply_ip_vault::webhooks::run_webhook_worker(db_for_worker, webhook_rx).await;
    });

    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_key_id, plaintext) = insert_key(&db, "Webhook Tester", true, true, true, true).await;

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set(group_name.to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    (app, db, plaintext, group_id)
}

/// A `CANONICAL_V1` webhook must send **both** `X-Signature-256` and `X-Timestamp`, with the
/// signature computed over `POST\n<path>\n<timestamp>\n<body>` — the exact construction the inbound
/// API middleware verifies, which is what makes vault-to-vault dispatch work.
#[tokio::test]
async fn test_canonical_v1_webhook_sends_timestamp_and_canonical_signature() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    let (base_url, captured) = spawn_capturing_receiver().await;
    let (app, _db, plaintext, group_id) = setup_webhook_fixture("canonical-hook-group").await;

    let secret = "canonical-webhook-secret";
    let hook_url = format!("{base_url}/hook");
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "Canonical Hook",
            "target_url": hook_url,
            "secret_token": secret,
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
            "signature_mode": "CANONICAL_V1",
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(created["signature_mode"], "CANONICAL_V1", "creation echoes the stored mode");

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")),
        json!({ "target_address": "5.5.5.5", "group_name": "canonical-hook-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let hit = await_dispatch(&captured).await.expect("webhook was not delivered within timeout");
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false") };

    let delivered_body = hit.body.expect("body");
    let signature = hit.signature.expect("CANONICAL_V1 dispatch must send X-Signature-256");
    let timestamp = hit.timestamp.expect("CANONICAL_V1 dispatch must send X-Timestamp");

    // The timestamp must be a plausible current epoch, not a placeholder — a receiver's anti-replay
    // window would reject anything else.
    let parsed: i64 = timestamp.parse().expect("X-Timestamp must be an integer epoch");
    let skew = (chrono::Utc::now().timestamp() - parsed).abs();
    assert!(skew < 300, "X-Timestamp should be current, was {skew}s off");

    // Bare hex, not the `sha256=` prefix BODY_ONLY uses — byte-identical to what the API produces.
    assert!(!signature.starts_with("sha256="), "CANONICAL_V1 sends bare hex, got {signature}");

    let expected = simply_ip_vault::crypto::compute_signature(
        secret, "POST", "/hook", &timestamp, delivered_body.as_bytes(),
    ).unwrap();
    assert_eq!(signature, expected, "signature must cover POST\\npath\\ntimestamp\\nbody");
    assert!(delivered_body.contains("5.5.5.5"));

    // The receiving end of the contract: the same bytes verify through the shared helper, which is
    // literally the function the inbound middleware calls.
    assert!(simply_ip_vault::crypto::verify_signature(
        secret, "POST", "/hook", &timestamp, delivered_body.as_bytes(), &signature,
    ));
}

/// Omitting `signature_mode` must keep the legacy behaviour exactly: body-only HMAC, `sha256=`
/// prefix, and **no** `X-Timestamp` header. Guards third-party receivers against a silent change.
#[tokio::test]
async fn test_body_only_is_the_default_and_sends_no_timestamp() {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let _env_guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    let (base_url, captured) = spawn_capturing_receiver().await;
    let (app, _db, plaintext, group_id) = setup_webhook_fixture("legacy-hook-group").await;

    let secret = "legacy-webhook-secret";
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "Legacy Hook",
            "target_url": format!("{base_url}/hook"),
            "secret_token": secret,
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
            // signature_mode deliberately omitted
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(created["signature_mode"], "BODY_ONLY", "omitted mode defaults to BODY_ONLY");

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")),
        json!({ "target_address": "6.6.6.6", "group_name": "legacy-hook-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let hit = await_dispatch(&captured).await.expect("webhook was not delivered within timeout");
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false") };

    let delivered_body = hit.body.expect("body");
    let signature = hit.signature.expect("missing X-Signature-256");
    assert!(hit.timestamp.is_none(), "BODY_ONLY must not send X-Timestamp");

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(delivered_body.as_bytes());
    assert_eq!(signature, format!("sha256={}", hex::encode(mac.finalize().into_bytes())));
}

/// `signature_mode` is validated at the API boundary rather than silently defaulted, and the stored
/// value is surfaced by `GET /api/webhooks` so the UI can display it.
#[tokio::test]
async fn test_signature_mode_is_validated_and_exposed_in_listings() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_key_id, plaintext) = insert_key(&db, "Master", true, true, true, true).await;

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("mode-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    let make = |mode: serde_json::Value, name: &str| {
        let mut payload = json!({
            "name": name,
            "target_url": "https://example.com/hook",
            "secret_token": "s3cret",
            "payload_template": "{}",
            "group_id": group_id.to_string(),
        });
        if !mode.is_null() {
            payload["signature_mode"] = mode;
        }
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/webhooks")
            .header("X-API-Key", &plaintext)
            .header("Content-Type", "application/json")), payload.to_string())
    };

    // A typo must be a 400, not a silent downgrade to BODY_ONLY: a caller who believes they enabled
    // canonical signing would otherwise ship a receiver that rejects every dispatch.
    let res = app.clone().oneshot(make(json!("CANONICAL_V2"), "typo")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = app.clone().oneshot(make(json!("nonsense"), "nonsense")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Casing is normalized rather than rejected — the value is an enum, not a password.
    let res = app.clone().oneshot(make(json!("canonical_v1"), "lowercase")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = app.clone().oneshot(make(json!("BODY_ONLY"), "explicit-legacy")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let mode_of = |name: &str| -> String {
        listed.as_array().unwrap().iter()
            .find(|w| w["name"] == name).unwrap()["signature_mode"]
            .as_str().unwrap().to_owned()
    };
    assert_eq!(mode_of("lowercase"), "CANONICAL_V1", "casing is normalized on the way in");
    assert_eq!(mode_of("explicit-legacy"), "BODY_ONLY");

    // The listing must still never leak the HMAC key itself.
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(!text.contains("s3cret"), "GET /api/webhooks leaked secret_token");
}

// ─────────────────────────────────────────────────────────────
// POST /api/keys/{id}/rotate-secret
// ─────────────────────────────────────────────────────────────

/// Rotating the signing secret invalidates the old one, activates the new one, and leaves the API
/// key itself — plus name, scopes and per-group grants — completely untouched.
#[tokio::test]
async fn test_rotate_secret_swaps_only_the_signing_secret() {
    // Serialized against the VAULT_ENCRYPTION_KEY test: whether the new secret is sealed is decided
    // by that variable at rotation time. See ENV_MUTATION_LOCK.
    let _guard = ENV_MUTATION_LOCK.lock().await;

    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (target_id, target_key) = insert_key(&db, "Worker Bot", false, false, true, true).await;

    // Give the target a per-group grant, so we can prove rotation doesn't disturb RBAC.
    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("rotate-secret-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();
    simply_ip_vault::entities::api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(target_id),
        group_id: Set(group_id),
        can_read: Set(true),
        can_write: Set(true),
        can_delete: Set(true),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    let old_secret = test_signing_secret(&target_key);

    // Baseline: the original secret works.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &target_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{target_id}/rotate-secret"))
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let rotated: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(rotated["id"], target_id.to_string(), "the key id is preserved");
    assert_eq!(rotated["name"], "Worker Bot", "the key name is preserved");
    let new_secret = rotated["signing_secret"].as_str().unwrap().to_owned();
    assert!(!new_secret.is_empty());
    assert_ne!(new_secret, old_secret, "a genuinely new secret is issued");
    // The response must not hand back a new API key — that is `/rotate`'s job, not this one's.
    assert!(rotated.get("plaintext_key").is_none(), "rotate-secret must not reissue the API key");

    // The old signing secret is dead...
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &target_key)), &old_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // ...and the new one works with the *same, unchanged* API key.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &target_key)), &new_secret, "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Identity and RBAC survived intact.
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let me: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(me["id"], target_id.to_string());
    assert_eq!(me["name"], "Worker Bot");
    assert_eq!(me["can_manage_webhooks"], true);
    assert_eq!(me["can_create_groups"], true);
    assert_eq!(me["is_master"], false);
    let perms = me["group_permissions"].as_array().unwrap();
    assert_eq!(perms.len(), 1, "the per-group grant is untouched");
    assert_eq!(perms[0]["group_name"], "rotate-secret-group");
    assert_eq!(perms[0]["can_write"], true);
    assert_eq!(perms[0]["can_delete"], true);
}

/// A key whose `signing_secret` is `NULL` (a row predating HMAC auth) is recoverable through
/// `rotate-secret` — the documented upgrade path — without reissuing its API key.
#[tokio::test]
async fn test_rotate_secret_recovers_a_key_with_no_signing_secret() {
    let _guard = ENV_MUTATION_LOCK.lock().await;

    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let legacy_id = Uuid::new_v4();
    let legacy_key = simply_ip_vault::api::generate_random_key();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(legacy_id),
        key_hash: Set(simply_ip_vault::api::hash_key(&legacy_key)),
        signing_secret: Set(None),
        name: Set("Legacy".to_owned()),
        bound_ips: Set(None),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    // Before: unusable.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &legacy_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{legacy_id}/rotate-secret"))
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let rotated: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_secret = rotated["signing_secret"].as_str().unwrap().to_owned();

    // After: the same API key now authenticates.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &legacy_key)), &new_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// `rotate-secret` is master/`can_manage_keys`-only, 404s for unknown keys, and writes an audit
/// entry naming the key it re-keyed.
#[tokio::test]
async fn test_rotate_secret_authorization_and_audit_trail() {
    let _guard = ENV_MUTATION_LOCK.lock().await;

    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (victim_id, _victim_key) = insert_key(&db, "Victim", false, false, false, false).await;
    let (_low_id, low_key) = insert_key(&db, "Lowly", false, false, false, false).await;

    // A key without can_manage_keys cannot re-key anyone — including itself.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{victim_id}/rotate-secret"))
        .header("X-API-Key", &low_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    // Unauthenticated is rejected before authorization.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{victim_id}/rotate-secret")))
        .body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // An unknown key id is a 404, not a silently-created key.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{}/rotate-secret", Uuid::new_v4()))
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND);

    // The successful path writes a readable audit entry.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{victim_id}/rotate-secret"))
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/audit-logs?action=KEY_SECRET_ROTATE&limit=1")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let logs: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entry = &logs.as_array().unwrap()[0];
    assert_eq!(entry["action"], "KEY_SECRET_ROTATE");
    let details = entry["details"].as_str().unwrap();
    assert!(details.contains("'Victim'"), "audit details should name the key, got {details}");
    // The secret itself must never reach the audit trail.
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(!text.contains("signing_secret"), "audit log leaked a signing secret field");
}
