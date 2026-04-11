use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection, EntityTrait};
use sea_orm_migration::MigratorTrait;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use simply_firewall::{create_app, migration, state::AppState};

async fn setup_test_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();
    db
}

fn inject_connect_info(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
}

#[tokio::test]
async fn test_auth_and_cidr_rejection() {
    let db = setup_test_db().await;
    let (webhook_tx, _) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_firewall::api::generate_random_key();
    let hash = simply_firewall::api::hash_key(&plaintext);

    simply_firewall::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        name: Set("Test Key".to_owned()),
        bound_ips: Set("192.168.1.1/32".to_owned()),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
    }
    .insert(&db)
    .await
    .unwrap();

    // 1. Missing Key -> 401
    let req = inject_connect_info(Request::builder().uri("/api/ips")).body(Body::empty()).unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid CIDR -> 403 (Client IP matches 127.0.0.1 from ConnectInfo, not 192.168.1.1)
    let req = inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &plaintext)).body(Body::empty()).unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // 3. Valid CIDR (simulated via X-Forwarded-For) -> 200
    let req = inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &plaintext).header("X-Forwarded-For", "192.168.1.1")).body(Body::empty()).unwrap();
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
    simply_firewall::entities::ip_group::ActiveModel {
        id: Set(group_a_id),
        name: Set("Group A".to_owned()),
    }.insert(&db).await.unwrap();

    let key_id = Uuid::new_v4();
    let plaintext = simply_firewall::api::generate_random_key();
    let hash = simply_firewall::api::hash_key(&plaintext);

    simply_firewall::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        name: Set("Tenant Key".to_owned()),
        bound_ips: Set("0.0.0.0/0".to_owned()),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
    }.insert(&db).await.unwrap();

    // Key has NO explicit junction mapping yet.
    
    // Attempt POST to Group A without permissions -> 403
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "8.8.8.8", "group_name": "Group A" }).to_string()))
        .unwrap();
    
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Assign M:N Read/Write permissions
    simply_firewall::entities::api_key_group_permission::ActiveModel {
        api_key_id: Set(key_id),
        group_id: Set(group_a_id),
        can_read: Set(true),
        can_write: Set(true),
        can_delete: Set(false),
    }.insert(&db).await.unwrap();

    // POST to Group A -> Should Work
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "8.8.8.8", "group_name": "Group A" }).to_string()))
        .unwrap();
    
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
    let plaintext = simply_firewall::api::generate_random_key();
    let hash = simply_firewall::api::hash_key(&plaintext);

    simply_firewall::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        name: Set("Creator Key".to_owned()),
        bound_ips: Set("0.0.0.0/0".to_owned()),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(true), // CAN CREATE GROUPS
    }.insert(&db).await.unwrap();

    // Post to an completely new group
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "4.4.4.4", "group_name": "Dynamic Group" }).to_string()))
        .unwrap();
    
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Verify it automatically gave us 'can_delete' in the M:N binding
    let perms = simply_firewall::entities::api_key_group_permission::Entity::find()
        .all(&db).await.unwrap();
    
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].api_key_id, key_id);
    assert_eq!(perms[0].can_read, true);
    assert_eq!(perms[0].can_write, true);
    assert_eq!(perms[0].can_delete, true);
}

#[tokio::test]
async fn test_explicit_key_group_manipulation() {
    let db = setup_test_db().await;
    let (webhook_tx, _) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let master_id = Uuid::new_v4();
    let master_plaintext = simply_firewall::api::generate_random_key();
    let master_hash = simply_firewall::api::hash_key(&master_plaintext);

    simply_firewall::entities::api_key::ActiveModel {
        id: Set(master_id),
        key_hash: Set(master_hash),
        name: Set("System Master".to_owned()),
        bound_ips: Set("0.0.0.0/0".to_owned()),
        is_master: Set(true), // CAN MANAGE KEYS
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
    }
    .insert(&db)
    .await
    .unwrap();

    let target_id = Uuid::new_v4();
    simply_firewall::entities::api_key::ActiveModel {
        id: Set(target_id),
        key_hash: Set(simply_firewall::api::hash_key("dummy")),
        name: Set("Target Sub-Key".to_owned()),
        bound_ips: Set("192.168.1.1/32".to_owned()),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
    }
    .insert(&db)
    .await
    .unwrap();

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(&format!("/api/keys/{}/groups", target_id))
        .header("X-API-Key", &master_plaintext)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "group_name": "Dynamic Access Hub",
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string()))
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let perms = simply_firewall::entities::api_key_group_permission::Entity::find()
        .all(&db)
        .await
        .unwrap();

    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].api_key_id, target_id);
    assert_eq!(perms[0].can_read, true);
    assert_eq!(perms[0].can_write, false);
}
