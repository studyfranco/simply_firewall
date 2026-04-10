use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection, EntityTrait, QueryFilter, ColumnTrait};
use sea_orm_migration::MigratorTrait;
use serde_json::json;
use tower::ServiceExt; 
use uuid::Uuid;

use simply_firewall::{
    create_app, setup_state, migration, entities::{ip_group, api_key, ip_record}
};

/// Helper to setup an in-memory database and the Axum app
async fn setup_test_app() -> (axum::Router, DatabaseConnection) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();

    let (state, _tx, _worker) = setup_state(db.clone());
    let app = create_app(state);

    (app, db)
}

/// Helper to hash keys like the API does
fn hash_key(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

async fn seed_master_key(db: &DatabaseConnection) -> String {
    let plaintext = "master_test_key".to_string();
    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(hash_key(&plaintext)),
        name: Set("Master Key".to_owned()),
        bound_ips: Set("0.0.0.0/0".to_owned()),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_view_ips: Set(true),
        can_add_ips: Set(true),
        can_edit_ips: Set(true),
        can_delete_ips: Set(true),
        group_id: Set(None),
    };
    model.insert(db).await.unwrap();
    plaintext
}

async fn seed_readonly_key(db: &DatabaseConnection) -> String {
    let plaintext = "readonly_test_key".to_string();
    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(hash_key(&plaintext)),
        name: Set("Readonly Key".to_owned()),
        bound_ips: Set("0.0.0.0/0".to_owned()),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_view_ips: Set(true),
        can_add_ips: Set(false),
        can_edit_ips: Set(false),
        can_delete_ips: Set(false),
        group_id: Set(None),
    };
    model.insert(db).await.unwrap();
    plaintext
}

async fn seed_scoped_key(db: &DatabaseConnection, group_id: Uuid) -> String {
    let plaintext = format!("scoped_test_key_{}", group_id);
    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(hash_key(&plaintext)),
        name: Set("Scoped Key".to_owned()),
        bound_ips: Set("0.0.0.0/0".to_owned()),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_view_ips: Set(true),
        can_add_ips: Set(true),
        can_edit_ips: Set(false),
        can_delete_ips: Set(false),
        group_id: Set(Some(group_id)),
    };
    model.insert(db).await.unwrap();
    plaintext
}

#[tokio::test]
async fn test_auth_and_cidr_rejection() {
    let (app, db) = setup_test_app().await;

    // 1. Missing Key -> 401
    let response = app.clone()
        .oneshot(Request::builder()
            .uri("/api/ips")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
            .body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid Key -> 401
    let response = app.clone()
        .oneshot(Request::builder().uri("/api/ips")
            .header("X-API-Key", "wrong")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
            .body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 3. CIDR Rejection
    let plaintext = "cidr_key".to_string();
    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(hash_key(&plaintext)),
        name: Set("CIDR Key".to_owned()),
        bound_ips: Set("127.0.0.1/32".to_owned()),
        is_master: Set(false),
        can_view_ips: Set(true),
        ..Default::default()
    };
    model.insert(&db).await.unwrap();

    let response = app.clone()
        .oneshot(Request::builder().uri("/api/ips")
            .header("X-API-Key", plaintext)
            .header("X-Forwarded-For", "8.8.8.8")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
            .body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_master_override() {
    let (app, db) = setup_test_app().await;
    let master_key = seed_master_key(&db).await;

    let response = app.clone()
        .oneshot(Request::builder()
            .method("POST")
            .uri("/api/keys")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
            .body(Body::from(json!({
                "name": "new_key",
                "bound_ips": "0.0.0.0/0",
                "is_master": false,
                "can_manage_keys": false,
                "can_manage_webhooks": false,
                "can_view_ips": false,
                "can_add_ips": false,
                "can_edit_ips": false,
                "can_delete_ips": false,
                "group_id": null
            }).to_string())).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_granular_rejection() {
    let (app, db) = setup_test_app().await;
    let readonly_key = seed_readonly_key(&db).await;

    let response = app.clone()
        .oneshot(Request::builder()
            .uri("/api/ips")
            .header("X-API-Key", &readonly_key)
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
            .body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app.clone()
        .oneshot(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &readonly_key)
            .header("Content-Type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
            .body(Body::from(json!({"target_address": "2.2.2.2"}).to_string())).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_tenant_isolation_data_leakage() {
    let (app, db) = setup_test_app().await;
    
    let group_a = ip_group::ActiveModel { id: Set(Uuid::new_v4()), name: Set("Group A".to_owned()) }.insert(&db).await.unwrap();
    let group_b = ip_group::ActiveModel { id: Set(Uuid::new_v4()), name: Set("Group B".to_owned()) }.insert(&db).await.unwrap();

    let now = chrono::Utc::now().naive_utc();
    let model_a = ip_record::ActiveModel {
        id: Set(Uuid::new_v4()),
        address: Set("10.0.0.1".to_owned()),
        is_whitelist: Set(false),
        group_id: Set(Some(group_a.id)),
        cause: Set(None),
        is_locked: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };
    model_a.insert(&db).await.unwrap();

    let model_b = ip_record::ActiveModel {
        id: Set(Uuid::new_v4()),
        address: Set("192.168.1.1".to_owned()),
        is_whitelist: Set(false),
        group_id: Set(Some(group_b.id)),
        cause: Set(None),
        is_locked: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };
    model_b.insert(&db).await.unwrap();

    let key_a = seed_scoped_key(&db, group_a.id).await;

    let response = app.clone()
        .oneshot(Request::builder()
            .uri("/api/ips")
            .header("X-API-Key", &key_a)
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
            .body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    let body = ax_body_to_json(response).await;
    let list = body.as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["address"], "10.0.0.1");
}

#[tokio::test]
async fn test_tenant_isolation_forced_association() {
    let (app, db) = setup_test_app().await;
    
    let group_a = ip_group::ActiveModel { id: Set(Uuid::new_v4()), name: Set("Group A".to_owned()) }.insert(&db).await.unwrap();
    let group_b = ip_group::ActiveModel { id: Set(Uuid::new_v4()), name: Set("Group B".to_owned()) }.insert(&db).await.unwrap();

    let key_a = seed_scoped_key(&db, group_a.id).await;

    let response = app.clone()
        .oneshot(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &key_a)
            .header("Content-Type", "application/json")
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
            .body(Body::from(json!({
                "target_address": "4.4.4.4",
                "group_name": "Group B"
            }).to_string())).unwrap())
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);

    // Use explicit Entity::find() to avoid ambiguity
    let record = ip_record::Entity::find().filter(ip_record::Column::Address.eq("4.4.4.4")).one(&db).await.unwrap().unwrap();
    assert_eq!(record.group_id, Some(group_a.id));
}

async fn ax_body_to_json(response: axum::response::Response) -> serde_json::Value {
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 64).await.unwrap();
    serde_json::from_slice(&body_bytes).unwrap()
}
