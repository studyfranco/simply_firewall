use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter};
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
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    let key_id = Uuid::new_v4();
    let plaintext = simply_firewall::api::generate_random_key();
    let hash = simply_firewall::api::hash_key(&plaintext);

    simply_firewall::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
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
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key_id),
        group_id: Set(group_a_id),
        can_read: Set(true),
        can_write: Set(true),
        can_delete: Set(false),
        created_at: Set(chrono::Utc::now().naive_utc()),
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
    assert!(perms[0].can_read);
    assert!(perms[0].can_write);
    assert!(perms[0].can_delete);
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
    simply_firewall::entities::api_key::ActiveModel {
        id: Set(target_id),
        key_hash: Set(simply_firewall::api::hash_key("dummy")),
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

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{}/groups", target_id))
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
    let plaintext = simply_firewall::api::generate_random_key();
    let hash = simply_firewall::api::hash_key(&plaintext);
    simply_firewall::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
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
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "9.9.9.9", "group_name": "group-fresh" }).to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // A stale record inserted directly with an old `last_seen_at`, in "group-old".
    let old_group_id = Uuid::new_v4();
    simply_firewall::entities::ip_group::ActiveModel {
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
    simply_firewall::entities::ip_record::ActiveModel {
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

    simply_firewall::entities::ip_record_group_membership::ActiveModel {
        ip_record_id: Set(old_record_id),
        group_id: Set(old_group_id),
    }
    .insert(&db)
    .await
    .unwrap();

    // `groups` filter: only the fresh record's group should be returned.
    let req = inject_connect_info(Request::builder()
        .uri("/api/ips?groups=group-fresh")
        .header("X-API-Key", &plaintext))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["target_address"], "9.9.9.9");

    // `max_age` filter: a 60-second window must exclude the 2-hour-old record but keep the
    // fresh one, and the exclusion must happen in the query (not just be truncated by paging).
    let req = inject_connect_info(Request::builder()
        .uri("/api/ips?max_age=60")
        .header("X-API-Key", &plaintext))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(items.iter().any(|i| i["target_address"] == "9.9.9.9"));
    assert!(items.iter().all(|i| i["target_address"] != "8.8.4.4"));

    // `since` filter: a very recent Unix timestamp must also exclude the stale record.
    let since_ts = (chrono::Utc::now() - chrono::Duration::minutes(5)).timestamp();
    let req = inject_connect_info(Request::builder()
        .uri(format!("/api/ips?since={since_ts}"))
        .header("X-API-Key", &plaintext))
        .body(Body::empty())
        .unwrap();
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
        simply_firewall::webhooks::run_webhook_worker(db_for_worker, webhook_rx).await;
    });

    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_firewall::api::generate_random_key();
    let hash = simply_firewall::api::hash_key(&plaintext);
    simply_firewall::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
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
    simply_firewall::entities::ip_group::ActiveModel {
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
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "name": "Test Hook",
            "target_url": hook_url,
            "secret_token": secret,
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
        }).to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "5.5.5.5", "group_name": "hook-group" }).to_string()))
        .unwrap();
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
    let plaintext = simply_firewall::api::generate_random_key();
    let hash = simply_firewall::api::hash_key(&plaintext);
    simply_firewall::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
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
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json"))
        .body(Body::from(ban("first offense")))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Second ban into the SAME group: the membership insert hits the conflict path. Must still
    // return 200, not 500.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json"))
        .body(Body::from(ban("second offense")))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Exactly one record and one membership row must exist, with the cause updated.
    let req = inject_connect_info(Request::builder()
        .uri("/api/ips?groups=reban-group")
        .header("X-API-Key", &plaintext))
        .body(Body::empty())
        .unwrap();
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
    let plaintext = simply_firewall::api::generate_random_key();
    let hash = simply_firewall::api::hash_key(&plaintext);
    simply_firewall::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
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
    simply_firewall::entities::ip_group::ActiveModel {
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
        inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/webhooks")
            .header("X-API-Key", &plaintext)
            .header("Content-Type", "application/json"))
            .body(Body::from(json!({
                "name": "Test",
                "target_url": url,
                "secret_token": "s",
                "payload_template": "{}",
                "group_id": group_id.to_string(),
            }).to_string()))
            .unwrap()
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
    let plaintext = simply_firewall::api::generate_random_key();
    let hash = simply_firewall::api::hash_key(&plaintext);
    simply_firewall::entities::api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(hash),
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

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/keys")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "name": "CI Bot",
            "bound_ips": "10.0.0.0/8",
            "can_manage_keys": true,
            "can_manage_webhooks": true
        }).to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(created["plaintext_key"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(created["bound_ips"], "10.0.0.0/8");
    let new_key_id = created["id"].as_str().unwrap();

    // Confirm the persisted flags actually match what was requested (not just the create
    // response echoing the input back).
    let stored = simply_firewall::entities::api_key::Entity::find_by_id(Uuid::parse_str(new_key_id).unwrap())
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
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/keys")
        .header("X-API-Key", &plain_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "name": "Should Not Exist" }).to_string()))
        .unwrap();
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
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_b_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "group_name": "Group_X",
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Master seeds an address into Group_X so there is something for Key_B to read.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "203.0.113.1", "group_name": "Group_X" }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Key_B can read Group_X.
    let req = inject_connect_info(Request::builder()
        .uri("/api/ips?groups=Group_X")
        .header("X-API-Key", &key_b))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["target_address"], "203.0.113.1");

    // Key_B cannot write to Group_X yet.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "203.0.113.2", "group_name": "Group_X" }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    // Master upgrades Key_B to can_write = true.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_b_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "group_name": "Group_X",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Key_B can now write to Group_X.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "203.0.113.2", "group_name": "Group_X" }).to_string()))
        .unwrap();
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

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_b_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "group_name": "Group_X",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Sanity check: Key_B actually works before deletion.
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_b))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let perms_before = simply_firewall::entities::api_key_group_permission::Entity::find()
        .filter(simply_firewall::entities::api_key_group_permission::Column::ApiKeyId.eq(key_b_id))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(perms_before.len(), 1);

    // Master deletes Key_B.
    let req = inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{key_b_id}"))
        .header("X-API-Key", &master_key))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Immediately, any request using Key_B's header must be rejected as unauthorized.
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_b))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    let req = inject_connect_info(Request::builder()
        .uri("/api/ips?groups=Group_X")
        .header("X-API-Key", &key_b))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // No orphaned api_key_group_permissions rows survive the deleted key.
    let perms_after = simply_firewall::entities::api_key_group_permission::Entity::find()
        .filter(simply_firewall::entities::api_key_group_permission::Column::ApiKeyId.eq(key_b_id))
        .all(&db)
        .await
        .unwrap();
    assert!(perms_after.is_empty());
}
