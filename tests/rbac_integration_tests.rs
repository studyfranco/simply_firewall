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

/// `ALLOW_PRIVATE_WEBHOOKS` is process-wide global state. Any test that mutates it must hold this
/// lock for the duration, so two such tests running on different libtest threads can never
/// interleave their `set_var` calls (which is itself a data race, hence why `set_var` is `unsafe`).
static ENV_MUTATION_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

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

// ─────────────────────────────────────────────────────────────
// Concurrency, reverse-proxy security, and CIDR boundary tests
// ─────────────────────────────────────────────────────────────

async fn insert_key_with_bound_ips(db: &DatabaseConnection, name: &str, bound_ips: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let plaintext = simply_firewall::api::generate_random_key();
    let hash = simply_firewall::api::hash_key(&plaintext);
    simply_firewall::entities::api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(hash),
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
            let req = inject_connect_info(Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &master_key)
                .header("Content-Type", "application/json"))
                .body(Body::from(json!({
                    "target_address": "44.44.44.44",
                    "group_name": "burst-group",
                    "cause": "fail2ban burst"
                }).to_string()))
                .unwrap();
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
    let req = inject_connect_info(Request::builder()
        .uri("/api/ips?groups=burst-group")
        .header("X-API-Key", &master_key))
        .body(Body::empty())
        .unwrap();
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
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_trusted)
        .header("X-Forwarded-For", &xff_header))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // A key bound to the leftmost, client-forgeable claim must NOT be let through: if it were,
    // any client could bypass CIDR restriction just by prepending an allowed address to the
    // header.
    let (_id2, key_forged) = insert_key_with_bound_ips(&db, "forged-claim", "8.8.8.8/32").await;
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_forged)
        .header("X-Forwarded-For", &xff_header))
        .body(Body::empty())
        .unwrap();
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
        inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json"))
            .body(Body::from(json!({ "target_address": addr, "group_name": "cidr-boundary-group" }).to_string()))
            .unwrap()
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
        simply_firewall::webhooks::run_webhook_worker(db_for_worker, webhook_rx).await;
    });

    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let group_id = Uuid::new_v4();
    simply_firewall::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("slow-hook-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "name": "Slow Hook",
            "target_url": format!("http://{slow_addr}/slow-hook"),
            "secret_token": "s",
            "payload_template": "{}",
            "group_id": group_id.to_string(),
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let start = std::time::Instant::now();
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "66.66.66.66", "group_name": "slow-hook-group" }).to_string()))
        .unwrap();
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
        let req = inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json"))
            .body(Body::from(json!({ "target_address": addr, "group_name": "delete-shape-group" }).to_string()))
            .unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    // Delete via URL query string.
    let req = inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips?target_address=55.55.55.1&group_name=delete-shape-group")
        .header("X-API-Key", &master_key))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Delete via JSON body instead — previously this failed before the handler even ran.
    let req = inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "55.55.55.2", "group_name": "delete-shape-group" }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    let req = inject_connect_info(Request::builder()
        .uri("/api/ips?groups=delete-shape-group")
        .header("X-API-Key", &master_key))
        .body(Body::empty())
        .unwrap();
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

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "77.1.1.1", "group_name": "interop-group" }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let group_id = simply_firewall::entities::ip_group::Entity::find()
        .filter(simply_firewall::entities::ip_group::Column::Name.eq("interop-group"))
        .one(&db).await.unwrap().unwrap().id;

    // Grant Key_C rights on the group BY ID.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_c_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "group_id": group_id, "can_read": true, "can_write": true, "can_delete": false }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Key_C bans an address identifying the group BY NAME...
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "77.1.1.2", "group_name": "interop-group" }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // ...and another identifying it BY ID.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "77.1.1.3", "group_id": group_id }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Supplying both is rejected.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "77.1.1.4", "group_id": group_id, "group_name": "interop-group" }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    // Supplying neither is rejected.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "77.1.1.5" }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    // An unknown group_id is 404 — unlike group_name, an ID is never auto-creatable.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "77.1.1.6", "group_id": Uuid::new_v4() }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND);
}

/// `POST /api/keys/{id}/rotate` must generate a new secret and immediately invalidate the old one.
#[tokio::test]
async fn test_key_rotation_invalidates_old_secret() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState { db: db.clone(), webhook_tx };
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (rotate_id, old_secret) = insert_key(&db, "Rotate_Me", false, false, false, false).await;

    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &old_secret))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{rotate_id}/rotate"))
        .header("X-API-Key", &master_key))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_secret = parsed["plaintext_key"].as_str().unwrap().to_owned();
    assert_ne!(new_secret, old_secret);

    // Old secret immediately stops working.
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &old_secret))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // New secret works.
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &new_secret))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // A non-privileged key cannot rotate someone else's key.
    let (other_id, _) = insert_key(&db, "Other", false, false, false, false).await;
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{other_id}/rotate"))
        .header("X-API-Key", &new_secret))
        .body(Body::empty())
        .unwrap();
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
    let req = inject_connect_info(Request::builder()
        .uri("/api/webhooks")
        .header("X-API-Key", &target_key))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    let req = inject_connect_info(Request::builder()
        .method("PUT")
        .uri(format!("/api/keys/{target_id}"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "name": "After",
            "bound_ips": "0.0.0.0/0",
            "can_manage_webhooks": true
        }).to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let updated: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(updated["name"], "After");
    assert_eq!(updated["bound_ips"], "0.0.0.0/0");
    assert_eq!(updated["can_manage_webhooks"], true);

    // Now allowed, immediately, with the same (unrotated) secret.
    let req = inject_connect_info(Request::builder()
        .uri("/api/webhooks")
        .header("X-API-Key", &target_key))
        .body(Body::empty())
        .unwrap();
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
        let req = inject_connect_info(Request::builder()
            .method("POST")
            .uri(format!("/api/keys/{key_id}/permissions"))
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json"))
            .body(Body::from(json!({ "group_name": group_name, "can_read": true, "can_write": true, "can_delete": true }).to_string()))
            .unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    let group_id_2 = simply_firewall::entities::ip_group::Entity::find()
        .filter(simply_firewall::entities::ip_group::Column::Name.eq("revoke-by-id-group"))
        .one(&db).await.unwrap().unwrap().id;

    // Revoke the first by name.
    let req = inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/keys/".to_owned() + &key_id.to_string() + "/permissions/revoke-by-name-group")
        .header("X-API-Key", &master_key))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Revoke the second by ID.
    let req = inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{key_id}/permissions/{group_id_2}"))
        .header("X-API-Key", &master_key))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Revoking again is 404 — the grant is already gone.
    let req = inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/keys/".to_owned() + &key_id.to_string() + "/permissions/revoke-by-name-group")
        .header("X-API-Key", &master_key))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND);

    // The key can no longer read either group.
    let req = inject_connect_info(Request::builder()
        .uri("/api/ips?groups=revoke-by-name-group,revoke-by-id-group")
        .header("X-API-Key", &key_plain))
        .body(Body::empty())
        .unwrap();
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

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "target_address": "88.1.1.1", "group_name": "audit-check-group" }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Non-master keys cannot view audit logs, even with other broad global scopes.
    let req = inject_connect_info(Request::builder()
        .uri("/api/audit-logs")
        .header("X-API-Key", &sub_key))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    let req = inject_connect_info(Request::builder()
        .uri("/api/audit-logs?action=IP_ADD")
        .header("X-API-Key", &master_key))
        .body(Body::empty())
        .unwrap();
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
        inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/groups")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json"))
            .body(Body::from(json!({ "name": "duplicate-group-test" }).to_string()))
            .unwrap()
    };

    let res = app.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "duplicate group name must be 409, not 500");

    // Only one row actually exists — the failed second attempt didn't leave anything behind.
    let count = simply_firewall::entities::ip_group::Entity::find()
        .filter(simply_firewall::entities::ip_group::Column::Name.eq("duplicate-group-test"))
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

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/groups")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({ "name": "flex-id-group" }).to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let group_uuid = created["id"].as_str().unwrap().to_owned();

    // A NAME string in the group_id field — previously a guaranteed 422.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_e_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "group_id": "flex-id-group",
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // An actual UUID string in the group_id field, via the /permissions alias.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_f_id}/permissions"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "group_id": group_uuid,
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Both grants landed on the exact same group.
    let perms = simply_firewall::entities::api_key_group_permission::Entity::find().all(&db).await.unwrap();
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

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "group_name": "no-read-group",
            "can_read": false,
            "can_write": true,
            "can_delete": false
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "group_name": "no-read-group",
            "can_read": false,
            "can_write": false,
            "can_delete": true
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    // can_read alone, or read+write together, are both fine.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "group_name": "no-read-group",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string()))
        .unwrap();
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

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "target_address": "192.0.2.200",
            "group_name": "conflict-banlist",
            "cause": "flagged as hostile"
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/white")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "target_address": "192.0.2.200",
            "group_name": "conflict-whitelist",
            "cause": "also a trusted partner"
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = inject_connect_info(Request::builder()
        .uri("/api/ips?ip=192.0.2.200")
        .header("X-API-Key", &master_key))
        .body(Body::empty())
        .unwrap();
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
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "target_address": "198.51.100.77",
            "group_name": "fail2ban_nginx",
            "cause": "nginx probing"
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = inject_connect_info(Request::builder()
        .uri("/api/groups")
        .header("X-API-Key", &master_key))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let groups: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    let group_id = groups.iter().find(|g| g["name"] == "fail2ban_nginx").unwrap()["id"].as_str().unwrap().to_owned();

    // Grant via the literal group_name field.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{name_key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "group_name": "fail2ban_nginx",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Grant a DIFFERENT key on the SAME group via its UUID, seamlessly alongside the name grant.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{uuid_key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json"))
        .body(Body::from(json!({
            "group_id": group_id,
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string()))
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Both keys can now read the group, and both grants reference the identical group id.
    for key in [&name_key, &uuid_key] {
        let req = inject_connect_info(Request::builder()
            .uri("/api/ips?group_name=fail2ban_nginx")
            .header("X-API-Key", key))
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(items.len(), 1);
    }

    let perms = simply_firewall::entities::api_key_group_permission::Entity::find().all(&db).await.unwrap();
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
        let req = inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/groups")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json"))
            .body(Body::from(json!({ "name": format!("pagination-group-{i}") }).to_string()))
            .unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    let fetch_page = |offset: u64| {
        let app = app.clone();
        let master_key = master_key.clone();
        async move {
            let req = inject_connect_info(Request::builder()
                .uri(format!("/api/audit-logs?action=GROUP_CREATE&limit=3&offset={offset}"))
                .header("X-API-Key", &master_key))
                .body(Body::empty())
                .unwrap();
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

    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &restricted_key)
        .header("X-Forwarded-For", "203.0.113.50"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"], "Client IP not allowed");

    // Sanity check: the same key from the bound address itself is let through.
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &restricted_key)
        .header("X-Forwarded-For", "127.0.0.1"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}
