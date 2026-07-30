//! Security regression suite — adversarial tests for the HMAC authentication and webhook
//! signing paths.
//!
//! Where `rbac_integration_tests.rs` asks "does the feature work?", every test here asks "can it be
//! made to *not* work?" and asserts the attack fails. Each one is named for the attack it replays,
//! so a failure reads as "this vulnerability is now open" rather than "this test broke".
//!
//! Deliberately self-contained: it duplicates a small amount of harness setup from the RBAC suite
//! rather than sharing it, so that a refactor of the functional tests can never silently weaken the
//! security ones.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use simply_ip_vault::{create_app, crypto, migration, state::AppState};

/// `ALLOW_PRIVATE_WEBHOOKS` is process-wide, and the dispatcher reads it once at worker startup.
/// Tests that flip it must not overlap.
static ENV_MUTATION_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

async fn setup_test_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();
    db
}

fn inject_connect_info(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        8080,
    ))))
}

/// Test-only convention mirroring the RBAC suite: a seeded key's signing secret is derived from its
/// plaintext API key.
fn test_signing_secret(api_key: &str) -> String {
    format!("signing-secret-for-{api_key}")
}

/// Seeds a master API key directly into the database and returns its plaintext form.
async fn insert_master_key(db: &DatabaseConnection, name: &str) -> String {
    let plaintext = simply_ip_vault::api::generate_random_key();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        name: Set(name.to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        prefix: Set("sectest1".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    plaintext
}

/// Builds a fully-signed request at an explicit timestamp. The signature always covers the exact
/// timestamp that is sent, so a rejection can only come from the freshness check — never from a
/// mismatched HMAC.
fn signed_at(
    builder: axum::http::request::Builder,
    secret: &str,
    timestamp: i64,
    body: &str,
) -> Request<Body> {
    let method = builder
        .method_ref()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "GET".to_owned());
    let path = builder
        .uri_ref()
        .map(|u| u.path().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let ts = timestamp.to_string();
    let signature = crypto::compute_signature(secret, &method, &path, &ts, body.as_bytes()).unwrap();
    builder
        .header("X-Timestamp", &ts)
        .header("X-Signature-256", &signature)
        .body(Body::from(body.to_owned()))
        .unwrap()
}

/// Builds a signed request stamped "now".
fn signed(builder: axum::http::request::Builder, secret: &str, body: &str) -> Request<Body> {
    signed_at(builder, secret, chrono::Utc::now().timestamp(), body)
}

// ─────────────────────────────────────────────────────────────
// Attack 1 — Timestamp forgery (anti-replay)
// ─────────────────────────────────────────────────────────────

/// A captured-and-held request must not become usable by back- or forward-dating `X-Timestamp`.
///
/// Both probes carry a **cryptographically valid** signature over the stale timestamp they send:
/// the attacker is assumed to hold the signing secret's output for that moment (a replayed
/// capture), so the HMAC check passes and only the freshness window can stop them. A test that sent
/// a bad signature here would pass for the wrong reason and would keep passing even if the entire
/// anti-replay check were deleted.
#[tokio::test]
async fn attack_timestamp_forgery_outside_the_window_is_rejected_both_directions() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState { db: db.clone(), webhook_tx });

    let key = insert_master_key(&db, "Replay Attacker").await;
    let secret = test_signing_secret(&key);
    let now = chrono::Utc::now().timestamp();

    let probe = |offset: i64| {
        let (app, key, secret) = (app.clone(), key.clone(), secret.clone());
        async move {
            let req = signed_at(
                inject_connect_info(
                    Request::builder().uri("/api/auth/me").header("X-API-Key", &key),
                ),
                &secret,
                now + offset,
                "",
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    // Control: the identical request at the current time authenticates. Without this, a blanket
    // 401 (e.g. from a broken fixture) would make the assertions below meaningless.
    assert_eq!(probe(0).await, StatusCode::OK, "a fresh, correctly signed request must succeed");

    // 301 seconds — one second past the 300s window, in both directions.
    assert_eq!(
        probe(-301).await,
        StatusCode::UNAUTHORIZED,
        "a 301s-stale timestamp is a replay and must be rejected"
    );
    assert_eq!(
        probe(301).await,
        StatusCode::UNAUTHORIZED,
        "a 301s-future timestamp must be rejected — allowing it would let a captured request be \
         held and replayed later"
    );

    // The boundary itself is inclusive, so 301 really is the first rejected value and the test
    // above is pinned to the edge rather than to an arbitrarily distant offset.
    assert_eq!(probe(-300).await, StatusCode::OK, "exactly 300s stale is still inside the window");
    assert_eq!(probe(300).await, StatusCode::OK, "exactly 300s ahead is still inside the window");

    // A long-held capture must never come back.
    assert_eq!(probe(-86_400).await, StatusCode::UNAUTHORIZED, "a day-old capture is rejected");
}

/// `X-Timestamp` must be *mandatory*, not merely validated when present. A middleware that skipped
/// the check on a missing header would leave every signature replayable forever, since the
/// signature alone carries no notion of time.
#[tokio::test]
async fn attack_omitting_the_timestamp_header_does_not_skip_the_replay_check() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState { db: db.clone(), webhook_tx });

    let key = insert_master_key(&db, "No Timestamp").await;
    let secret = test_signing_secret(&key);
    let now = chrono::Utc::now().timestamp().to_string();

    // An otherwise perfect request: correct key, correct signature over the current time — with the
    // timestamp header simply left off.
    let signature = crypto::compute_signature(&secret, "GET", "/api/auth/me", &now, b"").unwrap();
    let req = inject_connect_info(
        Request::builder()
            .uri("/api/auth/me")
            .header("X-API-Key", &key)
            .header("X-Signature-256", &signature),
    )
    .body(Body::empty())
    .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "a missing X-Timestamp must fail closed, not bypass the freshness check"
    );

    // A non-numeric timestamp must not be coerced into something that happens to fall in-window
    // (e.g. parsed-as-zero-then-compared).
    for malformed in ["", "not-a-number", "NaN", "1e9", " ", "+", "999999999999999999999999"] {
        let req = inject_connect_info(
            Request::builder()
                .uri("/api/auth/me")
                .header("X-API-Key", &key)
                .header("X-Timestamp", malformed)
                .header("X-Signature-256", &signature),
        )
        .body(Body::empty())
        .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "malformed X-Timestamp {malformed:?} must be rejected"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// Attack 2 — Signature forgery
// ─────────────────────────────────────────────────────────────

/// Flips the final hex digit of a signature, keeping it valid hex of the correct length.
///
/// Staying valid hex is the point: a signature mangled into non-hex would be thrown out by
/// `hex::decode` before the MAC is ever consulted, so the test would pass without the constant-time
/// comparison being exercised at all. This forces the rejection to come from `Mac::verify_slice`.
fn flip_last_hex_digit(signature: &str) -> String {
    let mut chars: Vec<char> = signature.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    chars.into_iter().collect()
}

/// A single-character change to an otherwise authentic signature must be rejected.
///
/// This is the canonical probe for a truncated or prefix-only comparison: an implementation that
/// compared, say, the first 8 bytes, or that used a short-circuiting `==` on a partially-copied
/// buffer, would accept a signature differing only in its last nibble.
#[tokio::test]
async fn attack_signature_forgery_by_last_character_flip_is_rejected() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState { db: db.clone(), webhook_tx });

    let key = insert_master_key(&db, "Forger").await;
    let secret = test_signing_secret(&key);
    let now = chrono::Utc::now().timestamp().to_string();

    let authentic = crypto::compute_signature(&secret, "GET", "/api/auth/me", &now, b"").unwrap();
    assert_eq!(authentic.len(), 64, "HMAC-SHA256 hex is 64 characters");

    let send = |sig: String| {
        let (app, key, now) = (app.clone(), key.clone(), now.clone());
        async move {
            let req = inject_connect_info(
                Request::builder()
                    .uri("/api/auth/me")
                    .header("X-API-Key", &key)
                    .header("X-Timestamp", &now)
                    .header("X-Signature-256", &sig),
            )
            .body(Body::empty())
            .unwrap();
            app.oneshot(req).await.unwrap().status()
        }
    };

    // Control: unmodified, it authenticates.
    assert_eq!(send(authentic.clone()).await, StatusCode::OK);

    // The attack: exactly one character different, still 64 valid hex digits.
    let forged = flip_last_hex_digit(&authentic);
    assert_ne!(forged, authentic);
    assert_eq!(forged.len(), authentic.len());
    assert_eq!(
        forged[..63],
        authentic[..63],
        "the forgery must differ *only* in the final character"
    );
    assert_eq!(
        send(forged).await,
        StatusCode::UNAUTHORIZED,
        "a signature differing by one trailing character must be rejected"
    );

    // The same must hold at the other end and in the middle — no position is unchecked.
    for pos in [0usize, 1, 31, 32, 62] {
        let mut chars: Vec<char> = authentic.chars().collect();
        chars[pos] = if chars[pos] == '0' { '1' } else { '0' };
        let mutated: String = chars.into_iter().collect();
        assert_eq!(
            send(mutated).await,
            StatusCode::UNAUTHORIZED,
            "a signature differing at index {pos} must be rejected"
        );
    }

    // A correct-prefix-but-truncated signature must not be accepted by a length-agnostic compare.
    assert_eq!(
        send(authentic[..32].to_owned()).await,
        StatusCode::UNAUTHORIZED,
        "a truncated signature sharing a valid prefix must be rejected"
    );
    // ...nor an over-long one that merely starts with the correct value.
    assert_eq!(
        send(format!("{authentic}00")).await,
        StatusCode::UNAUTHORIZED,
        "an over-long signature with a valid prefix must be rejected"
    );
}

/// The library-level equivalent, asserting the same property directly on `verify_signature` so a
/// regression is localized to `crypto` rather than only surfacing through the HTTP stack.
#[test]
fn attack_single_bit_signature_mutations_never_verify() {
    let (secret, method, path, ts, body) = ("s3cret", "POST", "/api/ban", "1700000000", b"payload");
    let authentic = crypto::compute_signature(secret, method, path, ts, body).unwrap();
    assert!(crypto::verify_signature(secret, method, path, ts, body, &authentic));

    // Every single-character mutation across the whole 64-character signature must fail. This is
    // the exhaustive version of the "last character" attack.
    for pos in 0..authentic.len() {
        let mut chars: Vec<char> = authentic.chars().collect();
        for replacement in ['0', '1', 'a', 'f'] {
            if chars[pos] == replacement {
                continue;
            }
            let original = chars[pos];
            chars[pos] = replacement;
            let mutated: String = chars.iter().collect();
            assert!(
                !crypto::verify_signature(secret, method, path, ts, body, &mutated),
                "mutating index {pos} to {replacement} must not verify"
            );
            chars[pos] = original;
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Attack 3 — Webhook HMAC template injection
// ─────────────────────────────────────────────────────────────

/// What the mock receiver recorded from a dispatch.
#[derive(Clone, Default)]
struct CapturedHook {
    path: Option<String>,
    body: Option<String>,
    signature: Option<String>,
    timestamp: Option<String>,
}

async fn spawn_capturing_receiver() -> (String, std::sync::Arc<std::sync::Mutex<CapturedHook>>) {
    use std::sync::{Arc, Mutex};

    let captured: Arc<Mutex<CapturedHook>> = Arc::new(Mutex::new(CapturedHook::default()));
    let for_handler = captured.clone();

    let hook_app = axum::Router::new().fallback(
        move |uri: axum::http::Uri, headers: axum::http::HeaderMap, body: String| {
            let captured = for_handler.clone();
            async move {
                let header = |name: &str| {
                    headers.get(name).and_then(|h| h.to_str().ok()).map(|s| s.to_owned())
                };
                let mut c = captured.lock().unwrap();
                c.path = Some(uri.path().to_owned());
                c.signature = header("X-Signature-256");
                c.timestamp = header("X-Timestamp");
                c.body = Some(body);
                StatusCode::OK
            }
        },
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, hook_app).await.unwrap();
    });

    (format!("http://{addr}"), captured)
}

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

/// A caller who controls part of the webhook payload must not be able to forge canonical-string
/// field boundaries in the signature the dispatcher produces.
///
/// The attack surface is concrete: `cause` travels from a `POST /api/ban` body, through
/// `payload_template`'s `$cause` substitution, into the dispatched payload — and the payload is the
/// `{body}` field of the signed canonical string. If the resolver rescanned substituted values, an
/// attacker could submit `cause` containing newlines and placeholder syntax to make the receiver
/// verify a *different* method, path, and timestamp than the ones actually dispatched.
#[tokio::test]
async fn attack_hmac_template_injection_via_payload_body_cannot_forge_canonical_fields() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    let (base_url, captured) = spawn_capturing_receiver().await;

    let db = setup_test_db().await;
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::channel(100);
    let db_for_worker = db.clone();
    tokio::spawn(async move {
        simply_ip_vault::webhooks::run_webhook_worker(db_for_worker, webhook_rx).await;
    });
    let app = create_app(AppState { db: db.clone(), webhook_tx });

    let key = insert_master_key(&db, "Injection Tester").await;
    let secret = test_signing_secret(&key);

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("injection-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    // A CANONICAL_V1 webhook on the **default** template — the injection must fail against the
    // shipped configuration, not just against a hardened custom one.
    let hook_secret = "injection-webhook-secret";
    let hook_url = format!("{base_url}/hook");
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({
            "name": "Injection Hook",
            "target_url": hook_url,
            "secret_token": hook_secret,
            "payload_template": r#"{"malicious":"$cause"}"#,
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
            "events": "IP_ADD",
        })
        .to_string(),
    );
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // The hostile value: real newlines plus a complete fake canonical prefix. If these were ever
    // treated as separators, the receiver would authenticate `POST /api/fake` at timestamp 123456.
    let hostile_cause = "value\nPOST\n/api/fake\n123456";
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({
            "target_address": "203.0.113.42",
            "group_name": "injection-group",
            "cause": hostile_cause,
        })
        .to_string(),
    );
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let hit = await_dispatch(&captured).await.expect("webhook was not delivered within timeout");
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false") };

    let delivered_body = hit.body.expect("dispatch must carry a body");
    let signature = hit.signature.expect("CANONICAL_V1 must send X-Signature-256");
    let timestamp = hit.timestamp.expect("CANONICAL_V1 must send X-Timestamp");

    // The injection really did reach the payload — otherwise this test proves nothing.
    assert!(
        delivered_body.contains(hostile_cause),
        "the hostile cause must survive into the dispatched payload verbatim, got {delivered_body:?}"
    );
    assert!(delivered_body.contains('\n'), "the payload must contain real newlines");

    // ── The core assertion ──────────────────────────────────────────────────
    // The signature is the HMAC over `POST\n<real path>\n<real timestamp>\n<entire body>`, with the
    // body — newlines and all — as one opaque trailing field.
    let expected = crypto::compute_signature(
        hook_secret,
        "POST",
        "/hook",
        &timestamp,
        delivered_body.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        signature, expected,
        "the dispatcher must sign the real method/path/timestamp with the body as one opaque field"
    );

    // ── The forgeries that must NOT verify ──────────────────────────────────
    // Each is what a receiver would compute if it (or the dispatcher) had let the injected newlines
    // act as canonical separators.
    let injected_tail = delivered_body
        .split_once("value\n")
        .map(|(_, tail)| tail.to_owned())
        .expect("the injected marker is present");
    for (method, path, ts, body) in [
        ("POST", "/api/fake", "123456", injected_tail.as_str()),
        ("POST", "/api/fake", "123456", delivered_body.as_str()),
        ("POST", "/api/fake", timestamp.as_str(), delivered_body.as_str()),
    ] {
        assert!(
            !crypto::verify_signature(hook_secret, method, path, ts, body.as_bytes(), &signature),
            "the injected fields ({method} {path} @{ts}) must not verify against the real signature"
        );
    }

    // The receiver's contract holds: verifying with the true fields succeeds.
    assert!(
        crypto::verify_signature(
            hook_secret,
            "POST",
            "/hook",
            &timestamp,
            delivered_body.as_bytes(),
            &signature,
        ),
        "the genuine canonical fields must verify"
    );

    // And the path actually requested is the one signed — not the injected `/api/fake`.
    assert_eq!(hit.path.as_deref(), Some("/hook"));
}

/// The same property at the unit level, isolated from HTTP and timing: a body carrying placeholder
/// syntax and escape sequences lands in the signed string byte-for-byte, and the canonical fields
/// remain recoverable by a receiver splitting into exactly four parts.
#[test]
fn attack_template_resolution_never_rescans_substituted_values() {
    use simply_ip_vault::{
        entities::webhook_config::DEFAULT_HMAC_TEMPLATE, webhooks::resolve_hmac_template,
    };

    // Both flavours of the attack: real newline characters, and literal backslash-n escapes.
    for hostile_body in [
        "{\"malicious\": \"value\nPOST\n/api/fake\n123456\"}",
        r#"{"malicious": "value\nPOST\n/api/fake\n123456"}"#,
        r"{path}\n{timestamp}\n{body}",
        r"{method}{path}{timestamp}{body}",
        "\\\\n{body}",
    ] {
        let resolved =
            resolve_hmac_template(DEFAULT_HMAC_TEMPLATE, "POST", "/real/path", "1700000000", hostile_body);

        // The signed string is exactly the three real fields plus the body appended verbatim.
        assert_eq!(
            resolved,
            format!("POST\n/real/path\n1700000000\n{hostile_body}"),
            "substituted values must never be rescanned for placeholders or escapes"
        );

        // A receiver splitting into four fields recovers the true method, path and timestamp — the
        // injected content stays entirely inside the fourth.
        let mut fields = resolved.splitn(4, '\n');
        assert_eq!(fields.next(), Some("POST"));
        assert_eq!(fields.next(), Some("/real/path"));
        assert_eq!(fields.next(), Some("1700000000"));
        assert_eq!(fields.next(), Some(hostile_body));
    }
}

// ─────────────────────────────────────────────────────────────
// Attack 4 — Invalid auth-mode configuration
// ─────────────────────────────────────────────────────────────

/// A signing mode with no secret must be refused at creation.
///
/// Accepting it would key the HMAC with the empty string — a signature *anyone* can compute, which
/// is strictly worse than sending none at all because the receiver sees a well-formed
/// `X-Signature-256` and concludes the request is authenticated.
#[tokio::test]
async fn attack_canonical_v1_webhook_without_a_secret_is_rejected() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState { db: db.clone(), webhook_tx });

    let key = insert_master_key(&db, "Webhook Admin").await;
    let secret = test_signing_secret(&key);

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("authmode-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let create = |mut payload: serde_json::Value, name: &str| {
        payload["name"] = json!(name);
        payload["target_url"] = json!("https://example.com/hook");
        payload["payload_template"] = json!("{}");
        payload["group_id"] = json!(group_id.to_string());
        signed(
            inject_connect_info(
                Request::builder()
                    .method("POST")
                    .uri("/api/webhooks")
                    .header("X-API-Key", &key)
                    .header("Content-Type", "application/json"),
            ),
            &secret,
            &payload.to_string(),
        )
    };
    let status = |req: Request<Body>| {
        let app = app.clone();
        async move { app.oneshot(req).await.unwrap().status() }
    };

    // The headline case: CANONICAL_V1 with an explicitly empty secret_token.
    assert_eq!(
        status(create(json!({ "auth_mode": "CANONICAL_V1", "secret_token": "" }), "empty-secret")).await,
        StatusCode::BAD_REQUEST,
        "CANONICAL_V1 with an empty secret_token must be rejected"
    );

    // ...and the equivalent shapes a client can produce for "no secret".
    assert_eq!(
        status(create(json!({ "auth_mode": "CANONICAL_V1" }), "omitted-secret")).await,
        StatusCode::BAD_REQUEST,
        "CANONICAL_V1 with an omitted secret_token must be rejected"
    );
    assert_eq!(
        status(create(json!({ "auth_mode": "CANONICAL_V1", "secret_token": null }), "null-secret")).await,
        StatusCode::BAD_REQUEST,
        "CANONICAL_V1 with a null secret_token must be rejected"
    );
    // Case-insensitive parsing must not become a way around the precondition.
    assert_eq!(
        status(create(json!({ "auth_mode": "canonical_v1", "secret_token": "" }), "lowercase-mode")).await,
        StatusCode::BAD_REQUEST,
        "the precondition must apply regardless of auth_mode casing"
    );
    // The deprecated alias reaches the same validation path.
    assert_eq!(
        status(create(json!({ "signature_mode": "CANONICAL_V1", "secret_token": "" }), "alias-mode")).await,
        StatusCode::BAD_REQUEST,
        "the deprecated signature_mode alias must not bypass the secret precondition"
    );
    // BODY_ONLY is the other signing mode and needs the same guarantee.
    assert_eq!(
        status(create(json!({ "auth_mode": "BODY_ONLY", "secret_token": "" }), "body-only-empty")).await,
        StatusCode::BAD_REQUEST,
        "BODY_ONLY with an empty secret_token must be rejected"
    );

    // An unknown mode must be refused outright rather than silently defaulted to something weaker.
    assert_eq!(
        status(create(json!({ "auth_mode": "PLAINTEXT", "secret_token": "s" }), "bogus-mode")).await,
        StatusCode::BAD_REQUEST,
        "an unrecognized auth_mode must be rejected, not defaulted"
    );

    // A template that never interpolates {body} signs a constant — replayable against any payload.
    assert_eq!(
        status(create(
            json!({
                "auth_mode": "CANONICAL_V1",
                "secret_token": "s",
                "hmac_template": r"{method}\n{path}\n{timestamp}",
            }),
            "bodyless-template"
        ))
        .await,
        StatusCode::BAD_REQUEST,
        "an hmac_template that omits {{body}} authenticates nothing and must be rejected"
    );

    // Control: with a real secret, the same request succeeds — proving the rejections above come
    // from the precondition and not from something incidental in the fixture.
    assert_eq!(
        status(create(
            json!({ "auth_mode": "CANONICAL_V1", "secret_token": "a-real-secret" }),
            "valid-canonical"
        ))
        .await,
        StatusCode::OK,
        "a CANONICAL_V1 webhook with a secret must still be creatable"
    );
}

/// The `secret_token` must never be readable back out of the API. A reader who can list webhooks
/// and recover the secret can forge `X-Signature-256` for every dispatch that webhook makes.
#[tokio::test]
async fn attack_webhook_secret_is_not_recoverable_from_read_endpoints() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState { db: db.clone(), webhook_tx });

    let key = insert_master_key(&db, "Reader").await;
    let secret = test_signing_secret(&key);

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("leak-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let hook_secret = "super-secret-hmac-key-do-not-leak";
    let downstream_key = "downstream-api-key-do-not-leak";
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({
            "name": "Leak Check",
            "target_url": "https://example.com/hook",
            "secret_token": hook_secret,
            "api_key": downstream_key,
            "payload_template": "{}",
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
        })
        .to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created = String::from_utf8(created.to_vec()).unwrap();
    assert!(!created.contains(hook_secret), "creation response leaked secret_token");
    assert!(!created.contains(downstream_key), "creation response leaked api_key");

    let req = signed(
        inject_connect_info(Request::builder().uri("/api/webhooks").header("X-API-Key", &key)),
        &secret,
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let listing = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let listing = String::from_utf8(listing.to_vec()).unwrap();
    assert!(!listing.contains(hook_secret), "GET /api/webhooks leaked secret_token");
    assert!(!listing.contains(downstream_key), "GET /api/webhooks leaked api_key");
}
