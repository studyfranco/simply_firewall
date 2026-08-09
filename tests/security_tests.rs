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
use sea_orm::{
    ConnectionTrait,
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Database, DatabaseConnection, EntityTrait,
    QueryFilter,
};
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

/// Injects an explicit TCP peer address, standing in for what the kernel reports.
///
/// This is the value an attacker **cannot** control. Everything the spoofing tests turn on is the
/// difference between it and the headers a client writes freely.
fn connect_from(req: axum::http::request::Builder, peer: &str) -> axum::http::request::Builder {
    let ip: std::net::IpAddr = peer.parse().expect("test peer literal parses");
    req.extension(axum::extract::ConnectInfo(std::net::SocketAddr::new(ip, 40000)))
}

/// Parses a `TRUSTED_PROXIES`-style string into the matcher list `AppState` carries.
fn trusted(entries: &str) -> Vec<simply_ip_vault::config::ProxyMatcher> {
    simply_ip_vault::config::parse_trusted_proxies(entries)
        .expect("test fixture must use valid proxy entries")
}

/// Test-only convention mirroring the RBAC suite: a seeded key's signing secret is derived from its
/// plaintext API key.
fn test_signing_secret(api_key: &str) -> String {
    format!("signing-secret-for-{api_key}")
}

/// The same secret in the shape the database actually stores.
///
/// `SecretCipher::open` is strictly fail-closed as of the 2026-08-02 hardening pass: a stored value
/// with no recognized prefix is a `MalformedCiphertext` error rather than a bare secret returned
/// verbatim. Seeded rows must therefore carry a real storage prefix, exactly as `SecretCipher::seal`
/// would have written it in the zero-config plaintext mode these suites run in.
fn stored_signing_secret(api_key: &str) -> String {
    format!("v1.plain.{}", hex::encode(test_signing_secret(api_key)))
}

/// Seeds an API key with explicit scopes and an optional `bound_ips`, returning `(id, plaintext)`.
#[allow(clippy::too_many_arguments)]
async fn insert_key(
    db: &DatabaseConnection,
    name: &str,
    is_master: bool,
    can_manage_keys: bool,
    can_manage_webhooks: bool,
    can_create_groups: bool,
    bound_ips: Option<&str>,
) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set(name.to_owned()),
        bound_ips: Set(bound_ips.map(str::to_owned)),
        is_master: Set(is_master),
        can_manage_keys: Set(can_manage_keys),
        can_manage_webhooks: Set(can_manage_webhooks),
        can_create_groups: Set(can_create_groups),
        parent_key_id: Set(None),
        prefix: Set("sectest2".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    (id, plaintext)
}

/// Seeds an IP group and returns its id.
async fn insert_group(db: &DatabaseConnection, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    id
}

/// Grants a key explicit read/write/delete on a group.
async fn grant(
    db: &DatabaseConnection,
    key_id: Uuid,
    group_id: Uuid,
    read: bool,
    write: bool,
    del: bool,
) {
    simply_ip_vault::entities::api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key_id),
        group_id: Set(group_id),
        can_read: Set(read),
        can_write: Set(write),
        can_delete: Set(del),
        // The administrative flag is off unless a test asks for it explicitly — the security suite
        // is about the read/write/delete surface.
        can_manage: Set(false),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
}

/// Grants a key read/write/delete **and** the administrative `can_manage` flag on a group.
///
/// R2 makes `can_manage` half of the authority to touch a group's permission rows at all, so any
/// fixture whose caller is expected to grant or revoke needs this rather than [`grant`].
async fn grant_manager(
    db: &DatabaseConnection,
    key_id: Uuid,
    group_id: Uuid,
    read: bool,
    write: bool,
    del: bool,
) {
    simply_ip_vault::entities::api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key_id),
        group_id: Set(group_id),
        can_read: Set(read),
        can_write: Set(write),
        can_delete: Set(del),
        can_manage: Set(true),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
}

/// Records `parent` as `child`'s creator, so a seeded fixture lands inside a caller's subtree.
///
/// §4 scopes credential-level operations to the caller's own subtree, and `insert_key` seeds keys with
/// no lineage at all — which puts them outside everyone's. A test about *authority* has to place its
/// target inside the caller's scope first, or it measures visibility instead.
async fn set_parent(db: &DatabaseConnection, child: Uuid, parent: Uuid) {
    let mut active: simply_ip_vault::entities::api_key::ActiveModel =
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(child)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .into();
    active.parent_key_id = Set(Some(parent));
    active.update(db).await.unwrap();
}

/// Seeds a master API key directly into the database and returns its plaintext form.
async fn insert_master_key(db: &DatabaseConnection, name: &str) -> String {
    let plaintext = simply_ip_vault::api::generate_random_key();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set(name.to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
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
    // The **full** target, query string included — signing the bare path here would make the
    // query-tampering tests below pass without proving anything.
    let target = builder
        .uri_ref()
        .map(|u| {
            u.path_and_query()
                .map(|pq| pq.as_str().to_owned())
                .unwrap_or_else(|| u.path().to_owned())
        })
        .unwrap_or_else(|| "/".to_owned());
    let ts = timestamp.to_string();
    let signature = crypto::compute_signature(secret, &method, &target, &ts, body.as_bytes()).unwrap();
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

/// Builds a signed request stamped `offset_secs` into the future.
///
/// A signature covers method, target, timestamp and body and nothing else, so repeating a call
/// unchanged inside the same wall-clock second yields the identical signature — a replay, which the
/// guard now refuses. Real callers never hit this because their second attempt lands on a later
/// timestamp; a test issuing both microseconds apart has to say so explicitly. The offset stays far
/// inside the ±300s window, so the request is exactly as fresh as a genuine later one.
fn signed_later(
    builder: axum::http::request::Builder,
    secret: &str,
    offset_secs: i64,
    body: &str,
) -> Request<Body> {
    signed_at(builder, secret, chrono::Utc::now().timestamp() + offset_secs, body)
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
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

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
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

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
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Forger").await;
    let secret = test_signing_secret(&key);
    let now = chrono::Utc::now().timestamp().to_string();

    let authentic = crypto::compute_signature(&secret, "GET", "/api/auth/me", &now, b"").unwrap();
    // Mutations are applied to the digest and re-tagged, so every case below reaches the MAC
    // comparison instead of being turned away by the `sha256=` format check — which would make the
    // whole test pass for a reason that has nothing to do with what it is probing.
    let digest = authentic
        .strip_prefix(crypto::SIGNATURE_PREFIX)
        .expect("compute_signature emits the mandatory tag")
        .to_owned();
    assert_eq!(digest.len(), 64, "HMAC-SHA256 hex is 64 characters");
    let tagged = |digest: &str| format!("{}{digest}", crypto::SIGNATURE_PREFIX);

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
    let forged = flip_last_hex_digit(&digest);
    assert_ne!(forged, digest);
    assert_eq!(forged.len(), digest.len());
    assert_eq!(forged[..63], digest[..63], "the forgery must differ *only* in the final character");
    assert_eq!(
        send(tagged(&forged)).await,
        StatusCode::UNAUTHORIZED,
        "a signature differing by one trailing character must be rejected"
    );

    // The same must hold at the other end and in the middle — no position is unchecked.
    for pos in [0usize, 1, 31, 32, 62] {
        let mut chars: Vec<char> = digest.chars().collect();
        chars[pos] = if chars[pos] == '0' { '1' } else { '0' };
        let mutated: String = chars.into_iter().collect();
        assert_eq!(
            send(tagged(&mutated)).await,
            StatusCode::UNAUTHORIZED,
            "a signature differing at index {pos} must be rejected"
        );
    }

    // A correct-prefix-but-truncated signature must not be accepted by a length-agnostic compare.
    assert_eq!(
        send(tagged(&digest[..32])).await,
        StatusCode::UNAUTHORIZED,
        "a truncated signature sharing a valid prefix must be rejected"
    );
    // ...nor an over-long one that merely starts with the correct value.
    assert_eq!(
        send(tagged(&format!("{digest}00"))).await,
        StatusCode::UNAUTHORIZED,
        "an over-long signature with a valid prefix must be rejected"
    );

    // And the digest sent bare — correct bytes, missing tag — is refused over HTTP with 401, not
    // merely inside `verify_signature`. This is the mandated end-to-end check on the format rule.
    //
    // It must be a signature that has **never been accepted**, which is why it is signed over a
    // fresh timestamp rather than reusing `digest`. Reusing it would make the replay guard the thing
    // doing the rejecting — the control request at the top of this test already consumed that
    // digest — and the check would then report 401 just as loudly with the format rule deleted.
    // Verified by mutation: with both the `crypto` and middleware checks removed, this fails.
    let unused_now = (chrono::Utc::now().timestamp() - 7).to_string();
    let unused = crypto::compute_signature(&secret, "GET", "/api/auth/me", &unused_now, b"").unwrap();
    let unused_digest = unused
        .strip_prefix(crypto::SIGNATURE_PREFIX)
        .expect("compute_signature emits the mandatory tag")
        .to_owned();

    let send_at = |sig: String, ts: String| {
        let (app, key) = (app.clone(), key.clone());
        async move {
            let req = inject_connect_info(
                Request::builder()
                    .uri("/api/auth/me")
                    .header("X-API-Key", &key)
                    .header("X-Timestamp", &ts)
                    .header("X-Signature-256", &sig),
            )
            .body(Body::empty())
            .unwrap();
            app.oneshot(req).await.unwrap().status()
        }
    };

    assert_eq!(
        send_at(unused_digest, unused_now.clone()).await,
        StatusCode::UNAUTHORIZED,
        "a valid hex signature missing the sha256= prefix must be rejected with 401"
    );
    // Control: the very same signature *with* the tag is accepted, proving the rejection above is
    // the missing prefix and not a stale timestamp or an exhausted key.
    assert_eq!(
        send_at(unused, unused_now).await,
        StatusCode::OK,
        "the same signature with its sha256= tag must authenticate"
    );
}

/// The library-level equivalent, asserting the same property directly on `verify_signature` so a
/// regression is localized to `crypto` rather than only surfacing through the HTTP stack.
///
/// # Why bits and not characters
///
/// An earlier version of this test mutated hex *characters*, which is a coarser instrument than it
/// looks: it replaced each position with one of four fixed digits, so it never distinguished the two
/// nibbles of a byte and never covered the other eleven values a nibble can take. This sweeps the
/// **decoded tag**: all 32 bytes × 8 bits = 256 single-bit forgeries, each one re-encoded and sent
/// through the real entry point. Every one must fail.
///
/// That is the exhaustive statement of what a constant-time comparison buys. A comparison that
/// short-circuits, that compares a prefix, that stops at a word boundary, or that folds bytes
/// together before comparing would each accept *some* single-bit change — and each would still pass
/// a spot-check of the first, middle, and last positions.
///
/// The wrong-length cases are the other half. `Mac::verify_slice` rejects a mismatched width before
/// comparing anything, which is correct and leaks only the digest width (a public constant); this
/// asserts it happens rather than assuming it, across every length from empty to double.
#[test]
fn attack_single_bit_signature_mutations_never_verify() {
    let (secret, method, path, ts, body) = ("s3cret", "POST", "/api/ban", "1700000000", b"payload");
    let authentic = crypto::compute_signature(secret, method, path, ts, body).unwrap();
    let tag = hex::decode(
        authentic.strip_prefix(crypto::SIGNATURE_PREFIX).expect("the mandatory tag is present"),
    )
    .expect("the digest is hex");

    assert_eq!(tag.len(), 32, "HMAC-SHA256 produces a 32-byte tag");
    assert!(
        crypto::verify_signature(secret, method, path, ts, body, &authentic).is_some(),
        "control: the unmodified signature verifies"
    );

    let verify = |tag: &[u8]| {
        let framed = format!("{}{}", crypto::SIGNATURE_PREFIX, hex::encode(tag));
        crypto::verify_signature(secret, method, path, ts, body, &framed)
    };

    // All 256 single-bit forgeries.
    for byte in 0..tag.len() {
        for bit in 0..8u32 {
            let mut forged = tag.clone();
            forged[byte] ^= 1 << bit;
            assert!(
                verify(&forged).is_none(),
                "flipping bit {bit} of byte {byte} must not verify"
            );
        }
    }

    // Every wrong width, including the empty tag and the doubled one. A truncation that happens to
    // share a prefix with the real tag is the case a length-agnostic compare would accept.
    for len in (0..=64).filter(|len| *len != 32) {
        let mut wrong = tag.clone();
        wrong.resize(len, 0);
        assert!(verify(&wrong).is_none(), "a {len}-byte tag must be rejected on width alone");
    }

    // ...and the untruncated tag with trailing bytes appended, which shares all 32 correct bytes.
    let mut extended = tag.clone();
    extended.extend_from_slice(&[0u8; 8]);
    assert!(verify(&extended).is_none(), "a tag that merely starts correct must be rejected");
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
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Injection Tester").await;
    let secret = test_signing_secret(&key);

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("injection-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
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
            crypto::verify_signature(hook_secret, method, path, ts, body.as_bytes(), &signature)
                .is_none(),
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
        )
        .is_some(),
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
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Webhook Admin").await;
    let secret = test_signing_secret(&key);

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("authmode-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
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
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Reader").await;
    let secret = test_signing_secret(&key);

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("leak-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
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

// ─────────────────────────────────────────────────────────────
// Attack 5 — X-Forwarded-For spoofing against bound_ips
// ─────────────────────────────────────────────────────────────

/// The headline IP-spoofing attack: a key restricted to a CIDR must not be usable from outside it
/// merely by claiming an allowed address in a header.
///
/// `X-Forwarded-For` is an ordinary request header — anyone can send any value. Honouring it from
/// an arbitrary peer turns `bound_ips` from a network restriction into a self-asserted one, i.e.
/// into no restriction at all. The peer address in `connect_from` is the part the attacker cannot
/// forge, and it is the only thing that may decide whether the header is believed.
#[tokio::test]
async fn attack_spoofed_forwarded_for_from_an_untrusted_peer_cannot_bypass_bound_ips() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    // A proxy IS configured — but not the attacker's. The check is per-peer, not
    // "is anything configured at all".
    let app = create_app(AppState::with_trusted_proxies(
        db.clone(),
        webhook_tx,
        trusted("10.0.0.0/8"),
    ));

    let (_id, key) = insert_key(&db, "Bound", false, false, false, false, Some("192.168.1.0/24")).await;
    let secret = test_signing_secret(&key);

    // Every call below repeats the same signed request with only unsigned headers (or nothing)
    // varying, which would otherwise reproduce one signature and be refused as a replay. The
    // counter stands in for the seconds a real caller would have spent between attempts.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let probe = |peer: &'static str, xff: Option<&'static str>, real_ip: Option<&'static str>| {
        let (app, key, secret, tick) = (app.clone(), key.clone(), secret.clone(), tick.clone());
        async move {
            let mut builder =
                connect_from(Request::builder().uri("/api/auth/me").header("X-API-Key", &key), peer);
            if let Some(v) = xff {
                builder = builder.header("X-Forwarded-For", v);
            }
            if let Some(v) = real_ip {
                builder = builder.header("X-Real-IP", v);
            }
            let offset = tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            app.oneshot(signed_later(builder, &secret, offset, "")).await.unwrap().status()
        }
    };

    // Control: from an address genuinely inside the bound CIDR, with no headers at all, it works.
    // Without this the assertions below could all be passing for an unrelated reason.
    assert_eq!(probe("192.168.1.50", None, None).await, StatusCode::OK);

    // The attack: an untrusted peer claiming to be inside the bound CIDR.
    assert_eq!(
        probe("203.0.113.9", Some("192.168.1.50"), None).await,
        StatusCode::FORBIDDEN,
        "a spoofed X-Forwarded-For from an untrusted peer must not satisfy bound_ips"
    );
    assert_eq!(
        probe("203.0.113.9", None, Some("192.168.1.50")).await,
        StatusCode::FORBIDDEN,
        "a spoofed X-Real-IP from an untrusted peer must not satisfy bound_ips"
    );
    assert_eq!(
        probe("203.0.113.9", Some("192.168.1.50"), Some("192.168.1.50")).await,
        StatusCode::FORBIDDEN,
        "sending both spoofed headers must not satisfy bound_ips either"
    );

    // Claiming to *be* the trusted proxy does not make the claim believable — trust is decided by
    // the peer address, never by the header's contents.
    assert_eq!(
        probe("203.0.113.9", Some("10.0.0.1, 192.168.1.50"), None).await,
        StatusCode::FORBIDDEN,
        "impersonating a trusted proxy inside the header must not bootstrap trust"
    );

    // A multi-hop chain forged entirely by the client is equally inert.
    assert_eq!(
        probe("203.0.113.9", Some("192.168.1.50, 192.168.1.51, 192.168.1.52"), None).await,
        StatusCode::FORBIDDEN,
        "a fully forged proxy chain must not satisfy bound_ips"
    );
}

/// The other half of the contract: from a peer that genuinely *is* a configured proxy, the header
/// is honoured — otherwise the fix would simply have broken every proxied deployment.
#[tokio::test]
async fn forwarded_for_is_honoured_from_a_configured_trusted_proxy() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(
        db.clone(),
        webhook_tx,
        trusted("10.0.0.0/8"),
    ));

    let (_id, key) = insert_key(&db, "Proxied", false, false, false, false, Some("192.168.1.0/24")).await;
    let secret = test_signing_secret(&key);

    // Repeated calls below differ only in unsigned headers, so each needs its own timestamp or the
    // second would reproduce the first's signature and be refused as a replay.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let probe = |peer: &'static str, xff: &'static str| {
        let (app, key, secret, tick) = (app.clone(), key.clone(), secret.clone(), tick.clone());
        async move {
            let req = signed_later(
                connect_from(
                    Request::builder().uri("/api/auth/me").header("X-API-Key", &key),
                    peer,
                )
                .header("X-Forwarded-For", xff),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                "",
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    // The trusted proxy declares an in-CIDR client.
    assert_eq!(probe("10.0.0.1", "192.168.1.50").await, StatusCode::OK);

    // A client-supplied prefix is ignored in favour of the proxy-appended rightmost entry, so a
    // client behind the proxy still cannot forge its way in.
    assert_eq!(
        probe("10.0.0.1", "192.168.1.50, 203.0.113.9").await,
        StatusCode::FORBIDDEN,
        "the rightmost (proxy-appended) hop wins over a client-supplied prefix"
    );

    // ...and the reverse ordering resolves to the real client.
    assert_eq!(probe("10.0.0.1", "203.0.113.9, 192.168.1.50").await, StatusCode::OK);

    // A chained trusted hop is skipped, exposing the genuine client behind it.
    assert_eq!(probe("10.0.0.1", "192.168.1.50, 10.0.0.2").await, StatusCode::OK);
}

/// A master key with a configured `bound_ips` must be held to it like any other key.
///
/// The previous `!key.is_master` bypass made the single most powerful credential in the system the
/// only one whose network restriction was decorative — and silently ignored a restriction an
/// operator had explicitly set, which is worse than not offering the field at all.
#[tokio::test]
async fn attack_master_key_is_not_exempt_from_its_bound_ips() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_id, bound_master) =
        insert_key(&db, "Bound Master", true, true, true, true, Some("192.168.1.0/24")).await;
    let bound_secret = test_signing_secret(&bound_master);

    // Repeated calls below differ only in unsigned headers, so each needs its own timestamp or the
    // second would reproduce the first's signature and be refused as a replay.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let call = |key: String, secret: String, peer: &'static str| {
        let (app, tick) = (app.clone(), tick.clone());
        async move {
            let req = signed_later(
                connect_from(
                    Request::builder().uri("/api/auth/me").header("X-API-Key", &key),
                    peer,
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                "",
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    // From inside its bound network the master key works normally.
    assert_eq!(
        call(bound_master.clone(), bound_secret.clone(), "192.168.1.50").await,
        StatusCode::OK
    );

    // From outside it, master status is no longer an exemption.
    assert_eq!(
        call(bound_master.clone(), bound_secret.clone(), "203.0.113.9").await,
        StatusCode::FORBIDDEN,
        "a master key with bound_ips set must be rejected outside that CIDR"
    );

    // A key with *no* bound_ips is still unrestricted — an empty column means "no restriction
    // configured", not "restrict to nothing".
    //
    // Not a second master: `api_keys.master_marker` carries a unique index now (RBAC_MODEL.md §5),
    // so one database holds one master and this fixture cannot mint another. Nothing is lost — the
    // property under test is a property of `bound_ips`, not of master status, and the master-specific
    // half of this test (no CIDR exemption) is already proven by the two assertions above.
    let (_id2, free_key) = insert_key(&db, "Free Key", false, false, false, false, None).await;
    assert_eq!(
        call(free_key.clone(), test_signing_secret(&free_key), "203.0.113.9").await,
        StatusCode::OK,
        "a key without bound_ips stays unrestricted"
    );
}

// ─────────────────────────────────────────────────────────────
// Attack 6 — Master privilege escalation via key administration
// ─────────────────────────────────────────────────────────────

/// Builds a `can_manage_keys` (but non-master) caller plus a master victim, and returns the app.
async fn escalation_fixture(
    db: &DatabaseConnection,
) -> (axum::Router, String, String, Uuid, Uuid) {
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (manager_id, manager) = insert_key(db, "Key Manager", false, true, true, true, None).await;
    let (victim_id, _victim) = insert_key(db, "Master Victim", true, true, true, true, None).await;

    let secret = test_signing_secret(&manager);
    (app, manager, secret, manager_id, victim_id)
}

/// `can_manage_keys` must not be a route to `is_master`.
///
/// Minting a master key returns its plaintext in the very same response, so accepting
/// `is_master: true` from a non-master was a single-request escalation from a delegated scope to
/// full control of the system.
///
/// The refusal moved from `403` to `400` when `RBAC_MODEL.md` §5 took master status out of the API
/// surface entirely: it is no longer a scope the caller lacks authority for, it is a field no
/// payload may carry — from *any* caller, master included. `attack_a_master_cannot_mint_a_second_master`
/// covers the other half of that, and the count assertion below is unchanged and still the point:
/// whatever the status code, no second master row appears.
#[tokio::test]
async fn attack_non_master_cannot_mint_a_master_key() {
    let db = setup_test_db().await;
    let (app, manager, secret, _mid, _vid) = escalation_fixture(&db).await;

    let create = |body: serde_json::Value| {
        let (app, manager, secret) = (app.clone(), manager.clone(), secret.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri("/api/keys")
                        .header("X-API-Key", &manager)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                &body.to_string(),
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        }
    };

    let (status, body) = create(json!({ "name": "escalated", "is_master": true })).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-master must not be able to create a master key (got body {body})"
    );
    assert!(
        body.contains("is_master"),
        "the refusal must name the offending field so the caller knows what to remove: {body}"
    );

    // Clearing it is refused on the same terms. §5 says "settable or clearable", and a payload that
    // carries the field is asserting authority over it in either direction.
    let (status, _) = create(json!({ "name": "explicitly-not-master", "is_master": false })).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "`is_master: false` is refused too — the field may not appear at all"
    );

    // Nothing was written — the rejection happens before the insert, so no orphan key is left over.
    let masters = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(masters.len(), 1, "only the pre-seeded master victim should exist");

    // The other two master-only scopes are each a path *back to* master authority — one mints
    // co-administrators, the other mints groups whose creator is auto-granted full access — so a
    // non-master cannot hand either out.
    for scope in ["can_manage_keys", "can_create_groups", "can_manage_webhooks"] {
        let (status, _) = create(json!({ "name": format!("escalated-{scope}"), scope: true })).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a non-master must not be able to grant '{scope}'"
        );
    }

    // `can_manage_webhooks` joined the master-only set under R4. It was previously delegable on the
    // reasoning that it "confers no authority over keys or groups", which was too narrow: a webhook is
    // a standing export of everything happening in a group to a URL its creator picks, and the scope
    // was freely amplifiable — a parent that did not hold it could hand it out, R1's plainest
    // violation. §1 puts resource-creation rights at the same tier as `can_manage_keys`.
    let (status, _) = create(json!({ "name": "webhook-minter", "can_manage_webhooks": true })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a non-master cannot grant can_manage_webhooks");

    // Control: the same caller can still create an ordinary key, so the guards bound key
    // administration rather than having disabled it.
    let (status, _) = create(json!({ "name": "ordinary" })).await;
    assert_eq!(status, StatusCode::OK, "a non-master may still create unscoped keys");

    // An explicit `false` on the master-only *scopes* is not treated as a request for elevation.
    // `is_master` is absent here on purpose: it is no longer a scope with a permissive `false`
    // branch, it is a field the payload may not carry at all, which the assertion further up
    // establishes separately.
    let (status, _) = create(json!({
        "name": "explicitly-unscoped",
        "can_manage_keys": false,
        "can_create_groups": false,
        "can_manage_webhooks": false,
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// The same restriction on the update path: a non-master cannot elevate an *existing* key into the
/// master-only scopes either, which would otherwise be a two-step version of the same escalation.
#[tokio::test]
async fn attack_non_master_cannot_elevate_an_existing_key_into_master_scopes() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (mid, manager) = insert_key(&db, "Manager", false, true, true, false, None).await;
    let secret = test_signing_secret(&manager);
    let (victim_id, _victim) = insert_key(&db, "Ordinary", false, false, false, false, None).await;
    // Inside the manager's subtree, so every refusal below is R4 refusing an elevation rather than §4
    // refusing to admit the key exists.
    set_parent(&db, victim_id, mid).await;

    // Some calls below repeat verbatim, so each takes its own timestamp — an identical repeat
    // inside one second is the same signature, which is exactly what a replay is.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let update = |body: serde_json::Value| {
        let (app, manager, secret, tick) =
            (app.clone(), manager.clone(), secret.clone(), tick.clone());
        async move {
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/api/keys/{victim_id}"))
                        .header("X-API-Key", &manager)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                &body.to_string(),
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    // Every global scope is master-only under R4 — `can_manage_webhooks` included, as of Phase 1.
    for scope in ["can_manage_keys", "can_create_groups", "can_manage_webhooks"] {
        assert_eq!(
            update(json!({ scope: true })).await,
            StatusCode::FORBIDDEN,
            "a non-master must not elevate another key into '{scope}'"
        );
    }

    // Ordinary fields still update normally, so the guard bounds elevation rather than freezing the
    // endpoint.
    assert_eq!(update(json!({ "name": "Renamed" })).await, StatusCode::OK);

    // Lowering a scope is never an elevation, so a non-master may still take one away.
    assert_eq!(update(json!({ "can_manage_webhooks": false })).await, StatusCode::OK);

    let after = simply_ip_vault::entities::prelude::ApiKey::find_by_id(victim_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(!after.is_master && !after.can_manage_keys && !after.can_create_groups);
    assert!(!after.can_manage_webhooks, "no scope was granted");
    assert_eq!(after.name, "Renamed", "the non-scope field did land");
}

// ─────────────────────────────────────────────────────────────
// Attack 6b — Master uniqueness and immutability (RBAC_MODEL.md §5)
// ─────────────────────────────────────────────────────────────

/// Master uniqueness is a **schema** invariant, not an application convention.
///
/// `RBAC_MODEL.md` §5 is explicit that it must be "enforced by a database constraint rather than by
/// application logic alone", and the reason is that application logic has a gap by construction:
/// `bootstrap_master_key` checks for an existing master and then inserts, which two processes
/// starting together both pass. This test bypasses every guard in `src/api.rs` and writes straight to
/// the table, which is the only way to distinguish "the handlers refuse it" from "the database
/// refuses it".
#[tokio::test]
async fn attack_a_second_master_cannot_be_written_even_bypassing_the_api() {
    let db = setup_test_db().await;

    let _first = insert_master_key(&db, "The Master").await;

    let plaintext = simply_ip_vault::api::generate_random_key();
    let second = simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set("Usurper".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set("usurper1".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await;

    // Note what this insert does *not* contain: `master_marker`. It cannot — the field is not on the
    // entity, because the column is engine-generated. That absence is what makes this an adversarial
    // write rather than a cooperative one, and it is the exact shape that used to be accepted.
    let err = second
        .expect_err("the unique index over the derived master_marker must refuse a second master");
    assert!(
        format!("{err:?}").to_lowercase().contains("unique"),
        "the refusal must come from the uniqueness constraint, not from something incidental: {err:?}"
    );

    let masters = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(masters.len(), 1, "exactly one master survives the attempt");
}

/// The upgrade path: a database that predates §5 comes out the far side with its existing master
/// carrying the derived marker, and every other key carrying `NULL`.
///
/// Nothing backfills this — that is the point. The value is produced by the engine from `is_master`
/// the instant the generated column exists, so the assertion is about what the *schema* computes for
/// rows that were written long before it, not about what any migration remembered to write.
///
/// Migrations 1–6 run first, two keys are seeded as they would have existed before §5, then the rest
/// of the chain runs.
#[tokio::test]
async fn the_master_marker_migration_derives_the_marker_for_pre_existing_rows() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, Some(6)).await.unwrap();

    for (name, prefix, is_master) in
        [("Legacy Master", "legacy01", true), ("Legacy Daughter", "legacy02", false)]
    {
        let plaintext = simply_ip_vault::api::generate_random_key();
        db.execute_unprepared(&format!(
            // `x'...'` rather than a quoted string: SeaORM stores `Uuid` as a 16-byte BLOB on
            // SQLite, and a 36-character hyphenated literal fails to decode on read.
            "INSERT INTO api_keys (id, name, key_hash, prefix, bound_ips, is_master, \
             can_manage_keys, can_manage_webhooks, can_create_groups, created_at, updated_at) \
             VALUES (x'{}', '{name}', '{}', '{prefix}', NULL, {is_master}, true, true, true, \
              '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
            Uuid::new_v4().simple(),
            simply_ip_vault::api::hash_key(&plaintext),
        ))
        .await
        .unwrap();
    }

    migration::Migrator::up(&db, None).await.unwrap();

    // Read through raw SQL: the column is absent from `api_key::Model` by design, so the entity
    // cannot see it. That is the same reason no `INSERT` can name it.
    let rows = db
        .query_all_raw(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "SELECT name, master_marker FROM api_keys ORDER BY prefix".to_owned(),
        ))
        .await
        .unwrap();
    let derived: Vec<(String, Option<i32>)> = rows
        .iter()
        .map(|r| {
            (r.try_get::<String>("", "name").unwrap(), r.try_get("", "master_marker").unwrap())
        })
        .collect();
    assert_eq!(
        derived,
        vec![
            ("Legacy Master".to_owned(), Some(1)),
            ("Legacy Daughter".to_owned(), None)
        ],
        "the engine must derive 1 for the pre-existing master and NULL for everyone else — the NULL \
         half is what lets every non-master row coexist under the unique index"
    );
}

/// A database that already holds two masters stops the migration rather than being silently
/// resolved.
///
/// Demoting a key would strip an operator's authority without asking, and picking the "oldest" is a
/// guess dressed as a policy. Failing names the ids and the `UPDATE` that fixes it, which is
/// recoverable in one command — and the migration leaves the schema untouched, so a retry after the
/// fix starts from a clean state rather than a half-applied one.
#[tokio::test]
async fn the_master_marker_migration_refuses_a_database_with_two_masters() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, Some(6)).await.unwrap();

    for name in ["Master A", "Master B"] {
        let plaintext = simply_ip_vault::api::generate_random_key();
        db.execute_unprepared(&format!(
            "INSERT INTO api_keys (id, name, key_hash, prefix, bound_ips, is_master, \
             can_manage_keys, can_manage_webhooks, can_create_groups, created_at, updated_at) \
             VALUES (x'{}', '{name}', '{}', 'legacy01', NULL, true, true, true, true, \
              '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
            Uuid::new_v4().simple(),
            simply_ip_vault::api::hash_key(&plaintext),
        ))
        .await
        .unwrap();
    }

    let err = migration::Migrator::up(&db, None)
        .await
        .expect_err("two masters must stop the migration");
    let message = format!("{err}");
    assert!(
        message.contains("RBAC_MODEL.md §5") && message.contains("UPDATE api_keys"),
        "the failure must say what is wrong and how to fix it: {message}"
    );
    assert!(
        !message.contains("<unreadable id>"),
        "the offending ids must be legible — they are what the operator's UPDATE targets: {message}"
    );

    // Left exactly as found: the column was never added, so a retry after the operator's `UPDATE`
    // starts clean instead of hitting a half-applied schema.
    assert!(
        db.execute_unprepared("SELECT master_marker FROM api_keys").await.is_err(),
        "the column must not have been added before the check refused"
    );
}

/// The upgrade that has to cope with the damage: a database that reached `m20260807_000008` while
/// holding **two** masters must stop at `m20260808_000009` rather than crash into the unique index.
///
/// This state is not hypothetical, and that is why the test builds it the hard way instead of seeding
/// it. `m20260807_000007`'s marker was application-maintained, so any writer could set
/// `is_master = true` and leave the marker NULL — NULLs do not collide — and the second master was
/// accepted. Every deployment that ran the old chain could be sitting on exactly this today.
///
/// What the migration owes such an operator is a legible refusal: both rows named, and the `UPDATE`
/// that resolves it. Letting `CREATE UNIQUE INDEX` fail instead would surface a driver-level
/// constraint error naming an index, not the rows, and would do it after the column had already been
/// swapped — a half-applied schema on top of an ambiguous database.
#[tokio::test]
async fn the_derived_marker_migration_refuses_a_database_the_old_marker_let_through() {
    let db = Database::connect("sqlite::memory:").await.unwrap();

    // Through 000008 — the old, bypassable regime — with one legitimate master.
    migration::Migrator::up(&db, Some(6)).await.unwrap();
    let seed = |name: &str, prefix: &str| {
        format!(
            "INSERT INTO api_keys (id, name, key_hash, prefix, bound_ips, is_master, \
             can_manage_keys, can_manage_webhooks, can_create_groups, created_at, updated_at) \
             VALUES (x'{}', '{name}', '{}', '{prefix}', NULL, true, true, true, true, \
              '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
            Uuid::new_v4().simple(),
            simply_ip_vault::api::hash_key(&simply_ip_vault::api::generate_random_key()),
        )
    };
    db.execute_unprepared(&seed("Legitimate Master", "legit001")).await.unwrap();
    // `Some(2)` is two *further* migrations, not "up to number 2": `up` counts pending ones. That
    // lands exactly on 000008 — the last state before the marker became engine-derived.
    migration::Migrator::up(&db, Some(2)).await.unwrap();

    // The bypass itself, replayed: `is_master = true`, marker omitted. Under the old schema this is
    // simply accepted, which is the defect `m20260808_000009` exists to close.
    db.execute_unprepared(&seed("Usurper", "usurper1"))
        .await
        .expect("the old application-maintained marker accepts this — that is the bug");

    let err = migration::Migrator::up(&db, None)
        .await
        .expect_err("two masters must stop the migration rather than fail on the index");
    let message = format!("{err}");
    for expected in ["RBAC_MODEL.md §5", "UPDATE api_keys", "Legitimate Master", "Usurper"] {
        assert!(
            message.contains(expected),
            "the refusal must name both offending rows and the fix, missing {expected:?}: {message}"
        );
    }
    assert!(
        !message.contains("<unreadable id>"),
        "the offending ids must be legible — they are what the operator's UPDATE targets: {message}"
    );

    // Left as found: still the old plain column, not a half-swapped generated one. A retry after the
    // operator's `UPDATE` therefore starts from a coherent schema.
    let ddl = db
        .query_all_raw(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "SELECT sql FROM sqlite_master WHERE name = 'api_keys'".to_owned(),
        ))
        .await
        .unwrap();
    let ddl = ddl[0].try_get::<String>("", "sql").unwrap();
    assert!(
        !ddl.contains("GENERATED"),
        "the schema must be untouched when the migration refuses: {ddl}"
    );
}

/// Even the Master cannot mint a second Master through the API.
///
/// `attack_non_master_cannot_mint_a_master_key` covers the delegated caller. This covers the one
/// caller that used to be allowed: before §5, `guard_scope_elevation` returned `Ok` early for a
/// master, so `POST /api/keys` with `is_master: true` from the master produced a second master and
/// returned its plaintext in the response body.
#[tokio::test]
async fn attack_a_master_cannot_mint_a_second_master() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "The Master").await;
    let secret = test_signing_secret(&master);

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/keys")
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({ "name": "Co-Master", "is_master": true }).to_string(),
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST,
        "master status is bootstrap-only; no payload may carry the field, from any caller"
    );

    let masters = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(masters.len(), 1, "no second master row was written");
}

/// The Master key cannot be deleted through the API — by itself or by anyone else.
///
/// `RBAC_MODEL.md` §5: "The Master key cannot be deleted through the API. Regeneration is: delete the
/// row directly in the database; the service re-mints at next boot." The previous guards were both
/// *relative* — "not yourself" and "not by a non-master" — which together left the master deletable
/// by any other master, and the whole point of §5 is that there is no other master.
#[tokio::test]
async fn attack_the_master_key_cannot_be_deleted_through_the_api() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "The Master").await;
    let secret = test_signing_secret(&master);
    let master_id = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .id;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/keys/{master_id}"))
                .header("X-API-Key", &master),
        ),
        &secret,
        "",
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "the master key must not be deletable through the API"
    );

    assert!(
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(master_id)
            .one(&db)
            .await
            .unwrap()
            .is_some(),
        "the row is still there"
    );
}

/// `bound_ips` is the Master's *only* API-editable field, and every other one is refused.
///
/// §5 draws the line here rather than at "immutable" outright because a master locked to a network it
/// can no longer reach is unrecoverable without database access, and relocating an operator's own
/// admin network is a routine, non-escalating change. Renaming and re-scoping are neither routine nor
/// non-escalating, and rotation hands back a working master credential in the response body — so all
/// three are outside the API surface entirely.
#[tokio::test]
async fn master_may_edit_only_its_own_bound_ips() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "The Master").await;
    let secret = test_signing_secret(&master);
    let master_id = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .id;

    // Repeats below differ only in body, and two identical bodies inside one second would produce
    // the same signature — which the replay guard refuses for reasons unrelated to this test.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let call = |method: &'static str, path: String, body: String| {
        let (app, master, secret, tick) =
            (app.clone(), master.clone(), secret.clone(), tick.clone());
        async move {
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("X-API-Key", &master)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                &body,
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    let put = |body: serde_json::Value| call("PUT", format!("/api/keys/{master_id}"), body.to_string());

    // The permitted edit.
    assert_eq!(
        put(json!({ "bound_ips": "10.0.0.0/8" })).await,
        StatusCode::OK,
        "the master may edit its own bound_ips"
    );
    let after = simply_ip_vault::entities::prelude::ApiKey::find_by_id(master_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.bound_ips.as_deref(), Some("10.0.0.0/8"), "and the edit landed");

    // Everything else on the same endpoint.
    for field in ["name", "can_manage_keys", "can_manage_webhooks", "can_create_groups"] {
        let value = if field == "name" { json!("Renamed") } else { json!(false) };
        assert_eq!(
            put(json!({ field: value })).await,
            StatusCode::FORBIDDEN,
            "the master's '{field}' must not be editable through the API"
        );
    }

    // A payload mixing the one permitted field with a forbidden one is refused whole rather than
    // partially applied — otherwise "edit bound_ips" would become a carrier for the rest.
    assert_eq!(
        put(json!({ "bound_ips": "192.0.2.0/24", "name": "Sneaky" })).await,
        StatusCode::FORBIDDEN
    );

    // Both rotation endpoints, which §5 names explicitly.
    assert_eq!(
        call("POST", format!("/api/keys/{master_id}/rotate"), String::new()).await,
        StatusCode::FORBIDDEN,
        "rotating the master would return a working master credential in the response body"
    );
    assert_eq!(
        call("POST", format!("/api/keys/{master_id}/rotate-secret"), String::new()).await,
        StatusCode::FORBIDDEN,
        "re-keying the master's HMAC secret is equally out of the API surface"
    );

    // Nothing leaked through: the master is exactly as it was except for the one permitted field.
    let final_state = simply_ip_vault::entities::prelude::ApiKey::find_by_id(master_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_state.name, "The Master", "the name never changed");
    assert!(final_state.can_manage_keys && final_state.can_manage_webhooks);
    assert_eq!(final_state.key_hash, after.key_hash, "the credential never rotated");
    assert_eq!(
        final_state.bound_ips.as_deref(),
        Some("10.0.0.0/8"),
        "the rejected mixed payload did not apply its bound_ips half either"
    );
}

/// Rotating a key returns fresh credentials for it. Allowing that against a *master* key handed a
/// non-master complete, immediate takeover of the master credential — the single most direct
/// escalation path in the system.
///
/// The refusal moved from `403` to `404` when §4's visibility scoping landed, and that is a
/// **strengthening, not a regression**. `403` confirmed the id named a real key; the master is in no
/// non-master's subtree, so §4 requires it to answer exactly as a nonexistent id would. A `403` on
/// `POST /keys/{id}/rotate` was a way to enumerate the master key, which is precisely the oracle §4
/// closes. The credential-leak assertions below are unchanged and remain the point of the test.
#[tokio::test]
async fn attack_non_master_cannot_rotate_or_destroy_a_master_key() {
    let db = setup_test_db().await;
    let (app, manager, secret, manager_id, victim_id) = escalation_fixture(&db).await;

    let call = |method: &'static str, path: String, body: &'static str| {
        let (app, manager, secret) = (app.clone(), manager.clone(), secret.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method(method)
                        .uri(&path)
                        .header("X-API-Key", &manager)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                body,
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    // Full rotation — would have returned a working master API key *and* signing secret.
    let (status, body) = call("POST", format!("/api/keys/{victim_id}/rotate"), "").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-master rotated a master key");
    assert!(
        !body.contains("plaintext_key") && !body.contains("signing_secret"),
        "the rejection must not leak credentials, got {body}"
    );

    // Signing-secret-only rotation — same takeover, narrower blast radius.
    let (status, body) = call("POST", format!("/api/keys/{victim_id}/rotate-secret"), "").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-master rotated a master key's signing secret");
    assert!(!body.contains("signing_secret"), "the rejection must not leak a secret, got {body}");

    // Relocating a master key's network binding to the attacker's own range.
    let (status, _) = call(
        "PUT",
        format!("/api/keys/{victim_id}"),
        r#"{"bound_ips":"203.0.113.0/24"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-master rewrote a master key's bound_ips");

    // Removing the master keys that would otherwise contain the incident.
    let (status, _) = call("DELETE", format!("/api/keys/{victim_id}"), "").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-master deleted a master key");

    // The victim is untouched: still master, still holding its original signing secret.
    let victim = simply_ip_vault::entities::prelude::ApiKey::find_by_id(victim_id)
        .one(&db)
        .await
        .unwrap()
        .expect("the master key must still exist");
    assert!(victim.is_master);

    // Control: the same operations against a *non-master* target still succeed, so the guard is
    // scoped to master targets rather than having disabled key administration outright.
    let (other_id, _other) = insert_key(&db, "Ordinary", false, false, false, false, None).await;
    set_parent(&db, other_id, manager_id).await;
    let (status, _) = call("POST", format!("/api/keys/{other_id}/rotate"), "").await;
    assert_eq!(status, StatusCode::OK, "rotating a non-master key must still work");
    let (status, _) = call("DELETE", format!("/api/keys/{other_id}"), "").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "deleting a non-master key must still work");

    // ...and the caller can still rotate itself.
    let (status, _) = call("POST", format!("/api/keys/{manager_id}/rotate-secret"), "").await;
    assert_eq!(status, StatusCode::OK, "a key may still re-key itself");
}

/// A key must not be able to widen its own global scopes through the generic update endpoint.
#[tokio::test]
async fn attack_non_master_cannot_widen_its_own_scopes() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // Holds only `can_manage_keys`.
    let (self_id, key) = insert_key(&db, "Self Escalator", false, true, false, false, None).await;
    let secret = test_signing_secret(&key);

    let update = |target: Uuid, body: String| {
        let (app, key, secret) = (app.clone(), key.clone(), secret.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/api/keys/{target}"))
                        .header("X-API-Key", &key)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                &body,
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    assert_eq!(
        update(self_id, r#"{"can_manage_webhooks":true}"#.to_owned()).await,
        StatusCode::FORBIDDEN,
        "a key must not grant itself can_manage_webhooks"
    );
    assert_eq!(
        update(self_id, r#"{"can_create_groups":true}"#.to_owned()).await,
        StatusCode::FORBIDDEN,
        "a key must not grant itself can_create_groups"
    );

    // Narrowing its own scopes is not an escalation and stays allowed.
    assert_eq!(
        update(self_id, r#"{"can_manage_keys":false}"#.to_owned()).await,
        StatusCode::OK,
        "dropping a scope you already hold is not an escalation"
    );

    let after = simply_ip_vault::entities::prelude::ApiKey::find_by_id(self_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(!after.can_manage_webhooks && !after.can_create_groups, "no scope was widened");
}

// ─────────────────────────────────────────────────────────────
// Attack 7 — Self-granting and over-granting group permissions
// ─────────────────────────────────────────────────────────────

/// A caller must not be able to widen its own group access, nor hand out access it does not hold.
///
/// Without this, per-group RBAC was advisory: any `can_manage_keys` holder could grant itself — or a
/// second key it controls — full read/write/delete over every group in the system.
#[tokio::test]
async fn attack_cannot_self_grant_or_over_grant_group_permissions() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (caller_id, caller) = insert_key(&db, "Granter", false, true, false, false, None).await;
    let (accomplice_id, _accomplice) = insert_key(&db, "Accomplice", false, false, false, false, None).await;
    let secret = test_signing_secret(&caller);

    let own_group = insert_group(&db, "own-group").await;
    let foreign_group = insert_group(&db, "foreign-group").await;
    // The caller can read and write its own group, but cannot delete in it — and it administers the
    // group, which under R2 is what admits it to the grant path at all. Without `can_manage` every
    // assertion below would pass on the admission check rather than on the per-verb ceiling this test
    // is about, and the control at the end would fail.
    grant_manager(&db, caller_id, own_group, true, true, false).await;

    // `group_id` is a plain string (it doubles as a name), and all three verbs are required fields.
    let post = |target: Uuid, group: Uuid, read: bool, write: bool, del: bool| {
        let (app, caller, secret) = (app.clone(), caller.clone(), secret.clone());
        async move {
            let body = json!({
                "group_id": group.to_string(),
                "can_read": read,
                "can_write": write,
                "can_delete": del,
            });
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/keys/{target}/permissions"))
                        .header("X-API-Key", &caller)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                &body.to_string(),
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    // Self-targeting is bounded rather than blocked: the request is compared against the caller's
    // own row, which is the row being written, so it can never widen. Asking for `can_delete` — the
    // one verb the caller does not hold on its own group — is the escalation direction and fails.
    assert_eq!(
        post(caller_id, own_group, true, true, true).await,
        StatusCode::FORBIDDEN,
        "a key must not widen its own group permissions"
    );
    assert_eq!(
        post(caller_id, foreign_group, true, false, false).await,
        StatusCode::FORBIDDEN,
        "a key must not grant itself access to a group it cannot reach"
    );

    // Granting a third party access to a group the caller cannot reach is refused too — otherwise
    // the accomplice becomes a trivial proxy around the self-grant rule.
    assert_eq!(
        post(accomplice_id, foreign_group, true, false, false).await,
        StatusCode::FORBIDDEN,
        "a key must not delegate access to a group it has none on"
    );

    // Nor may it delegate a verb it does not hold on a group it *can* reach.
    assert_eq!(
        post(accomplice_id, own_group, true, true, true).await,
        StatusCode::FORBIDDEN,
        "a key holding read+write must not grant delete"
    );

    // Control: delegating exactly what it does hold is legitimate and still works.
    assert_eq!(
        post(accomplice_id, own_group, true, true, false).await,
        StatusCode::OK,
        "delegating permissions the caller holds must still work"
    );

    // The accomplice ended up with precisely the delegated verbs and nothing more.
    let perms = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(
            simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(accomplice_id),
        )
        .all(&db)
        .await
        .unwrap();
    assert_eq!(perms.len(), 1, "only the one legitimate grant landed");
    assert!(perms[0].can_read && perms[0].can_write && !perms[0].can_delete);

    // Last, because it mutates the caller's own row and everything above depends on it: reducing
    // your own access is permitted. It is the same authority the dedicated revoke endpoint confers,
    // reached through this one, and removing a verb cannot raise anyone above where they already
    // were — the caller least of all.
    assert_eq!(
        post(caller_id, own_group, true, false, false).await,
        StatusCode::OK,
        "a key may drop a verb from its own row on a group it manages"
    );
    let own = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(caller_id))
        .one(&db)
        .await
        .unwrap()
        .expect("the caller still has a row");
    assert!(own.can_read && !own.can_write, "the self-directed change was a genuine reduction");
}

// ─────────────────────────────────────────────────────────────
// Attack 8 — Webhook hijacking by repointing
// ─────────────────────────────────────────────────────────────

/// Repointing a webhook must invalidate the secret it signs with.
///
/// `secret_token` is write-only — no endpoint returns it — so an editor cannot read the secret
/// directly. The hijack is indirect: point the webhook at a server you control and wait, and the
/// next dispatch arrives at your endpoint carrying a valid `X-Signature-256` over a payload you
/// influenced, which is a working forgery oracle for the receiver's shared secret. Forcing rotation
/// on repoint means a secret is only ever usable against the destination it was configured for.
#[tokio::test]
async fn attack_repointing_a_webhook_forces_its_secret_to_rotate() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Hook Admin").await;
    let secret = test_signing_secret(&key);
    let group_id = insert_group(&db, "hijack-group").await;

    let original_secret = "original-webhook-secret-do-not-leak";
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
            "name": "Hijack Target",
            "target_url": "https://legitimate.example.com/hook",
            "secret_token": original_secret,
            "payload_template": "{}",
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
        })
        .to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created).unwrap();
    let hook_id = created["id"].as_str().unwrap().to_owned();

    let put = |body: serde_json::Value| {
        let (app, key, secret, hook_id) =
            (app.clone(), key.clone(), secret.clone(), hook_id.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/api/webhooks/{hook_id}"))
                        .header("X-API-Key", &key)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                &body.to_string(),
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
            (status, parsed)
        }
    };

    let stored_secret = |db: DatabaseConnection, hook_id: String| async move {
        let id: Uuid = hook_id.parse().unwrap();
        simply_ip_vault::entities::prelude::WebhookConfig::find_by_id(id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .secret_token
    };

    // A rename touches neither the URL nor the template, so the secret is left alone.
    let (status, body) = put(json!({ "name": "Renamed" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret_rotated"], false, "a rename must not churn the secret");
    assert_eq!(
        stored_secret(db.clone(), hook_id.clone()).await,
        original_secret,
        "the secret survives an unrelated edit"
    );

    // Re-submitting the identical URL is not a repoint — an idempotent PUT must not rotate.
    let (status, body) = put(json!({ "target_url": "https://legitimate.example.com/hook" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret_rotated"], false, "re-submitting the same URL is not a repoint");
    assert_eq!(stored_secret(db.clone(), hook_id.clone()).await, original_secret);

    // ── The attack: repoint at an attacker-controlled server. ──────────────
    let (status, body) = put(json!({ "target_url": "https://attacker.example.net/collect" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret_rotated"], true, "repointing must rotate the secret");

    let after_repoint = stored_secret(db.clone(), hook_id.clone()).await;
    assert_ne!(after_repoint, original_secret, "the old secret must not survive a repoint");
    assert_eq!(after_repoint.len(), 64, "the replacement is a full-width generated secret");

    // The new secret is disclosed exactly once, to the caller that caused the rotation...
    assert_eq!(
        body["secret_token"].as_str(),
        Some(after_repoint.as_str()),
        "the generated secret is returned once so the operator can reconfigure the receiver"
    );
    // ...and the *old* one is never echoed anywhere in that response.
    assert!(
        !body.to_string().contains(original_secret),
        "the pre-rotation secret must never appear in a response"
    );

    // Rewriting the template is treated the same way: it decides which bytes the signature covers,
    // so a caller who can rewrite it can make the existing secret vouch for content it never saw.
    let before_template_edit = stored_secret(db.clone(), hook_id.clone()).await;
    let (status, body) = put(json!({ "hmac_template": r"{method}\n{path}\n{timestamp}\n{body}\nx" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret_rotated"], true, "rewriting hmac_template must rotate the secret");
    assert_ne!(stored_secret(db.clone(), hook_id.clone()).await, before_template_edit);

    // A template that does not cover the body is still refused outright, rotation or not.
    let (status, _) = put(json!({ "hmac_template": r"{method}\n{path}\n{timestamp}" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a bodyless template is rejected on update too");

    // A caller supplying its own replacement gets no generated value echoed back.
    let (status, body) =
        put(json!({ "target_url": "https://elsewhere.example.com/h", "secret_token": "chosen-by-caller" }))
            .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret_rotated"], true);
    assert!(body["secret_token"].is_null(), "a caller-supplied secret is not echoed back");
    assert_eq!(stored_secret(db.clone(), hook_id.clone()).await, "chosen-by-caller");

    // No read endpoint ever discloses the secret, before or after rotation.
    let req = signed(
        inject_connect_info(Request::builder().uri("/api/webhooks").header("X-API-Key", &key)),
        &secret,
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    let listing = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let listing = String::from_utf8(listing.to_vec()).unwrap();
    assert!(!listing.contains(original_secret) && !listing.contains("chosen-by-caller"));
}

/// Webhook administration must be bounded by the caller's own group access.
///
/// A webhook is a standing export of everything that happens in its group, to a URL the creator
/// chooses. `can_manage_webhooks` alone let a key scoped to one group subscribe to *every* group's
/// events and stream them to a server it controls.
#[tokio::test]
async fn attack_webhook_admin_cannot_reach_groups_it_has_no_access_to() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Owner").await;
    let master_secret = test_signing_secret(&master);
    let (tenant_id, tenant) = insert_key(&db, "Tenant", false, false, true, false, None).await;
    let tenant_secret = test_signing_secret(&tenant);

    let own_group = insert_group(&db, "tenant-group").await;
    let foreign_group = insert_group(&db, "other-tenant-group").await;
    grant(&db, tenant_id, own_group, true, true, true).await;

    // The master seeds a webhook on the group the tenant cannot see.
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &master_secret,
        &json!({
            "name": "Foreign Hook",
            "target_url": "https://foreign.example.com/hook",
            "secret_token": "foreign-secret",
            "payload_template": "{}",
            "group_id": foreign_group.to_string(),
            "auth_mode": "CANONICAL_V1",
        })
        .to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created).unwrap();
    let foreign_hook_id = created["id"].as_str().unwrap().to_owned();

    let as_tenant = |method: &'static str, path: String, body: String| {
        let (app, tenant, tenant_secret) = (app.clone(), tenant.clone(), tenant_secret.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method(method)
                        .uri(&path)
                        .header("X-API-Key", &tenant)
                        .header("Content-Type", "application/json"),
                ),
                &tenant_secret,
                &body,
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    // Subscribing to a group it cannot read is refused.
    let exfil = json!({
        "name": "Exfiltrator",
        "target_url": "https://attacker.example.net/collect",
        "secret_token": "s",
        "payload_template": "{\"ip\":\"$target_address\"}",
        "group_id": foreign_group.to_string(),
        "auth_mode": "CANONICAL_V1",
    })
    .to_string();
    let (status, _) = as_tenant("POST", "/api/webhooks".to_owned(), exfil).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a tenant must not subscribe a webhook to another tenant's group"
    );

    // The foreign webhook is invisible in its listing...
    let (status, body) = as_tenant("GET", "/api/webhooks".to_owned(), String::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("Foreign Hook"), "listing leaked another group's webhook: {body}");
    assert!(!body.contains("foreign.example.com"), "listing leaked another group's target URL");

    // ...and neither editable nor deletable, reported as absent rather than forbidden.
    let (status, _) = as_tenant(
        "PUT",
        format!("/api/webhooks/{foreign_hook_id}"),
        r#"{"target_url":"https://attacker.example.net/collect"}"#.to_owned(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a tenant must not repoint another group's webhook");

    let (status, _) =
        as_tenant("DELETE", format!("/api/webhooks/{foreign_hook_id}"), String::new()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a tenant must not delete another group's webhook");

    // Control: on its own group everything still works.
    let own = json!({
        "name": "Own Hook",
        "target_url": "https://tenant.example.com/hook",
        "secret_token": "s",
        "payload_template": "{}",
        "group_id": own_group.to_string(),
        "auth_mode": "CANONICAL_V1",
    })
    .to_string();
    let (status, _) = as_tenant("POST", "/api/webhooks".to_owned(), own).await;
    assert_eq!(status, StatusCode::OK, "a tenant may still manage webhooks on its own group");
}

// ─────────────────────────────────────────────────────────────
// IP record soft delete, restore, hard delete, and 92-day purge
// ─────────────────────────────────────────────────────────────

/// Seeds an IP record in a group and returns its id.
async fn insert_ip_record(db: &DatabaseConnection, address: &str, group_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    simply_ip_vault::entities::ip_record::ActiveModel {
        id: Set(id),
        target_address: Set(address.to_owned()),
        cause: Set(Some("seeded".to_owned())),
        is_locked: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(db)
    .await
    .unwrap();

    simply_ip_vault::entities::ip_record_group_membership::ActiveModel {
        ip_record_id: Set(id),
        group_id: Set(group_id),
    }
    .insert(db)
    .await
    .unwrap();

    id
}

/// Reads a record straight from the database, bypassing every API-level filter.
async fn raw_record(
    db: &DatabaseConnection,
    id: Uuid,
) -> Option<simply_ip_vault::entities::ip_record::Model> {
    simply_ip_vault::entities::prelude::IpRecord::find_by_id(id).one(db).await.unwrap()
}

/// A non-master's delete must hide the record without destroying it.
///
/// The two halves are equally important and are asserted separately: the API must stop returning
/// it (otherwise "delete" did nothing observable) *and* the row must survive with its attribution
/// intact (otherwise it is an ordinary delete wearing a different name, and nothing is recoverable).
#[tokio::test]
async fn non_master_delete_is_soft_and_hides_the_record_without_dropping_the_row() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (deleter_id, deleter) = insert_key(&db, "Deleter", false, false, false, false, None).await;
    let secret = test_signing_secret(&deleter);
    let group_id = insert_group(&db, "soft-delete-group").await;
    grant(&db, deleter_id, group_id, true, true, true).await;

    let record_id = insert_ip_record(&db, "198.51.100.10", group_id).await;

    // Visible before the delete.
    let req = signed(
        inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &deleter)),
        &secret,
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8(body.to_vec()).unwrap().contains("198.51.100.10"));

    // Delete.
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/ips/{record_id}"))
                .header("X-API-Key", &deleter),
        ),
        &secret,
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["deleted"], "soft", "a non-master delete must be soft");

    // Half one: the row is still there, flagged and attributed.
    let row = raw_record(&db, record_id).await.expect("the row must survive a soft delete");
    assert!(row.is_deleted, "is_deleted must be set");
    assert!(row.deleted_at.is_some(), "deleted_at must be stamped");
    assert_eq!(
        row.deleted_by.as_deref(),
        Some(deleter_id.to_string().as_str()),
        "deleted_by must attribute the acting key"
    );
    assert_eq!(row.target_address, "198.51.100.10", "the record's data is untouched");

    // Half two: it is gone from every read the caller has. Each listing gets its own timestamp —
    // the three paths differ, but the loop also runs after earlier calls in this test and a repeat
    // would otherwise collide with one of them.
    for (offset, path) in
        ["/api/ips", "/api/ips?format=iplist", "/api/ips?include_deleted=true"].iter().enumerate()
    {
        let req = signed_later(
            inject_connect_info(Request::builder().uri(*path).header("X-API-Key", &deleter)),
            &secret,
            // +1: the plain `/api/ips` listing was already issued above, before the delete.
            offset as i64 + 1,
            "",
        );
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            !text.contains("198.51.100.10"),
            "{path} must not expose a soft-deleted record to a non-master (got {text})"
        );
    }

    // A non-master cannot escalate to a hard delete by asking for one.
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/ips/{record_id}?hard=true"))
                .header("X-API-Key", &deleter),
        ),
        &secret,
        "",
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "hard delete must be master-only"
    );
    assert!(raw_record(&db, record_id).await.is_some(), "the row must still be there");
}

/// A key with no delete permission on any of the record's groups cannot delete it at all.
#[tokio::test]
async fn deleting_a_record_requires_delete_permission_on_one_of_its_groups() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (reader_id, reader) = insert_key(&db, "Reader", false, false, false, false, None).await;
    let secret = test_signing_secret(&reader);
    let group_id = insert_group(&db, "read-only-group").await;
    // Read and write, but explicitly NOT delete.
    grant(&db, reader_id, group_id, true, true, false).await;

    let record_id = insert_ip_record(&db, "198.51.100.20", group_id).await;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/ips/{record_id}"))
                .header("X-API-Key", &reader),
        ),
        &secret,
        "",
    );
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    let row = raw_record(&db, record_id).await.expect("row survives");
    assert!(!row.is_deleted, "a rejected delete must not have flagged the record");
}

/// The master's side of the trash: see it, restore it, or destroy it for good.
#[tokio::test]
async fn master_can_view_restore_and_hard_delete_soft_deleted_records() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Trash Admin").await;
    let secret = test_signing_secret(&master);
    let group_id = insert_group(&db, "trash-group").await;
    let record_id = insert_ip_record(&db, "198.51.100.30", group_id).await;

    // Some calls below repeat verbatim, so each takes its own timestamp — an identical repeat
    // inside one second is the same signature, which is exactly what a replay is.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let call = |method: &'static str, path: String| {
        let (app, master, secret, tick) =
            (app.clone(), master.clone(), secret.clone(), tick.clone());
        async move {
            let req = signed_later(
                inject_connect_info(
                    Request::builder().method(method).uri(&path).header("X-API-Key", &master),
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                "",
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    let (status, _) = call("DELETE", format!("/api/ips/{record_id}")).await;
    assert_eq!(status, StatusCode::OK);

    // Hidden from the default listing even for a master — the trash is opt-in, so a master's
    // ordinary view is not silently different from everyone else's.
    let (_, body) = call("GET", "/api/ips".to_owned()).await;
    assert!(!body.contains("198.51.100.30"), "the default listing hides deleted records");

    // ...and visible with the explicit flag.
    let (status, body) = call("GET", "/api/ips?include_deleted=true".to_owned()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("198.51.100.30"), "include_deleted must surface the trash");
    let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let row = listed.as_array().unwrap().iter().find(|r| r["target_address"] == "198.51.100.30").unwrap();
    assert_eq!(row["is_deleted"], true, "the trash view reports the flag");
    assert!(row["deleted_at"].is_string(), "and when it happened");

    // Restore.
    let (status, body) = call("POST", format!("/api/ips/{record_id}/restore")).await;
    assert_eq!(status, StatusCode::OK, "master restore must succeed");
    assert!(body.contains("\"restored\":true"));

    let row = raw_record(&db, record_id).await.expect("row exists");
    assert!(!row.is_deleted, "restore clears the flag");
    assert!(row.deleted_at.is_none(), "restore clears deleted_at");
    assert!(row.deleted_by.is_none(), "restore clears deleted_by");

    // Back in the normal listing.
    let (_, body) = call("GET", "/api/ips".to_owned()).await;
    assert!(body.contains("198.51.100.30"), "a restored record is visible again");

    // Restoring a live record is a no-op error, not a silent success.
    let (status, _) = call("POST", format!("/api/ips/{record_id}/restore")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "nothing to restore");

    // Hard delete really removes the row.
    let (status, body) = call("DELETE", format!("/api/ips/{record_id}?hard=true")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("permanent"));
    assert!(raw_record(&db, record_id).await.is_none(), "hard delete drops the row");
}

/// Restore is master-only: recovering from a careless or compromised key must not depend on that
/// same key's authority.
#[tokio::test]
async fn restore_and_purge_are_master_only() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // Every delegated scope short of master.
    let (id, delegated) = insert_key(&db, "Delegated", false, true, true, true, None).await;
    let secret = test_signing_secret(&delegated);
    let group_id = insert_group(&db, "perm-group").await;
    grant(&db, id, group_id, true, true, true).await;
    let record_id = insert_ip_record(&db, "198.51.100.40", group_id).await;

    let post = |path: String| {
        let (app, delegated, secret) = (app.clone(), delegated.clone(), secret.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri(&path)
                        .header("X-API-Key", &delegated)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                "",
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    assert_eq!(post(format!("/api/ips/{record_id}/restore")).await, StatusCode::FORBIDDEN);
    assert_eq!(post("/api/system/purge-ips".to_owned()).await, StatusCode::FORBIDDEN);
}

/// The purge drops records past the retention window and keeps everything else.
///
/// Three records with deliberately chosen ages pin the boundary: one well past 92 days (purged),
/// one just inside it (kept), and one live-but-old (kept, because it was never deleted). The last
/// is the important one — a purge that filtered on `deleted_at` alone without also checking
/// `is_deleted` would destroy restored records that kept an old timestamp.
#[tokio::test]
async fn purge_removes_only_records_past_the_92_day_retention_window() {
    use simply_ip_vault::retention::{purge_expired_ip_records, DEFAULT_RETENTION_DAYS};

    let db = setup_test_db().await;
    let group_id = insert_group(&db, "purge-group").await;

    let expired = insert_ip_record(&db, "203.0.113.1", group_id).await;
    let recent = insert_ip_record(&db, "203.0.113.2", group_id).await;
    let live = insert_ip_record(&db, "203.0.113.3", group_id).await;

    let age = |days: i64| (chrono::Utc::now() - chrono::Duration::days(days)).naive_utc();

    let mark_deleted = |id: Uuid, at: chrono::NaiveDateTime, deleted: bool| {
        let db = db.clone();
        async move {
            let record = raw_record(&db, id).await.unwrap();
            let mut active: simply_ip_vault::entities::ip_record::ActiveModel = record.into();
            active.is_deleted = Set(deleted);
            active.deleted_at = Set(Some(at));
            active.update(&db).await.unwrap();
        }
    };

    mark_deleted(expired, age(DEFAULT_RETENTION_DAYS + 1), true).await;
    mark_deleted(recent, age(DEFAULT_RETENTION_DAYS - 1), true).await;
    // Deleted long ago, then restored: `is_deleted` is false but the stale timestamp remains.
    mark_deleted(live, age(DEFAULT_RETENTION_DAYS + 365), false).await;

    let purged = purge_expired_ip_records(&db, DEFAULT_RETENTION_DAYS).await.unwrap();
    assert_eq!(purged, 1, "exactly the one aged-out record is purged");

    assert!(raw_record(&db, expired).await.is_none(), "the aged-out record is gone");
    assert!(raw_record(&db, recent).await.is_some(), "a record inside the window is kept");
    assert!(
        raw_record(&db, live).await.is_some(),
        "a restored record must survive regardless of its stale deleted_at"
    );

    // Cascade: the purged record's group membership went with it, leaving no orphan junction row.
    let orphans = simply_ip_vault::entities::prelude::IpRecordGroupMembership::find()
        .filter(
            simply_ip_vault::entities::ip_record_group_membership::Column::IpRecordId.eq(expired),
        )
        .all(&db)
        .await
        .unwrap();
    assert!(orphans.is_empty(), "cascade removed the membership rows");

    // A retention window of 0 disables purging entirely rather than meaning "purge everything".
    assert_eq!(purge_expired_ip_records(&db, 0).await.unwrap(), 0);
    assert_eq!(purge_expired_ip_records(&db, -1).await.unwrap(), 0);
    assert!(raw_record(&db, recent).await.is_some(), "nothing was destroyed by the disabled sweep");
}

/// The master-only purge endpoint runs the same sweep and reports what it removed.
#[tokio::test]
async fn purge_endpoint_reports_the_number_of_records_removed() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Purger").await;
    let secret = test_signing_secret(&master);
    let group_id = insert_group(&db, "endpoint-purge-group").await;
    let old = insert_ip_record(&db, "203.0.113.50", group_id).await;

    let record = raw_record(&db, old).await.unwrap();
    let mut active: simply_ip_vault::entities::ip_record::ActiveModel = record.into();
    active.is_deleted = Set(true);
    active.deleted_at = Set(Some((chrono::Utc::now() - chrono::Duration::days(200)).naive_utc()));
    active.update(&db).await.unwrap();

    // Some calls below repeat verbatim, so each takes its own timestamp — an identical repeat
    // inside one second is the same signature, which is exactly what a replay is.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let purge = |body: &'static str| {
        let (app, master, secret, tick) =
            (app.clone(), master.clone(), secret.clone(), tick.clone());
        async move {
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri("/api/system/purge-ips")
                        .header("X-API-Key", &master)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                body,
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    // `older_than_days: 0` would read as "purge everything" — rejected rather than obeyed, because
    // the destructive reading must never be what a typo selects.
    let (status, _) = purge(r#"{"older_than_days":0}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = purge(r#"{"older_than_days":-5}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(raw_record(&db, old).await.is_some(), "the rejected purges destroyed nothing");

    // An empty body uses the configured 92-day default.
    let (status, body) = purge("").await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["purged"], 1);
    assert_eq!(parsed["retention_days"], 92, "the default window is 92 days");
    assert!(raw_record(&db, old).await.is_none());

    // A second sweep finds nothing left.
    let (_, body) = purge("").await;
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["purged"], 0);
}

/// Re-banning a soft-deleted address must resurrect it rather than colliding with the unique
/// index. Otherwise an address someone deleted could never be banned again until a master emptied
/// the trash — a delete would be a denial of service on that address.
#[tokio::test]
async fn re_registering_a_soft_deleted_address_restores_it() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Rebanner").await;
    let secret = test_signing_secret(&master);
    let group_id = insert_group(&db, "reban-group").await;
    let record_id = insert_ip_record(&db, "203.0.113.77", group_id).await;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/ips/{record_id}"))
                .header("X-API-Key", &master),
        ),
        &secret,
        "",
    );
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    assert!(raw_record(&db, record_id).await.unwrap().is_deleted);

    // Ban the same address again.
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({
            "target_address": "203.0.113.77",
            "group_name": "reban-group",
            "cause": "seen again",
        })
        .to_string(),
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "re-banning a soft-deleted address must succeed, not collide with the unique index"
    );

    let row = raw_record(&db, record_id).await.expect("the same row is reused");
    assert!(!row.is_deleted, "re-registration clears the deleted flag");
    assert!(row.deleted_at.is_none(), "...and the retention clock");
    assert!(row.deleted_by.is_none(), "...and the attribution");
    assert_eq!(row.cause.as_deref(), Some("seen again"), "the new cause was applied");
}

// ─────────────────────────────────────────────────────────────
// Convergence — anti-replay, pipeline ordering, full-URI signing, memory bounds
//
// These cover the arbitrated decisions of the cross-service convergence pass. Each one exists
// because the property it asserts is invisible in normal use and would regress silently.
// ─────────────────────────────────────────────────────────────

/// **Replay.** An intercepted, validly-signed request resent verbatim inside the freshness window
/// must be rejected.
///
/// This is the gap a timestamp check alone cannot close. The window bounds how *long* a captured
/// request stays usable; it says nothing about using it *twice*. Every field the signature covers —
/// method, target, timestamp, body — is unchanged in a replay, so the HMAC verifies perfectly and
/// the freshness check passes. Only a record of what has already been accepted can tell the two
/// apart.
///
/// The scenario is concrete rather than theoretical: `simply_ip_vault` is normally reached over
/// plain HTTP on a LAN, so an authentic `POST /api/ban` is readable by anything on the path, and
/// replaying it repeats the side effect for the next 300 seconds.
#[tokio::test]
async fn an_intercepted_signed_request_cannot_be_replayed_within_the_window() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_id, master) = insert_key(&db, "Master", true, true, true, true, None).await;
    let secret = test_signing_secret(&master);

    // One authentic request, captured on the wire. Building it once and cloning the parts is the
    // point: the attacker resends the *same bytes*, not a re-signed equivalent.
    let timestamp = chrono::Utc::now().timestamp();
    let body = json!({ "target_address": "203.0.113.200", "group_name": "replay-group" }).to_string();
    let build = || {
        signed_at(
            inject_connect_info(
                Request::builder()
                    .method("POST")
                    .uri("/api/ban")
                    .header("X-API-Key", &master)
                    .header("Content-Type", "application/json"),
            ),
            &secret,
            timestamp,
            &body,
        )
    };

    assert_eq!(
        app.clone().oneshot(build()).await.unwrap().status(),
        StatusCode::OK,
        "the genuine request must succeed"
    );

    let res = app.clone().oneshot(build()).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "a byte-identical resend inside the window is a replay and must be refused"
    );
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        text.contains("already been used"),
        "the rejection must name replay, not look like a signature failure: {text}"
    );

    // A third attempt is refused too — the guard is not a one-shot latch that clears itself.
    assert_eq!(
        app.clone().oneshot(build()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    // ...while a *freshly signed* request from the same key is unaffected, so the guard rejects
    // replays rather than simply breaking the key after one use.
    let fresh = signed_at(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        timestamp + 1,
        &body,
    );
    assert_eq!(app.clone().oneshot(fresh).await.unwrap().status(), StatusCode::OK);
}

/// A replay of one key's request must not consume another key's identical signature, and vice
/// versa — the guard is keyed per API key, not globally.
#[tokio::test]
async fn replay_tracking_is_scoped_per_key() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // Ordinary keys: replay tracking is keyed on identity, not on scope, and only one master may
    // exist per database (RBAC_MODEL.md §5). `GET /api/ips` answers `200` with an empty list for a
    // key holding no grants, which is all this test needs from it.
    let (_a, first) = insert_key(&db, "First", false, false, false, false, None).await;
    let (_b, second) = insert_key(&db, "Second", false, false, false, false, None).await;
    let timestamp = chrono::Utc::now().timestamp();

    for key in [&first, &second] {
        let req = signed_at(
            inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", key)),
            &test_signing_secret(key),
            timestamp,
            "",
        );
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::OK,
            "each key's first use of its own signature must succeed"
        );
    }
}

/// **Auth before authz.** A caller that cannot prove possession of the signing secret must not be
/// able to tell "this key does not exist" from "this key exists but your address is not allowed".
///
/// If `bound_ips` were checked before the HMAC, the `403`-vs-`401` split would turn key guessing
/// into key *mapping*: an attacker could enumerate identifiers and learn which ones are real, and
/// even which networks they are pinned to, without ever holding a secret. Both shapes must return
/// `401` until the signature verifies.
#[tokio::test]
async fn an_unauthenticated_caller_cannot_distinguish_a_missing_key_from_a_blocked_address() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // A key that genuinely exists, bound to a network the test connection is *not* in.
    let (_id, bound) =
        insert_key(&db, "Bound", true, true, true, true, Some("10.99.0.0/16")).await;

    let probe = |key: String, offset: i64| {
        let app = app.clone();
        async move {
            // Deliberately the *wrong* secret: this models an attacker holding (or guessing) an
            // identifier but not the secret behind it.
            let req = signed_later(
                inject_connect_info(Request::builder().uri("/api/auth/me").header("X-API-Key", &key)),
                "not-the-real-signing-secret",
                offset,
                "",
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    let nonexistent = probe("this-key-does-not-exist-at-all".to_owned(), 0).await;
    let real_but_out_of_range = probe(bound.clone(), 1).await;

    assert_eq!(nonexistent, StatusCode::UNAUTHORIZED);
    assert_eq!(
        real_but_out_of_range,
        StatusCode::UNAUTHORIZED,
        "a real key whose CIDR excludes the caller must also be 401 while the signature is unproven \
         — a 403 here would confirm the key exists"
    );
    assert_eq!(nonexistent, real_but_out_of_range, "the two must be indistinguishable");

    // ...and once the signature *does* verify, the CIDR check runs and reports 403, proving the
    // ordering is a deliberate sequence rather than the network check having been dropped.
    let authenticated = signed(
        inject_connect_info(Request::builder().uri("/api/auth/me").header("X-API-Key", &bound)),
        &test_signing_secret(&bound),
        "",
    );
    assert_eq!(
        app.clone().oneshot(authenticated).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "an authenticated caller outside its bound network gets 403"
    );
}

/// **Full-URI signing.** Rewriting the query string of an otherwise-valid signed request must
/// invalidate it.
///
/// The concrete attack: `?hard=true` turns a reversible soft delete into an irreversible purge, and
/// `?include_deleted=true` widens a listing to the trash view. While the query sat outside the
/// signed material, an on-path attacker who could not forge a signature could still rewrite a
/// captured request into either — no secret required.
#[tokio::test]
async fn tampering_with_the_query_string_invalidates_the_signature() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_id, master) = insert_key(&db, "Master", true, true, true, true, None).await;
    let secret = test_signing_secret(&master);
    let group_id = insert_group(&db, "tamper-group").await;
    let record_id = insert_ip_record(&db, "198.51.100.77", group_id).await;
    let timestamp = chrono::Utc::now().timestamp();

    // Signed for the plain path...
    let honest = crypto::compute_signature(
        &secret,
        "DELETE",
        &format!("/api/ips/{record_id}"),
        &timestamp.to_string(),
        b"",
    )
    .expect("signing succeeds");

    // ...but sent with `?hard=true` bolted on, exactly as a proxy-level attacker would.
    let tampered = inject_connect_info(
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/ips/{record_id}?hard=true"))
            .header("X-API-Key", &master)
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", &honest),
    )
    .body(Body::empty())
    .expect("request builds");

    assert_eq!(
        app.clone().oneshot(tampered).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "a query string appended after signing must break the signature"
    );
    assert!(
        raw_record(&db, record_id).await.is_some(),
        "the record must survive the rejected escalation"
    );

    // The honest request still works, so the rejection above is about the tampering and not about
    // the route being broken.
    let honest_req = inject_connect_info(
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/ips/{record_id}"))
            .header("X-API-Key", &master)
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", &honest),
    )
    .body(Body::empty())
    .expect("request builds");
    assert_eq!(app.clone().oneshot(honest_req).await.unwrap().status(), StatusCode::OK);

    // Symmetrically: a signature computed *with* the query is not valid without it, so an attacker
    // cannot strip a parameter either.
    let with_query = crypto::compute_signature(
        &secret,
        "GET",
        "/api/ips?include_deleted=true",
        &timestamp.to_string(),
        b"",
    )
    .expect("signing succeeds");
    let stripped = inject_connect_info(
        Request::builder()
            .uri("/api/ips")
            .header("X-API-Key", &master)
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", &with_query),
    )
    .body(Body::empty())
    .expect("request builds");
    assert_eq!(
        app.clone().oneshot(stripped).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "removing a signed query parameter must also break the signature"
    );
}

/// A legitimate request that *carries* a query string still authenticates, so the change above did
/// not simply break every filtered read.
#[tokio::test]
async fn a_correctly_signed_query_string_authenticates() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_id, master) = insert_key(&db, "Master", true, true, true, true, None).await;
    let secret = test_signing_secret(&master);

    for (offset, path) in [
        "/api/ips?limit=5",
        "/api/ips?groups=a,b&limit=10&offset=0",
        "/api/ips?include_deleted=true",
        "/api/ips?ip=203.0&cause=ssh",
    ]
    .iter()
    .enumerate()
    {
        let req = signed_later(
            inject_connect_info(Request::builder().uri(*path).header("X-API-Key", &master)),
            &secret,
            offset as i64,
            "",
        );
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::OK,
            "{path} signed over its full target must authenticate"
        );
    }
}

/// **Memory bound.** The router-wide limit and the middleware's signature buffer are the same
/// number, so no body size is accepted by one layer and refused by the other.
///
/// Asserted on the constants rather than by pushing 3 MiB through the stack: the property that
/// matters is that the two cannot drift, and a size-based test would pass just as well with two
/// independently-chosen values that happen to agree today.
#[test]
fn the_body_limit_and_the_signature_buffer_are_one_constant() {
    assert_eq!(
        simply_ip_vault::MAX_REQUEST_BODY_BYTES,
        3 * 1024 * 1024,
        "the converged limit is 3 MiB"
    );
}

/// A body over the router-wide limit is refused before it can be buffered.
#[tokio::test]
async fn an_oversized_body_is_rejected_rather_than_buffered() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_id, master) = insert_key(&db, "Master", true, true, true, true, None).await;
    let secret = test_signing_secret(&master);

    let oversized = "x".repeat(simply_ip_vault::MAX_REQUEST_BODY_BYTES + 1024);
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &oversized,
    );

    let status = app.clone().oneshot(req).await.unwrap().status();
    assert!(
        status == StatusCode::PAYLOAD_TOO_LARGE || status == StatusCode::BAD_REQUEST,
        "an over-limit body must be refused, got {status}"
    );
}

/// **Pragma resilience.** `apply_sqlite_pragmas` must never be able to stop the service, whatever
/// the database says.
///
/// An in-memory database is the case that actually occurs — it reports `journal_mode=memory` and
/// declines WAL silently — and it is what the entire test suite runs on. A version of this function
/// that propagated the outcome would take down every deployment on a read-only mount or a
/// filesystem without shared-memory support, trading a real outage for a concurrency setting that
/// did not apply.
#[tokio::test]
async fn sqlite_pragma_failures_never_stop_the_service() {
    let db = setup_test_db().await;

    // Returns unit: there is no error channel to propagate, by construction. Calling it twice also
    // proves it is idempotent, since it runs before migrations on every boot.
    simply_ip_vault::state::apply_sqlite_pragmas(&db).await;
    simply_ip_vault::state::apply_sqlite_pragmas(&db).await;

    // The database is still fully usable afterwards.
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));
    let (_id, master) = insert_key(&db, "Master", true, true, true, true, None).await;
    let req = signed(
        inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &master)),
        &test_signing_secret(&master),
        "",
    );
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// **WAL actually engages, and persists.** The pragma resilience test above proves only that a
/// failure is survivable — and it runs on `sqlite::memory:`, where WAL legitimately *cannot* engage.
/// So on its own it would pass unchanged if `apply_sqlite_pragmas` stopped issuing the pragma
/// altogether, which is exactly the regression it looks like it is guarding against.
///
/// This one uses a real file, which is the only place the setting can take effect, and asserts the
/// two properties the production reasoning depends on:
///
/// 1. `journal_mode` is genuinely `wal` and `busy_timeout` is genuinely 5000 after the call.
/// 2. **WAL survives reconnection.** It is recorded in the database file header rather than being
///    connection state, which is what makes applying it once at startup sufficient for every
///    connection the pool opens later — and for every subsequent run of the service. If that were
///    not true, a single pooled connection would be the only one benefiting and the whole
///    "apply once at boot" design would be wrong.
#[tokio::test]
async fn wal_engages_on_a_file_backed_database_and_survives_reconnection() {
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};

    async fn pragma<T>(db: &sea_orm::DatabaseConnection, sql: &str, column: &str) -> T
    where
        T: sea_orm::TryGetable,
    {
        db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, sql.to_owned()))
            .await
            .expect("pragma query succeeds")
            .expect("pragma returns a row")
            .try_get::<T>("", column)
            .expect("pragma column has the expected type")
    }

    // `tempfile` rather than a fixed path: the suite runs tests in parallel, and two of them sharing
    // one database file would produce exactly the lock contention this pragma exists to avoid.
    let dir = tempfile::tempdir().expect("temp dir is creatable");
    let path = dir.path().join("wal_probe.db");
    let url = format!("sqlite://{}?mode=rwc", path.display());

    let db = Database::connect(&url).await.expect("file-backed sqlite opens");
    simply_ip_vault::state::apply_sqlite_pragmas(&db).await;

    let mode: String = pragma(&db, "PRAGMA journal_mode;", "journal_mode").await;
    assert_eq!(
        mode.to_ascii_lowercase(),
        "wal",
        "WAL must be in force on a file-backed database, got {mode:?}"
    );

    let timeout: i32 = pragma(&db, "PRAGMA busy_timeout;", "timeout").await;
    assert_eq!(timeout, 5000, "the busy timeout must be the configured 5000ms");

    // Migrations still run against the WAL database, so the setting is not merely reported but
    // actually usable for the writes the service performs at boot.
    simply_ip_vault::migration::Migrator::up(&db, None).await.expect("migrations run under WAL");

    // Reconnect with a completely fresh pool. Nothing re-applies the pragma here — if WAL were
    // connection state rather than file state, this would come back `delete`.
    drop(db);
    let reopened = Database::connect(&url).await.expect("file-backed sqlite reopens");
    let inherited: String = pragma(&reopened, "PRAGMA journal_mode;", "journal_mode").await;
    assert_eq!(
        inherited.to_ascii_lowercase(),
        "wal",
        "WAL is written to the file header and must survive reconnection, got {inherited:?}"
    );

    drop(reopened);
}

/// **Stored secrets are opened strictly, or not at all.** A value carrying no recognized prefix is a
/// `MalformedCiphertext` error, never a bare secret handed back verbatim.
///
/// The removed fallback looked like backward compatibility and behaved like a silent failure. "No
/// recognized prefix" is not evidence of a pre-prefix row; it is evidence of nothing, and the other
/// causes are all worse. A `v1.plain.` value whose prefix was lost to a botched migration or a
/// truncated column would have had its surviving hex text used as HMAC key material — turning a
/// damaged row into a fleet of `401`s that point at the client instead of at the database.
#[test]
fn a_stored_secret_without_a_recognized_prefix_is_refused() {
    use simply_ip_vault::crypto::{CryptoError, SecretCipher};

    let key = "00".repeat(32);
    for cipher in [
        SecretCipher::Plaintext,
        SecretCipher::from_hex_key(&key).expect("a 64-hex key is valid"),
    ] {
        for unprefixed in [
            "signing-secret-for-legacy-key",       // the shape the old fallback accepted
            "",                                    // an empty column
            "deadbeef",                            // bare hex, indistinguishable from a stripped body
            "v1.plain",                            // the prefix, truncated just short of its dot
            "v1.xchacha20poly1305",                // likewise
            "V1.PLAIN.6162",                       // prefixes are matched exactly, not case-folded
            // The retired AES-GCM shape, spelled exactly as the old writer produced it: a 12-byte
            // hex nonce followed by hex ciphertext‖tag. Reinstating the read path would make this
            // value open again, which is the regression this entry exists to catch.
            "aesgcm256:000102030405060708090a0b1122334455667788990011223344556677",
            "aesgcm256",                           // and the bare prefix
        ] {
            assert!(
                matches!(cipher.open(unprefixed), Err(CryptoError::MalformedCiphertext)),
                "{unprefixed:?} must be refused rather than returned as a signing secret"
            );
        }

        // ...while a correctly-prefixed value still round-trips, so the loop above is not passing
        // simply because `open` rejects everything.
        let sealed = cipher.seal("real-secret").expect("sealing succeeds");
        assert_eq!(cipher.open(&sealed).expect("opening succeeds"), "real-secret");
    }
}

/// The end-to-end consequence of the rule above: a key whose stored secret is unreadable cannot
/// authenticate, and fails as an operator problem (`500`) rather than as a caller problem (`401`).
///
/// The distinction matters operationally. `401` tells an operator to go and look at the client, which
/// is the one place the fault is not. `500` plus the row's prefix in the log points at the database.
#[tokio::test]
async fn a_key_whose_stored_secret_is_unreadable_cannot_authenticate() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (id, plaintext) = insert_key(&db, "Damaged", true, true, true, true, None).await;

    // Simulate a row whose storage prefix was lost — a truncated column, a bad restore, a migration
    // that rewrote the value without re-sealing it.
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(id),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        ..Default::default()
    }
    .update(&db)
    .await
    .expect("row updates");

    let req = signed(
        inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &plaintext)),
        &test_signing_secret(&plaintext),
        "",
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "an unreadable stored secret is an operator fault, not a failed authentication attempt"
    );
}

/// **Cipher fail-closed.** A malformed encryption key must abort startup rather than silently
/// downgrading to storing signing secrets in the clear.
///
/// The old behaviour accepted any string and SHA-256'd it, so `VAULT_ENCRYPTION_KEY=password`
/// produced a 32-byte key with the entropy of "password" and no signal that anything was wrong.
/// Refusing is the only honest option: an operator who set the variable believes their secrets are
/// encrypted.
#[test]
fn a_malformed_encryption_key_fails_closed_instead_of_degrading() {
    use simply_ip_vault::crypto::{CryptoError, SecretCipher};

    for bad in ["password", "", "deadbeef", "not hex at all", &"00".repeat(31), &"00".repeat(33)] {
        assert!(
            matches!(SecretCipher::from_hex_key(bad), Err(CryptoError::InvalidKey)),
            "{bad:?} must be refused, never accepted as key material"
        );
    }

    // A real key is accepted and actually encrypts.
    let good = SecretCipher::from_hex_key(&"ab".repeat(32)).expect("64 hex characters are valid");
    assert!(good.is_encrypting());
    let sealed = good.seal("round-trip").expect("sealing succeeds");
    assert!(sealed.starts_with("v1.xchacha20poly1305."), "got {sealed}");
    assert!(!sealed.contains("round-trip"), "the plaintext must not survive");
    assert_eq!(good.open(&sealed).expect("opening succeeds"), "round-trip");
}
