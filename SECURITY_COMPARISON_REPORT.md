# Security Comparison Report — `simply_ip_vault` ↔ `simply_hook_executor`

**Date:** 2026-08-01
**Mode:** Read-only comparative audit. No source file was modified; this report is the only artefact produced.

## Scope and orientation

| | Path | Role in this audit |
|---|---|---|
| `simply_ip_vault` | repository root (`./src`, `./tests`, `./scripts`) | **Project A** — the working tree |
| `simply_hook_executor` | `./example/simply_hook_executor` | **Project B** — the vendored reference |

> **Correction to the task framing.** The request described `simply_hook_executor` as "the current repository" and `simply_ip_vault` as the code "located in the `./example` directory". That is inverted. `Cargo.toml` at the root declares `name = "simply_ip_vault"`; `example/simply_hook_executor/Cargo.toml` declares `name = "simply_hook_executor"`. Every statement below uses the actual layout.

> **A second correction, to a prior finding.** An earlier session in this repository recorded that the reference implementation "parses IP/CIDR only" and "takes the rightmost `X-Forwarded-For` entry unconditionally". That was true when it was written and is **no longer true**: `example/simply_hook_executor/src/config.rs` (mtime 2026-08-01 15:37) now implements hostname resolution with caching *and* right-to-left chain walking. The two projects hardened in parallel. Notes in `AGENT_NOTES.MD` that rest on the older reading are stale.

Business logic (IP records vs. hooks, ban orchestration vs. process execution) is deliberately **not** compared. Only security primitives are.

**Summary of direction:** neither project dominates. Project A is stronger on authentication ordering, mandatory signing, and delegated-grant containment. Project B is stronger on cryptographic key handling, request-target coverage in the signature, deployment surface control, and test depth on the shared primitives. Seven discrepancies are material; two are outright defects.

---

## 1. Proxy & IP Middleware

Files: `src/config.rs`, `src/middleware.rs` in both projects.

### 1.1 `TRUSTED_PROXIES` — parsing and hostname resolution

Both projects accept **CIDR ranges, bare addresses (widened to a host route), and hostnames**, both default to empty meaning "trust nothing", both resolve names through `tokio::net::lookup_host` with a **30-second TTL**, and both fail closed when resolution fails. The design intent is identical, and in several places the doc comments are near-verbatim between the two. The implementations differ structurally.

**Project A — `simply_ip_vault`** (`src/config.rs:52-152`)

```rust
pub struct TrustedProxies {
    matchers: Arc<Vec<ProxyMatcher>>,
    cache: Arc<RwLock<HashMap<String, CachedLookup>>>,   // std::sync::RwLock
}
pub async fn contains(&self, ip: IpAddr) -> bool { /* literals first, DNS only on miss */ }
```

A **per-hostname** cache keyed by name. `contains()` scans literal networks first and short-circuits, so an all-CIDR configuration never touches the resolver. A resolution failure caches nothing and is retried on the next request.

**Project B — `simply_hook_executor`** (`example/.../src/config.rs:44-190`)

```rust
struct ResolvedProxies { networks: Arc<Vec<IpNetwork>>, refreshed_at: Option<Instant> }
pub async fn resolved(&self) -> Arc<Vec<IpNetwork>> { /* whole-set snapshot */ }
```

A **whole-set** snapshot: every hostname is resolved together and merged with the literals into one flat `Vec<IpNetwork>`, returned as an `Arc`. The no-hostname path returns `Arc::clone(&self.networks)` without touching the lock at all. The refresh re-checks the TTL under the write lock, so a burst of requests arriving on an expired cache produces **one** lookup rather than N.

| Property | A (`ip_vault`) | B (`hook_executor`) |
|---|---|---|
| Cache granularity | per hostname | whole set |
| Lock type | `std::sync::RwLock` | `tokio::sync::RwLock` |
| Thundering-herd guard on expiry | ✗ none | ✓ double-check under write lock |
| Failed lookup | not cached, retried every request | absent from snapshot, retried after TTL |
| Test-facing TTL override | ✗ | ✓ `with_ttl()` |
| Steady-state cost, no hostnames | iterate matchers | `Arc` refcount bump |

Neither lock choice is a defect: A never holds its `std` guard across an `.await` (the `read()` scope closes before `lookup_host`), which is the rule that matters.

**The one behavioural divergence that is not a defect but should be a decision:** on repeated DNS failure, A re-queries the resolver on **every request**. If a `TRUSTED_PROXIES` hostname stops resolving under load, A generates one DNS lookup per inbound request on the hot path. B absorbs this into its TTL. A's choice buys faster recovery when the name comes back; B's bounds the resolver load. B's is the safer default under adverse conditions.

### 1.2 Entry validation — a real divergence

Both reject entries containing `/` or `:` that failed to parse as CIDR/IP, which correctly stops a botched prefix like `10.0.0.0/8x` from being silently demoted to a hostname that never resolves. But:

```rust
// B — example/.../src/config.rs:578-581
// A name made only of digits and dots is a malformed IPv4 literal, not a hostname.
if candidate.chars().all(|c| c.is_ascii_digit() || c == '.') { return false; }
```

Project A has no such rule (`src/config.rs:189-198`), and its own test asserts the consequence:

```rust
// A — src/config.rs:353-355
// Not a valid address, but a legal DNS label — treated as a name, which fails safe
// by never resolving rather than being silently trusted.
ProxyMatcher::Hostname("999.1.1.1".to_owned()),
```

Both fail safe. But `TRUSTED_PROXIES=10.0.0.256` — a plausible typo — is a **loud startup error** in B and a **silent never-matching entry** in A. The operator-visible outcome in A is "my proxy stopped being trusted and nothing said why", which is the failure mode `TRUSTED_PROXIES` exists to make debuggable.

### 1.3 `X-Forwarded-For` chain parsing

Both implement the same algorithm, and both express the same load-bearing precondition: **the headers are consulted only if the TCP peer is itself trusted.**

```rust
if !trusted.contains(peer).await { return peer; }         // A, src/config.rs:261
if !is_trusted(peer, trusted)  { return peer; }           // B, example/.../config.rs:274
```

Both then walk the chain `.rev()`, skipping trusted hops, and fall back to `peer` — never to an unvalidated claim — when the header is absent, unparseable, or contains only proxies. Both normalize IPv4-mapped IPv6 on the peer *and* on each hop. Both consult `X-Real-IP` only when `X-Forwarded-For` yields nothing.

**The divergence is in what counts as "trusted" during the walk.**

Project B's `resolve_client_ip` takes a pre-resolved `&[IpNetwork]` in which hostname-derived addresses are already flattened, so **a hostname-identified proxy appearing as an intermediate hop is correctly skipped**.

Project A's walk calls `is_literal_network` (`src/config.rs:223-228`), which returns `false` for every `Hostname` matcher by construction. A hostname-identified intermediate hop is **not** skipped and is reported as the client. A documents this precisely:

> The consequence is narrow: a chained hop identified only by hostname is treated as a client rather than skipped, which resolves to that hop's address instead of the one behind it. That is the conservative direction — it never trusts an address further left than it should.

The reasoning is correct and the direction is safe. But the cost is not zero: in the exact deployment shape this feature was built for — a Docker/Traefik stack where proxies are *named* because their addresses are assigned by the orchestrator — a two-hop chain resolves `bound_ips` against the inner proxy instead of the real client. B's architecture avoids the trade-off entirely rather than choosing the safe side of it, because resolving the whole set up front makes the hostname addresses available to the walk for free.

### 1.4 `bound_ips` enforcement and master keys

**Identical, and both correct.** Neither exempts master keys:

```rust
let is_allowed = networks.is_empty() || networks.iter().any(|net| net.contains(client_ip));
```

Both carry a comment recording that `is_master` used to bypass this and why that was wrong. Both log `is_master` alongside the denial. No discrepancy.

### 1.5 Bootstrap `bound_ips` default — **defect in Project A**

```rust
// A — src/main.rs:94
let bound_ip = std::env::var("BOOTSTRAP_SUBNET").unwrap_or_else(|_| "0.0.0.0/0".to_owned());

// B — example/.../src/main.rs:95-96
let bound_ip = std::env::var("BOOTSTRAP_SUBNET").unwrap_or_else(|_| "0.0.0.0/0,::/0".to_owned());
```

B's comment states the reason explicitly:

> Listing only `0.0.0.0/0` would have been harmless while master keys bypassed the CIDR check; now that they are held to it, an IPv4-only default would lock an operator out of a dual-stack deployment on the very first request.

This applies verbatim to Project A, which made the same master-key change without the same default fix. `normalize_ip` rescues only *IPv4-mapped* IPv6 (`::ffff:a.b.c.d`); a **native** IPv6 peer — `::1` from a `localhost` that resolves to IPv6 first, or any real IPv6 client — does not match `0.0.0.0/0`. The bootstrap master key is then rejected with `403` on its first request, with no other credential in the database to fix it with.

This does not reproduce in A's E2E suite because it connects over `127.0.0.1`. **This is the most actionable finding in the report.**

### Section conclusion

**B is stronger**, on three counts: the chain walk honours hostname-identified proxies, malformed entries surface as configuration errors, and the DNS refresh is herd-safe. **A is not weaker on the control that matters most** — the peer-trust precondition is identical and correct in both, and both apply `bound_ips` to master keys. A's bootstrap default is a genuine dual-stack lockout bug that B has already fixed.

---

## 2. RBAC & Privilege Escalation Guards

File: `src/api.rs` in both.

The scope vocabulary differs (A: `is_master` / `can_manage_keys` / `can_create_groups` / `can_manage_webhooks`, over M:N *groups*; B: `is_master` / `can_manage_keys` / `can_manage_hooks`, over M:N *hooks*), so the comparison is structural.

### 2.1 Scope elevation on mint and update

| | A | B |
|---|---|---|
| Guard | `guard_scope_elevation` (`src/api.rs:190`) | `require_master_to_grant_scopes` (`example/.../api.rs:343`) |
| Master-only scopes | `is_master`, `can_manage_keys`, `can_create_groups` | `is_master`, `can_manage_keys`, `can_manage_hooks` |
| Applied on create | ✓ with `held = [false; 3]` | ✓ |
| Applied on update | ✓ with `held = target`'s current values | ✓ with `None` for `is_master` |
| Revocation allowed to non-master | ✓ | ✓ |
| Idempotent re-submission of a held scope | ✓ accepted | ✗ rejected |

Both reason identically about *why* the non-`is_master` scopes are on the list — each is a path back to master authority rather than a leaf capability — and both exempt the one scope that is genuinely bounded (A: `can_manage_webhooks`; B has no equivalent).

The `held` parameter is A's only functional addition. It is **not** a hole: `guard_master_target` independently blocks a non-master from touching a master target at all, so `held[0]` can never be `true` for a caller who could exploit it. It permits an idempotent `PUT` from a dashboard that posts every field. B rejects that same request with `403`. A's behaviour is better; B's is stricter without buying anything, because the case it refuses is by definition a no-op.

### 2.2 Master-key administration

Structurally identical. A's `guard_master_target` (`src/api.rs:216`) and B's `require_master_to_administer` (`example/.../api.rs:378`) both reduce to `if target.is_master && !caller.is_master → 403`, both log the attempt at `warn`, and both are applied to **update, rotate, and delete**. Both record the same rationale: rotation returns the new plaintext in its response, so rotating someone else's master key is credential theft with a lockout attached.

A applies it to one endpoint B does not have — `rotate_signing_secret` (`POST /keys/{id}/rotate-secret`, `src/api.rs:1771`) — correctly, since that response also returns plaintext key material.

Both refuse self-deletion (`if id == key.id → 403`). No discrepancy.

### 2.3 Self-granting

| | A | B |
|---|---|---|
| Self-grant of M:N permissions | ✓ blocked (`src/api.rs:1828`) | ✓ blocked (`example/.../api.rs:2204`) |
| Master exempt from that block | ✓ | ✓ |
| Self-widening of *global* scopes | ✓ blocked (`src/api.rs:1636-1648`) | ✗ **not blocked** |

A carries an extra guard B lacks: a non-master cannot set `can_manage_webhooks: true` on **its own** key even though that scope is delegable to others. A's comment states the principle — `can_manage_keys` is authority over *other* keys, and letting it rewrite the caller's own flags makes every scope reachable from any one of them. B has no counterpart, so in B a `can_manage_keys` holder can `PUT /api/keys/{own_id}` and grant itself any non-master-only scope. B's list happens to contain no delegable scope today, which makes the gap latent rather than live — but it is a missing guard, not a design decision, and the next delegable scope added to B opens it.

A's rationale for blocking self-targeting outright rather than relying on "cannot grant what you don't hold" is the stronger argument of the two, and is worth quoting because B does not make it:

> …a caller allowed to target itself could ratchet — grant itself `can_read` on a group it can already read, then use that row as the basis for widening to `can_write`, and so on. Requiring a second party for every self-affecting change removes the ratchet entirely.

### 2.4 Delegated grants — "cannot grant what you don't hold"

Both enforce it, differently shaped:

- **A** — `guard_delegated_group_grant` (`src/api.rs:131`) compares each verb independently against the caller's own permission row: holding `can_read` on a group does not confer the right to grant `can_write` on it.
- **B** — `require_manage` on the target hook (`example/.../api.rs:2233`), plus `require_master_for_privileged_hook`, which keeps distribution of rights over an *elevated* hook master-only even for a caller who legitimately manages it.

Both are sound. A's per-verb decomposition is finer-grained.

### 2.5 Revocation is unguarded in Project A — **defect**

**B** guards revocation symmetrically with granting:

```rust
// example/.../api.rs:2292-2297
// Symmetric with granting. Revoking is not an escalation, but leaving it ungated would mean a
// key manager could strip access to hooks it has no relationship with — cross-tenant tampering,
// and an odd asymmetry where a grant you could not create is one you could still destroy.
if !key.is_master { require_manage(&state.db, &key, hook_model.id).await?; }
```

**A's `revoke_key_group_permission`** (`src/api.rs:1911-1950`) checks only `is_master || can_manage_keys` and then deletes. There is no `guard_delegated_group_grant`, no `caller_group_permission` lookup, and no `guard_master_target`.

The consequence: in Project A, a non-master holding `can_manage_keys` and scoped to group *A* can revoke **any** key's permissions on **any** group, including group *B* it has no relationship with. A blocks over-*granting* and leaves over-*revoking* wide open — precisely the asymmetry B's comment describes. It is a denial-of-access and cross-tenant tampering primitive, not a privilege escalation, which is why it survived A's hardening pass. It is still a hole in a per-group RBAC model that is otherwise carefully enforced.

### 2.6 Audit-log access

Identical: master-only in both, with the same reasoning (audit entries span every key, so a scoped key reading them is an RBAC leak regardless of its own grants).

### Section conclusion

**Close, with defects on both sides.** A is stronger on self-escalation (global-scope self-widening blocked; B does not), on per-verb delegation, and on covering its extra secret-rotation endpoint. B is stronger on revocation symmetry, which A is missing entirely (§2.5). A's `held`-aware elevation guard is strictly better ergonomics at equal safety.

---

## 3. Cryptography & HMAC Logic

Files: `src/crypto.rs`, `src/middleware.rs`, plus `src/webhooks.rs` (A only).

### 3.1 Constant-time comparison — both correct

**Verified by reading, in both projects. Neither uses `==` on a signature anywhere.**

```rust
// A — src/crypto.rs:141
mac.verify_slice(&provided_bytes).is_ok()

// B — example/.../middleware.rs:139
mac.verify_slice(&expected).map_err(|_| AppError::Unauthorized(...))
```

Both reach `subtle::ConstantTimeEq` through the RustCrypto `Mac` API rather than depending on `subtle` directly. B additionally documents the verified call chain (`Mac::verify_slice → CtOutput::eq → subtle::ConstantTimeEq::ct_eq`) and pins the property with an exhaustive test that flips every bit position of a valid tag and asserts each is rejected — the deterministic fingerprint of a full-width compare. A has the equivalent test in `tests/security_tests.rs`. Both reject wrong-length tags.

No discrepancy on the property that was the original reason for this audit.

### 3.2 Canonical string construction — **A signs less than B**

```
A:  METHOD \n PATH             \n TIMESTAMP \n RAW_BODY      (src/crypto.rs:74)
B:  METHOD \n PATH_AND_QUERY   \n TIMESTAMP \n RAW_BODY      (example/.../middleware.rs:66)
```

Both use LF delimiters with no trailing newline, both use the raw body verbatim, both correctly use `OriginalUri` (essential — `Router::nest("/api", …)` strips the prefix inner layers observe), and both carry a test proving the delimiter closes boundary-shifting (`"POST" + "/api/x"` vs `"POS" + "T/api/x"`).

**The query string is the difference.** A excludes it deliberately and documents the trade-off: a reverse proxy that reorders, re-encodes, or appends query parameters would otherwise invalidate valid requests, and `AGENT.MD` records the compensating rule that query parameters on `/api/*` are read-only filters while every mutating field travels in the signed body.

**That compensating rule no longer holds in Project A.** The soft-delete work added query parameters that are not read-only filters:

| Route | Parameter | Effect |
|---|---|---|
| `DELETE /api/ips/{id}` | `?hard=true` | escalates a soft delete to an irreversible hard delete |
| `GET /api/ips` | `?include_deleted=true` | widens the result set to the master trash view |

Because the query is outside the signed material, a captured signed `DELETE /api/ips/{id}` can be replayed within the 300-second window as `DELETE /api/ips/{id}?hard=true`. The `?hard=true` path is separately gated on `key.is_master`, so this converts a master's *reversible* action into an *irreversible* one rather than crossing a privilege boundary — but that is a data-destruction primitive reachable by an on-path attacker who cannot forge a signature, and it exists precisely because the documented invariant that justified excluding the query has been silently broken by later work.

B signs the full request target and states the concrete case: `?older_than_days=0` must not be rewritable to `?older_than_days=1` on an otherwise-valid signed request.

### 3.3 Anti-replay window

| | A | B |
|---|---|---|
| Window | `MAX_TIMESTAMP_SKEW_SECS = 300`, **compile-time constant** | `signature_max_age_seconds`, default 300, **`SIGNATURE_MAX_AGE_SECONDS` env, clamped `.max(1)`** |
| Symmetric (future rejected) | ✓ | ✓ |
| Checked before HMAC work | ✓ | ✓ |
| Rejection status | `401` | `401` |
| Modes | `CANONICAL_V1` only, always | per-key `CanonicalV1` / `BodyOnly` |

Both use `(now - presented).abs() > limit` and both document why the future direction is refused: a forward-dated request would stay replayable for as long as the skew allows.

B's `BodyOnly` mode signs the body alone for GitHub-style senders. It is replay-vulnerable by construction, and B handles that honestly: it does not demand a timestamp it would not actually cover, it refuses to honour `X-Hub-Signature-256` for a `CanonicalV1` key (so a strict key cannot be downgraded to the weaker scheme by sending the other header name), and choosing it is written into the audit trail as removing replay protection. A has no mode selector on the inbound path — every `/api/*` request is `CANONICAL_V1`, always.

### 3.4 Mandatory vs. optional signing — **A is stronger**

**A: signatures are mandatory.** `X-API-Key`, `X-Timestamp` and `X-Signature-256` are all required on every `/api/*` request; there is no configuration that relaxes this. A leaked API key alone is useless.

**B: signatures are optional by default.** `require_signed_requests` defaults to `false`, so the bearer key alone authenticates; a present signature must still verify. B documents this as an upgrade-compatibility choice with `REQUIRE_SIGNED_REQUESTS` as the intended end state.

A's posture is the stronger default. B's is the more deployable one, and it does not fail open on a *presented* signature — but "off by default" means the property most deployments actually get is bearer-token auth.

### 3.5 Check ordering — **A is stronger**

```
A:  resolve IP → timestamp → key lookup → verify signature → bound_ips        (src/middleware.rs)
B:  resolve IP → key lookup → bound_ips → verify signature                    (example/.../middleware.rs)
```

A verifies the signature **before** the CIDR check and states why:

> Running the network-binding check first would let a caller who cannot prove possession of the signing secret learn — from the 403-vs-401 distinction alone — whether a key it merely guessed is bound to the caller's own network.

B checks `bound_ips` first and so exposes exactly that oracle. It is narrow (it requires already holding a valid `X-API-Key`, and it distinguishes only "bound to your network" from "not"), but A's ordering is free and B's is not. **Authenticate, then authorize** — A has it right.

### 3.6 Encryption at rest — **B is stronger**

| | A | B |
|---|---|---|
| AEAD | AES-GCM-256, 96-bit nonce | XChaCha20-Poly1305, 192-bit nonce |
| Key source | `VAULT_ENCRYPTION_KEY`, **any string, SHA-256'd to 32 bytes** | `SIGNING_SECRET_KEY` (alias `VAULT_ENCRYPTION_KEY`), **must be exactly 64 hex chars** |
| Malformed key | impossible — anything is accepted | **hard error, startup aborts** |
| Cipher construction | per call, re-reads env each time | once at startup, held in `AppState` |
| Unencrypted mode | stores plaintext verbatim | stores hex-encoded behind `v1.plain.` |
| Sealed row, key missing | error, not silent passthrough ✓ | error, not silent passthrough ✓ |
| Fresh nonce per message | ✓ | ✓ |
| Tamper detection tested | ✓ | ✓ |

Three differences favour B:

1. **Key strength.** A accepts any passphrase and SHA-256's it. There is no KDF stretching, so `VAULT_ENCRYPTION_KEY=password` produces a 32-byte key with the entropy of `password` and no indication anything is wrong. B refuses to start unless given 32 bytes of real key material and tells the operator how to generate it (`openssl rand -hex 32`). A's ergonomic win costs the guarantee.
2. **Nonce width.** Random 96-bit nonces carry a birthday bound; random 192-bit nonces are collision-safe without counter state. The practical exposure in A is negligible — nonces are consumed per *key rotation*, not per request — but B's construction removes the question rather than bounding it.
3. **Failure mode.** B's `SecretCipher::from_env()?` runs before the bootstrap key is minted, so a malformed key stops startup rather than silently degrading to writing secrets in the clear. A cannot express that failure at all.

A's `encryption_key()` also re-reads the environment and re-derives the key on **every** seal and open — i.e. on every authenticated request. That is a per-request `getenv` + SHA-256, and it means the key can change under a running process. Neither is severe; both are avoided by B's construct-once design.

### 3.7 Template injection (Project A only)

`resolve_hmac_template` has no counterpart in B, which dispatches no outbound webhooks. Re-verified here: the substitution loop appends resolved values to an output buffer and advances past each placeholder without ever re-scanning `out`, so for any body `B` the resolved string is exactly `POST\n<path>\n<ts>\n` ++ `B`. A receiver splitting on `splitn(4, '\n')` recovers the true fields regardless of newlines injected into the body. **Confirmed non-manipulable.** Pinned by a test in `tests/security_tests.rs` driving the real `cause → /api/ban → $cause → {body}` path.

The outbound SSRF screen in `src/webhooks.rs` (scheme allowlist, every resolved address checked, IPv4-mapped normalization, `Policy::none()` on redirects) likewise has no counterpart to compare against. Its documented residual — DNS rebinding, because `is_url_safe` resolves and then `reqwest` resolves again independently — remains open and is recorded in `AGENT_NOTES.MD`.

### Section conclusion

**Split, and the split is clean.** A is stronger on the *protocol*: mandatory signing, authenticate-before-authorize, no weak mode available. B is stronger on the *material*: full request-target coverage, enforced key strength, a nonce width that removes rather than bounds the collision question, and a cipher that fails closed at startup. Both are correct on the constant-time comparison that motivated the audit. A's exclusion of the query string from the signed material is now unsound in A specifically, because the invariant justifying it (`?…` is read-only) was broken by the soft-delete work (§3.2).

---

## 4. Database Configuration & Edge Cases

### 4.1 SQLite pragmas

Both apply `journal_mode=WAL` and `busy_timeout=5000`, both gate on `db.get_database_backend() != DatabaseBackend::Sqlite` rather than sniffing the URL string, both run **before** migrations, both read back the actual `journal_mode` rather than assuming success, and both document this as the one deliberate exception to the SQL-agnostic rule in `AGENT.MD` — it configures the engine, not a query.

| | A (`src/state.rs:35`) | B (`example/.../src/db.rs:49`) |
|---|---|---|
| Pragma failure | `?` — **propagates, aborts startup** | logged and swallowed |
| `busy_timeout` statement | `execute_unprepared(&str)` | `execute_raw(Statement)` |
| Comparison of read-back mode | `Some("wal")` exact | `eq_ignore_ascii_case("wal")` |
| Unit test | ✗ **none** | ✓ file-backed, asserts WAL + timeout + inheritance across reconnect |
| Pool limits configured | ✗ | ✗ |

Two things stand out.

**A aborts startup on a pragma failure.** The doc comment says the in-memory case "is harmless there and the result is logged rather than treated as a failure" — true for the read-back branch, but the surrounding `?` still propagates a genuine `DbErr`. B chose the opposite and explained it: refusing to boot over a performance setting that did not apply trades a real outage for a theoretical slowdown. B's is the better call for a daemon.

**A has no unit test for the pragmas at all.** A verifies WAL only through log-line assertions in `scripts/test_e2e.sh` §24b. B's test opens a **file-backed** database — the only place WAL can actually engage; an in-memory database would pass a weaker assertion vacuously — asserts `journal_mode = wal` and `busy_timeout = 5000` by reading them back, then reopens the file on a fresh connection and asserts WAL was inherited, which is what makes applying it once at startup sufficient for the whole pool. That last property is asserted nowhere in A.

B also documents a distinction A's comment elides: **`journal_mode` is persistent** (recorded in the file header, inherited by every future connection) while **`busy_timeout` is per-connection** (the pool-wide guarantee comes from SQLx's own five-second default; the explicit statement makes the intent visible and asserts it holds, rather than being the sole mechanism). A's comment reads as though both are pool-wide.

Neither project sets `ConnectOptions::max_connections` / `min_connections`; both configure only `sqlx_logging_level`. Equal, and equally worth revisiting.

### 4.2 Retention and soft delete

Architecturally parallel — both soft-delete with `is_deleted` / `deleted_at`, both purge at **92 days**, both sweep on a `tokio::time::interval` with a shutdown channel, both treat a non-positive retention as "disabled".

One difference in the purge predicate:

```rust
// A — src/retention.rs:83-85
.filter(ip_record::Column::IsDeleted.eq(true))
.filter(ip_record::Column::DeletedAt.is_not_null())
.filter(ip_record::Column::DeletedAt.lt(threshold))

// B — example/.../retention.rs:78-79
.filter(hook::Column::IsDeleted.eq(true))
.filter(hook::Column::DeletedAt.lt(threshold))
```

A adds an explicit `is_not_null()`. Under SQL three-valued logic `NULL < threshold` evaluates to NULL and is not matched, so **both are correct** — A's is defensive rather than load-bearing. A's requirement that `is_deleted` *and* an aged `deleted_at` both match is the property that matters, and both have it: filtering on the timestamp alone would destroy restored records still carrying a stale one.

The retention window is env-configurable in A (`IP_RETENTION_DAYS`, `IP_RETENTION_SWEEP_SECONDS`) and a hard constant in B (`DELETED_HOOK_RETENTION_DAYS`). A is more operable.

### 4.3 The `301s`-future timestamp test

Both suites hit the same latent flake and fixed it the same way — **widen the margin so elapsed wall-clock cannot carry a future timestamp back inside the window.**

The mechanism, as recorded in A's script: a *stale* timestamp only gets staler while the script runs, so `NOW - 301` can never drift back inside. A *future* timestamp decays toward the window — at `NOW + 301`, one second between capturing `NOW_TS` and the server reading its own clock leaves a skew of `300`, which is legitimately inside it. The test passed only when the request landed in the same second as the capture.

| | A (`scripts/test_e2e.sh:404-414`) | B (`example/.../test_e2e.sh:877-891`) |
|---|---|---|
| Stale case | `NOW_TS - 301` (reuses the captured value — safe) | `NOW - 360` |
| Future case | `$(date -u +%s) + 360` — **fresh capture immediately before the call** | `NOW + 3600` |
| Exact ±300/±301 edge | pinned in-process in `tests/security_tests.rs` | pinned in-process in `middleware.rs` unit tests |

A re-captures the clock; B leans on a margin an order of magnitude larger than any plausible drift. Both are deterministic. A's is the more precise fix, B's the more obviously robust. Both correctly moved the *exact boundary* assertion out of the shell and into an in-process test, which is the part that actually matters.

### 4.4 Deployment surface — **B is stronger**

```rust
// A — src/main.rs:221
let addr = SocketAddr::from(([0, 0, 0, 0], 3000));      // hardcoded

// B — example/.../src/main.rs:210
let addr = config::resolve_bind_addr();                 // BIND_HOST / HOST / PORT
```

Project A **cannot be bound to a specific interface**. It always listens on every interface on port 3000; restricting exposure requires a firewall or a container network. B supports `BIND_HOST` (preferred over `HOST`, because `HOST` is widely set to unrelated values by other tooling), supports `PORT`, requires a **literal IP** rather than resolving a hostname (resolving could yield several addresses with no principled way to choose, and binding the wrong interface is a security problem), passes port `0` through so the OS assigns an ephemeral port, and logs the address read back from the listener rather than the one requested.

B additionally has `GET /api/settings` (master-only), which reports the resolved `trusted_proxies` spec, `signature_max_age_seconds`, `require_signed_requests`, and `signing_secrets_encrypted`. A has no equivalent, so an operator cannot verify from the API which proxy configuration is actually in force — they must read the startup log.

B also pins an explicit `DefaultBodyLimit::max(1 MiB)` on the whole router, **outside** the nests so it covers `/api/*`, `/webhook/*` and the static fallback alike, and deliberately reuses that same constant as the signature-verification buffer so no band of sizes is accepted by one layer and refused by the other. A sets no `DefaultBodyLimit` at all — it relies on Axum's implicit default and independently hardcodes `MAX_SIGNED_BODY_BYTES = 2 MiB` in the middleware, which is exactly the two-independently-chosen-limits shape B's comment warns about.

### Section conclusion

**B is stronger.** Same pragmas, but B tests them properly (file-backed, with the inheritance property A never asserts), fails soft on a pragma error where A aborts startup, and is far ahead on deployment surface: configurable bind address, explicit router-wide body limit tied to the signature buffer, and a settings endpoint that makes the security configuration verifiable. A's only edge here is env-configurable retention.

---

## 5. Information Leakage & Audit Logging

### 5.1 Error handling — **identical**

`src/error.rs` is effectively the same file in both. Same variants (B adds `TooManyRequests` for its concurrency budget), same status mapping, same single `IntoResponse` that is the only place deciding what detail reaches a client, and — the security-relevant part — the same treatment of driver errors:

```rust
AppError::DbError(err) => {
    tracing::error!("Database error: {}", err);
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error".to_owned())
}
```

Full detail to the log, generic text to the client. B annotates the reason (a raw driver error can expose schema and query structure); A does the same thing without the comment. No discrepancy.

Both return `AppError::Internal` — never a decryption error detail — when a stored signing secret fails to open, so a caller cannot distinguish "wrong key configured" from "tampered row". Both return `401` rather than `403` for a signature failure. A additionally avoids the 403/401 network-binding oracle by ordering (§3.5); B does not.

### 5.2 Audit logging — **B is stronger on attribution**

```rust
// A — src/api.rs:235
async fn create_audit_log(db, key: Option<&api_key::Model>, client_ip: Option<IpAddr>, ...)

// B — example/.../api.rs:104
async fn create_audit_log(db, key: &api_key::Model, client_ip: IpAddr, ...)
```

Both denormalize the acting key's name and prefix into the row so the trail stays legible after the key is deleted, and both record the **resolved** client IP from the `ClientIp` extension — never a raw header value.

A's signature makes both the acting key and the client IP **optional**, so `audit_logs.client_ip` can be written `NULL`. B's makes them mandatory: every audit row is attributable by construction, enforced by the type system rather than by convention. For a trail whose purpose includes recording identity-spoofing attempts, "attribution is optional" is the weaker contract.

Both log denials at `warn` with structured context, and the coverage is comparable:

| Event | A | B |
|---|---|---|
| `bound_ips` rejection, with `is_master` | ✓ | ✓ |
| Scope-elevation attempt | ✓ | ✓ |
| Master-target administration attempt | ✓ | ✓ |
| Self-granting attempt | ✓ | ✓ |
| Over-granting beyond own permissions | ✓ | — (structurally prevented) |
| Unresolvable `TRUSTED_PROXIES` hostname | ✓ | ✓ |
| Invalid signature, with key prefix + method + path | ✓ | — |
| Timestamp outside window | ✓ | ✓ (in the response text) |
| Choosing a replay-vulnerable HMAC mode | n/a | ✓ audited explicitly |

One operational difference worth calling out, from `example/.../src/main.rs:163`:

```rust
.with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
```

> Colour only when stdout is a terminal. Under systemd or any redirect, ANSI escapes would be written verbatim into journald and log files, which makes them ugly to read and — more importantly — breaks `grep 'rejection=PermissionDenied'`, since the codes land between the field name and its value.

A does not do this. A's security warnings are therefore **not reliably greppable** when the daemon runs under systemd or with stdout redirected, which is every production deployment. For logs whose value is being searched after an incident, this is a real defect rather than cosmetics.

### 5.3 Secret handling in responses

Both return plaintext key material exactly once, at mint and at rotation, and never echo it from a read endpoint. Both omit `key_hash` from every listing (A's `ApiKeySummary` documents that the hash of the live secret has no reason to leave the server even for a trusted admin UI). Both keep signing secrets out of every read path.

B redacts key material from `Debug`:

```rust
// example/.../crypto.rs:65-73 — never renders key material, so a {:?} of application
// state cannot leak it into a log
Self::Sealed(_) => f.write_str("SecretCipher::Sealed(<redacted>)")
```

and likewise renders `TrustedProxies` as the configured spec rather than the resolution cache. A holds no cipher in state (it re-derives per call), so it has no equivalent exposure — the risk is avoided by accident rather than by design, but it is avoided.

### Section conclusion

**B is stronger, narrowly.** Error handling is identical and correct in both. B makes audit attribution non-optional at the type level where A allows `NULL`, and B keeps its security warnings machine-readable under redirection where A's are corrupted by ANSI escapes. A logs one thing B does not — invalid-signature attempts with key prefix and target — and A's `403`/`401` ordering closes an oracle B leaves open.

---

## 6. Consolidated findings

Ordered by severity. Nothing here has been fixed; this report is read-only.

| # | Finding | Affects | Severity | Reference |
|---|---|---|---|---|
| 1 | Bootstrap master key bound to `0.0.0.0/0` only. Now that master keys are held to `bound_ips`, a native-IPv6 first request is `403`'d with no other credential in the database. | **A** | **High** | §1.5 |
| 2 | `revoke_key_group_permission` has no delegated-authority guard: any `can_manage_keys` holder can strip any key's access to any group. B guards the symmetric case. | **A** | **Medium** | §2.5 |
| 3 | Query string excluded from the signed material while `?hard=true` and `?include_deleted=true` are now state-changing — the invariant that justified excluding it no longer holds. | **A** | **Medium** | §3.2 |
| 4 | Encryption key accepts any passphrase, SHA-256'd with no KDF and no length floor; a weak key is indistinguishable from a strong one. | **A** | **Medium** | §3.6 |
| 5 | `bound_ips` checked *before* signature verification, exposing a 403/401 network-binding oracle to a caller holding a key but not its secret. | **B** | **Medium** | §3.5 |
| 6 | Signatures optional by default (`REQUIRE_SIGNED_REQUESTS=false`), so the shipped posture is bearer-token auth. | **B** | **Medium** | §3.4 |
| 7 | No self-grant guard on global scopes — a `can_manage_keys` holder can `PUT` its own key. Latent today (no delegable scope exists); live as soon as one is added. | **B** | **Low–Med** | §2.3 |
| 8 | Bind address hardcoded to `0.0.0.0:3000`; no `BIND_HOST`/`PORT`, no way to restrict the listening interface. | **A** | **Low–Med** | §4.4 |
| 9 | No `DefaultBodyLimit` on the router; the middleware's 2 MiB signature buffer is an independently-chosen second limit. | **A** | **Low–Med** | §4.4 |
| 10 | Hostname-identified proxies are not skipped during the `X-Forwarded-For` chain walk — safe direction, but breaks chained Docker/Traefik topologies. | **A** | **Low** | §1.3 |
| 11 | ANSI colour always on; security warnings are corrupted by escape codes under systemd or redirection, breaking `grep`. | **A** | **Low** | §5.2 |
| 12 | Pragma failure propagates and aborts startup, trading a real outage for a performance setting that did not apply. | **A** | **Low** | §4.1 |
| 13 | No unit test for WAL/`busy_timeout`; verified only through E2E log assertions, and the persistence-across-reconnect property is asserted nowhere. | **A** | **Low** | §4.1 |
| 14 | Malformed `TRUSTED_PROXIES` entries (`10.0.0.256`) become silent never-matching hostnames instead of startup errors. | **A** | **Low** | §1.2 |
| 15 | Failed hostname resolution is not cached, so a persistently-failing name generates one DNS lookup per request on the hot path. | **A** | **Low** | §1.1 |
| 16 | `create_audit_log` accepts `Option` for both acting key and client IP, permitting unattributable audit rows. | **A** | **Low** | §5.2 |
| 17 | `purge_expired_deleted_hooks` omits the explicit `deleted_at IS NOT NULL` guard. Correct under SQL three-valued logic; less defensive. | **B** | **Informational** | §4.2 |
| 18 | DNS rebinding in outbound webhook SSRF screening (resolve-then-reresolve). Pre-existing, documented, no counterpart in B. | **A** | Known | §3.7 |

## 7. Where each project is authoritative

Should the two be unified, these are the implementations worth treating as the reference for each primitive:

**Adopt from `simply_hook_executor` (B):**
- Whole-set proxy resolution (`TrustedProxies::resolved() -> Arc<Vec<IpNetwork>>`) — makes the chain walk hostname-aware, is herd-safe on expiry, and is cheaper in the steady state.
- `is_hostname_like`'s rejection of all-digit-and-dot entries.
- Full request-target (`path_and_query`) in the canonical string.
- `SecretCipher` — enforced 32-byte key, fail-closed at startup, constructed once, hex-encoded even in plaintext mode, redacted `Debug`.
- `resolve_bind_addr()` and the `BIND_HOST`/`PORT` contract.
- `DefaultBodyLimit` pinned router-wide to the same constant as the signature buffer.
- The file-backed pragma test, including the reconnect-inheritance assertion.
- `.with_ansi(is_terminal(stdout))`.
- Non-optional audit attribution.
- The symmetric revocation guard (`require_manage` on revoke).
- `GET /api/settings` as an operator-facing view of the live security configuration.
- `0.0.0.0/0,::/0` as the bootstrap `bound_ips` default.

**Adopt from `simply_ip_vault` (A):**
- Signature verification **before** the `bound_ips` check.
- Mandatory signing with no relaxation path.
- The self-escalation guard on global scopes (`id == key.id` on `update_api_key`).
- `held`-aware scope elevation, which permits idempotent `PUT` at equal safety.
- Per-verb delegated-grant checking (`guard_delegated_group_grant`).
- The explicit `deleted_at IS NOT NULL` purge predicate.
- Env-configurable retention window and sweep interval.
- `guard_master_target` applied to a narrow secret-only rotation endpoint.
- Logging invalid-signature attempts with key prefix, method, and path.

**Already identical and correct in both — leave alone:**
- `Mac::verify_slice` constant-time comparison, and the exhaustive bit-flip test behind it.
- The peer-trust precondition on forwarding headers.
- Right-to-left chain walking with trusted-hop skipping and fallback to the peer.
- IPv4-mapped IPv6 normalization on both peer and hops.
- `bound_ips` applied to master keys.
- Symmetric anti-replay windows, checked before HMAC work.
- `AppError` and its `IntoResponse` mapping.
- Master-only audit-log access.
- Denormalized key name/prefix in audit rows.
