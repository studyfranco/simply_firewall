# Simply IP Vault - AI Agent Context & Directives

Hello AI Agent! You are assisting with the development of `simply_ip_vault`. Read and strictly adhere to these guidelines before inspecting or writing any code.

---

## 📄 Document & Context Hierarchy

To keep this context clean and modular, responsibilities are split across three files:
1. **`AGENT.MD`** *(This file)*: Core architectural rules, security constraints, documentation standards, and testing directives.
2. **`SCHEMA.MD`**: Official Database Schema, SeaORM Entity relations, M:N RBAC definitions, and Enum specifications.
3. **`AGENT_NOTES.MD`**: Agent worklog. You MUST update this file with architectural decisions, progress notes, or pending tasks after completing significant modifications.
4. **`example/`**: You can find the code of other similar/linked project inside.

---

## 🎯 Project Overview

`simply_ip_vault` is an enterprise-grade, central Firewall and ACL management API written in Rust. It acts as the single source of truth for IP banning/whitelisting and dispatches signed, templated webhook events to downstream systems or other `simply_ip_vault` instances. It features an integrated Vanilla JS dashboard governed by a granular multi-tenant Role-Based Access Control (RBAC) system.

---

## 🛠️ Tech Stack & Constraints

- **Backend:** Rust + Axum (0.8+) + Tokio (1.x).
- **ORM (SQL-Agnostic):** SeaORM (2.0+). Defaults to **SQLite** for zero-config local development/testing, but MUST remain strictly **SQL-agnostic** (PostgreSQL-ready). **Never write vendor-specific raw SQL queries.**
- **Frontend:** STRICTLY Vanilla JS, HTML5, and CSS3. **NO external dependencies** (No React, Vue, Tailwind, Bootstrap, CDN links, or Axios). Native `fetch()` only.
- **Quality & Safety:**
  - Zero compiler warnings, zero `clippy` warnings.
  - **Zero `.unwrap()` or `.expect()`** in production or HTTP handlers. Use structured `AppError` and Axum's `IntoResponse`.
  - **Mandatory `rustdoc`**: All public modules, structs, enums, functions, and Axum handlers MUST be documented using `///` (or `//!` for crates/modules). Enforce `#![warn(missing_docs)]` in `lib.rs`.

---

## 🏛️ Core Architectural Rules

### 1. Security & Network (Zero-Trust)

- **Middleware Protection:** All `/api/*` routes pass through custom authentication middleware (`src/middleware.rs`).
- **Authentication (HMAC-SHA256):** Every request MUST carry **three** headers. Possession of `X-API-Key` alone is NOT sufficient.

  | Header | Purpose |
  | :--- | :--- |
  | `X-API-Key` | The plaintext key. Used **only** to look up the key record (by SHA-256 of its value). Identity, not proof. |
  | `X-Timestamp` | Current UTC Unix time in **seconds**. |
  | `X-Signature-256` | Hex HMAC-SHA256 over the **CANONICAL_V1** string (below), keyed with the key's `signing_secret`. A `sha256=` prefix is accepted and stripped. |

  - **CANONICAL_V1 signed string:** `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY` — the four parts joined by a single `\n` (LF), with **no trailing newline**. `METHOD` is uppercase; `TARGET` is the full request target **including the query string** when one is present; `RAW_BODY` is the exact request body bytes (empty when there is no body).
  - **Why a delimiter:** plain concatenation is ambiguous — `("POST", "/api/ban")` and `("POS", "T/api/ban")` produce identical bytes, so a signature over one authenticates the other. `\n` cannot appear in a method or a URL path, so it eliminates that class of boundary confusion. This is also the format `simply_hook_executor` speaks, so a single canonical string serves the inbound API and outbound `CANONICAL_V1` webhooks alike.
  - **Why the query string is included** *(changed by the cross-service convergence pass; this directive previously said the opposite)*: the original rule excluded it because reverse proxies reorder or append query parameters, and because query parameters on `/api/*` were read-only filters. **That second half stopped being true.** `?hard=true` on `DELETE /api/ips/{id}` escalates a reversible soft delete into an irreversible purge, and `?include_deleted=true` widens `GET /api/ips` to the master trash view. With the query outside the signed material, an on-path attacker who cannot forge a signature could still rewrite a captured `DELETE /api/ips/{id}` into `…?hard=true` inside the replay window. The cost is real and accepted: a proxy that rewrites query strings must now be configured not to.
  - **`TARGET` is the request target as the client sent it** (e.g. `/api/ips?limit=10`), not the path relative to the router's `/api` mount point. The middleware reads `OriginalUri` for exactly this reason.
  - **Anti-Replay Guard — two halves, both mandatory:**
    1. **Freshness.** Reject with `401 Unauthorized` when `|server_time - X-Timestamp| > 300` seconds. The window is **symmetric** — a future-dated timestamp is as suspect as a stale one, since allowing it would extend a captured request's usable lifetime.
    2. **Single use.** Reject with `401` a `(key, signature)` pair already accepted inside that window (`replay::ReplayGuard`, its own module). Freshness bounds how *long* a captured request stays usable and says nothing about using it *twice*: every field the signature covers is unchanged in a replay, so the HMAC verifies and the window check passes. The guard is consulted **after** the HMAC verifies — recording unverified signatures would let an unauthenticated caller exhaust memory and pre-insert a signature a legitimate client is about to send.
    - **Keyed on the raw digest.** Entries are `(key_id, Vec<u8>)`, using the bytes `crypto::verify_signature` decoded and returned — not the header text. `sha256=AB…` and `ab…` are the same signature and must never be recordable as two distinct single uses. `verify_signature` therefore returns `Option<Vec<u8>>`, not `bool`.
    - **Expiry is monotonic** (`tokio::time::Instant`, `now + window`), never wall-clock. Wall-clock arithmetic let an NTP correction evict still-valid entries in either direction — re-opening replay at the moment an operator is least likely to connect the two events. The caller-supplied `X-Timestamp` must not influence retention at all.
    - **Saturation never flushes.** At the 100 000-entry ceiling the guard sweeps expired entries, logs a warning, and **keeps enforcing**; the map is allowed to grow. `clear()` would make every signature accepted in the current window replayable at once, and since the map is process-global, one key's burst would disable the guard for every other key.
    - **Sweeping is amortized**, not per-request: once per quarter-window, or once per sixteenth-window while saturated. An O(n) retain inside the lock every authenticated request takes is a throughput cliff that worsens exactly as traffic rises.
    - **Operational consequence:** a signature covers method, target, timestamp and body and nothing else, so **repeating a call unchanged within the same wall-clock second is indistinguishable from a replay** and is refused. Real clients never hit this — a retry lands on a later timestamp. A caller that genuinely needs the same request twice in one second must wait for the next.
  - **Signature auth is unconditional.** Every key, every `/api/*` route, no per-key mode and no environment switch. `simply_hook_executor` keeps a configurable posture because it faces third-party webhook senders; this service does not, and its callers are shell scripts that compute the HMAC with one `openssl dgst -sha256 -hmac`.
  - **Ordering:** authenticate, then authorize. Timestamp (no I/O) → key lookup → signature verification → CIDR binding check. A caller that cannot prove possession of the signing secret must never learn, from a `403`-vs-`401` distinction, whether a guessed key is bound to its network.
  - Signature comparison MUST be constant-time (`Mac::verify_slice`), never `==` on hex strings.
- **Signing Secrets at Rest (`VAULT_ENCRYPTION_KEY`):** `signing_secret` cannot be hashed — verifying an HMAC needs it verbatim. When `VAULT_ENCRYPTION_KEY` (alias `SIGNING_SECRET_KEY`) is set, it is encrypted with **XChaCha20-Poly1305** (fresh random 24-byte nonce per value). The key **MUST be exactly 64 hex characters** (`openssl rand -hex 32`); anything else **aborts startup**. Without a key, the secret is stored hex-encoded but unencrypted — the zero-config **development** fallback only, logged as a warning at startup.
  - **Fail closed, never degrade.** An operator who set the variable believes their secrets are encrypted; silently writing them in the clear betrays that belief at the worst moment. The previous implementation accepted any string and SHA-256'd it, so `VAULT_ENCRYPTION_KEY=password` produced a key with the entropy of "password" and no signal that anything was wrong.
  - **The cipher is built once at startup** and carried in `AppState`. It is never re-read from the environment per request — an authorization input that can change under a running process cannot be reasoned about.
  - **Storage prefixes:** `v1.xchacha20poly1305.<nonce>.<ct>` (current), `v1.plain.<hex>` (unencrypted), and `aesgcm256:<nonce><ct>` (written by earlier versions, **read-only** — still openable under the same key, moved to the current format on the next rotation). Upgrading between these is non-destructive; no migration touches secret material.
  - **`open()` is strictly fail-closed** *(changed 2026-08-02; this directive previously listed a fourth shape)*: a stored value carrying **none** of those three prefixes is a `CryptoError::MalformedCiphertext`, surfacing as `500`. An unprefixed bare secret used to be returned verbatim as a compatibility path, which was a silent failure mode wearing a compatibility costume — "no recognized prefix" is not evidence of a pre-prefix row, and every other cause is worse. A `v1.plain.` value whose prefix was lost to a botched migration, a truncated column, or a partial write would have had its surviving text fed to `Hmac::new_from_slice` as key material, producing a fleet of `401`s that point at the client rather than at the database. Failing loudly makes the damaged row say so.
    - **Upgrade note:** a deployment still holding an unprefixed secret must rotate it (`POST /api/keys/{id}/rotate-secret`, master-only) *before* upgrading, or that key stops authenticating.
- **CIDR Restriction:** API Keys are bound to CIDR network ranges (`bound_ips`, supporting comma-separated IPv4/IPv6 ranges like `127.0.0.1/32, 10.0.0.0/8, ::/0`). Middleware MUST validate the client's IP against these bounds.
- **Resilient IP Extraction:** Do NOT use external IP extraction crates. `X-Forwarded-For`/`X-Real-IP` are honoured **only when the TCP peer is itself a configured `TRUSTED_PROXIES` member**; otherwise the peer address is authoritative. When the peer is trusted, the chain is walked **right to left, skipping hops that are themselves trusted proxies**, stopping at the first untrusted one — rightmost-first is what makes a client-supplied prefix unforgeable, and skipping trusted hops is what makes a *chain* work. Falls back to `ConnectInfo` whenever the headers are absent, unparseable, or name nothing but proxies. `TRUSTED_PROXIES` accepts CIDRs, bare addresses, and **hostnames** (resolved with a 30s positive / 5s negative TTL, so a dead name cannot trigger a lookup per request). An unresolvable entry disables **that entry only** and never the service. This walk is byte-identical to `simply_hook_executor`'s; `scripts/verify_convergence.sh` asserts it.
- **Listen address:** `BIND_HOST` (or `HOST`) and `PORT`, defaulting to `0.0.0.0:3000`. The host must be a literal IP — resolving a name could yield several addresses with no principled way to choose, and binding the wrong interface is a security problem.
- **Request body ceiling:** a single router-wide `DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES)` = **3 MiB**, applied outside the `/api` nest so it also covers the static fallback. `middleware::MAX_SIGNED_BODY_BYTES` is *derived from the same constant* — two independently-chosen limits would leave a band of sizes accepted by one layer and refused by the other.

### 2. Granular Multi-Tenant RBAC (M:N)

- **Global Rights:** An `ApiKey` can be `is_master` (bypasses all checks) or hold global booleans (`can_manage_keys`, `can_manage_webhooks`, `can_create_groups`).
- **Group Rights:** Managed via junction table `ApiKeyGroupPermission` linking keys to `IpGroup` with explicit flags (`can_read`, `can_write`, `can_delete`).
- **Least Privilege:** `can_write` or `can_delete` require `can_read` to be true.
- **Auto-Provisioning:** When an API Key creates a new `IpGroup`, the backend MUST automatically generate full read/write/delete permissions for that key on the new group.
- **Delegation is bounded in both directions.** `can_manage_keys` is the right to administer credentials, not authority over groups the caller cannot reach. A non-master may neither **grant** nor **revoke** a group permission beyond what its own `api_key_group_permissions` row holds, checked per verb (`guard_delegated_group_grant`, shared by `update_key_group_permissions` and `revoke_key_group_permission`). A caller with no row on the group is refused outright.
  - **Revocation is guarded too**, and it is not the harmless direction it looks like. This service keeps `fail2ban`-style automation writing to shared banlists, so stripping the key that maintains another tenant's list stops that tenant's blocking — a denial-of-service that presents as "bans stopped landing", several audit-log pages from its cause. An unguarded revoke let any `can_manage_keys` holder do that to every group in the system.
  - **Self-targeting is refused outright** for non-masters, on both paths. Granting to yourself is a ratchet; revoking from yourself rewrites the record of what a master decided about you. A master is exempt — it already has unconditional access to every group.

### 3. IP Management & Query Filtering

- **IPv4 & IPv6 CIDRs:** Full support for single IPs and subnet ranges (e.g., `/24`, `/64`).
- **Rerecord Tracking:** Store `created_at` and `last_seen_at`. Re-registering an existing IP updates `last_seen_at` rather than failing.
- **Multi-Group Membership:** An IP can belong to multiple `IpGroup`s simultaneously.
- **Group Tagging:** A group can be tag as whitelist or banlist. By default it is a banlist.
- **Flexible Fetching (`GET /api/ips`):**
  - Parameter `groups=fail2ban,sshd` (or singular `group_name=fail2ban`): Filters IPs belonging to specified groups. If omitted, returns all IPs accessible to the API Key.
  - Parameter `max_age=3600` or `since=<unix_timestamp>`: Temporal filtering based on `last_seen_at`, applied at the query level (before pagination). (No automatic TTL deletion worker exists; filtering is strictly query-driven).
  - Parameter `ip=<substring>`: Filters by a substring of `target_address`.
  - Parameter `cause=<substring>`: Filters by a substring of `cause`.
  - Parameter `status=ban|white`: Filters to only the group type (`banlist`/`whitelist`) matching the associated IP group.
  - Each result row includes the associated `group_type`, so a single address in both a `banlist` and a `whitelist` group is distinguishable per-row (used by the dashboard's conflict-highlighting badge).

### 4. Advanced & Secure Webhooks

- **Group Scoping:** Webhooks are bound to specific `IpGroup`s. Actions on IPs in those groups dispatch asynchronous HTTP POST requests via Tokio tasks.
- **Templating & Headers:** Custom JSON payload templates (e.g., `{"ip": "$target_address", "group": "$group_name"}`) and custom HTTP headers via `headers_json`.
- **Auth Modes (`webhook_configs.auth_mode`):** each webhook picks how it authenticates to its receiver. The column defaults to `CANONICAL_V1`; the API validates the value and rejects anything unrecognized with `400` rather than silently downgrading.

  | Mode | Signed message | Headers sent |
  | :--- | :--- | :--- |
  | `CANONICAL_V1` *(default)* | the resolved `hmac_template` | `X-Signature-256: <bare hex>`, `X-Timestamp`, plus `X-API-Key` when `api_key` is set |
  | `BODY_ONLY` | `RAW_BODY` only | `X-Signature-256: sha256=<hex>` |
  | `API_KEY_ONLY` | *(none)* | `X-API-Key` |
  | `NONE` | *(none)* | *(none)* |

  - `CANONICAL_V1` with the default template is byte-identical to the inbound API scheme above, which is what makes **instance chaining** work: set `api_key` to a key on the receiving instance, set `secret_token` to *that key's* `signing_secret`, point `target_url` at its `/api/ban`, and the dispatch authenticates as a normal signed API request (including the receiver's own anti-replay check, hence the `X-Timestamp`). This is also the mode `simply_hook_executor` consumes.
  - `BODY_ONLY` is the legacy/generic scheme, matching what GitHub-style third-party receivers expect. Never change an existing webhook's mode without coordinating with its receiver — it changes both the signed bytes and the header set.
  - `API_KEY_ONLY` and `NONE` compute no signature. They are legitimate (an API whose only credential is a bearer-style key; a receiver authenticated by network position) but must stay *explicitly chosen* — never a fallback anyone can drift into.
  - An unrecognized value already in the database falls back to `BODY_ONLY` with a warning rather than erroring — a webhook worker must not be taken down by one bad row. The fallback is deliberately **not** the column default and never `NONE`: an unreadable mode must resolve to *more* authentication, not less.
  - **Per-mode preconditions are enforced at creation, not at dispatch** (`400`): a signing mode needs a non-empty `secret_token` (an HMAC keyed with the empty secret is forgeable while *looking* authenticated), `API_KEY_ONLY` needs an `api_key` (without one it silently becomes `NONE`), and an `hmac_template` must contain `{body}` (a signature that does not cover the payload is replayable across payloads). Deferring these to the background worker would surface them only as a log line, on every future event.
- **Dynamic HMAC templates (`webhook_configs.hmac_template`, `CANONICAL_V1` only):** the exact string to sign, with `{method}`/`{path}`/`{timestamp}`/`{body}` placeholders and `\n`/`\r`/`\t`/`\\` escapes. See `SCHEMA.MD` §6 for the full substitution rules. Two invariants matter:
  1. **Single-pass resolution.** Escapes and placeholders are expanded in one left-to-right scan (`webhooks::resolve_hmac_template`), so substituted values are never rescanned. A two-phase implementation would let a request body containing `{path}` or `\n` — reachable through an IP record's `cause` field — forge field boundaries inside the signed string. Do not "simplify" this into chained `.replace()` calls.
  2. **A literal path overrides `{path}`.** Writing `{method}\n/api/hooks/42/execute\n{timestamp}\n{body}` makes the dispatch sign the path the receiver sees behind a rewriting reverse proxy, while still POSTing to `target_url`. This is the whole mechanism — no proxy-awareness in the dispatcher, no extra column.
- **Credential exposure:** neither `secret_token` nor `api_key` is ever returned by a read endpoint. `GET /api/webhooks` reports `has_api_key: bool` instead; `hmac_template` *is* returned (resolved to its effective value) because it contains only structure, never key material.
- **SSRF Prevention:** Validate target URLs. Reject private/loopback IP ranges (RFC 1918, RFC 4193, loopback) unless `ALLOW_PRIVATE_WEBHOOKS=true` is set in environment.

### 5. Frontend Integration & Dynamic UI

- The UI is a Single Page Application (SPA). Authentication state is held in `localStorage`.
- Single Page Application served from `static/`.
- **Credentials:** the login screen prompts for **both** the API key and its **signing secret**, stored as `simply_ip_vault_key` and `simply_ip_vault_signing_secret`. Both are required; either alone is useless.
- **Request signing:** the global `fetch` wrapper injects `X-API-Key`, computes `X-Timestamp`, and signs every call with `X-Signature-256` over the CANONICAL_V1 string. The secret is used as its raw **UTF-8 bytes** (not hex-decoded), matching the server's `secret.as_bytes()`.
- **Proxy-aware paths — two bases, deliberately separate:**
  - `requestBase` — where requests are **sent**. Derived from the directory this page is served from, so a dashboard mounted at `/vault/` fetches `/vault/api/ips` with no configuration. Served at `/` it yields `/api`, identical to the previous hardcoded value.
  - `signingBase` — what gets **signed**. The path the vault process itself sees *after* the proxy has rewritten the URL, which the browser cannot discover. Set via the login screen's **API Base Path Override** (`localStorage['simply_ip_vault_api_base']`, default `/api`).
  - Never collapse these into one, and never sign `window.location.pathname`: with a prefix-stripping proxy the server verifies `/api/ips` against a signature computed over `/vault/api/ips`, and every request 401s.
- **Two crypto backends, automatically selected:**
  1. **Web Crypto** (`crypto.subtle.importKey` + `crypto.subtle.sign`, HMAC/SHA-256) whenever available — constant-time and fast. The imported `CryptoKey` is memoized per session.
  2. A **self-contained pure-JS HMAC-SHA256** (`sha256Bytes` / `hmacSha256Bytes` at the top of `app.js`) as fallback. `crypto.subtle` exists *only* in a secure context (HTTPS or `http://localhost`), so a homelab instance reached over plain HTTP at a LAN address — the normal way this tool is used — has no Web Crypto at all. Without the fallback the dashboard simply cannot authenticate there.
  - Both paths produce identical bytes. The fallback is **not** constant-time; that is an accepted, documented trade-off, because on a plain-HTTP LAN connection the request and its headers are already fully visible on the wire, so browser timing side-channels are not the weak link. HTTPS remains the recommended deployment.
  - The fallback must stay dependency-free (per the no-external-dependencies rule) and must never be preferred over `crypto.subtle` when the latter exists.
- **Dynamic Permission Rendering:** On startup, `app.js` calls `GET /api/auth/me`. The UI dynamically renders/hides tabs and controls (e.g., Webhooks, Key Management) based solely on the returned permissions based on the RBAC payload received from `GET /api/auth/me`.
- The JS implements a global fetch wrapper that automatically injects the `X-API-Key` header and intercepts `401/403` responses to clear the token and return to the login screen.

### 6. Audit Logging

- Every write/delete operation generates an `AuditLog` entry storing `api_key_id`, `action`, `target_ip`, affected groups, and timestamp.

### 7. Database Bootstrapping

- Database connections use `ConnectOptions` with SQLx logging set to `DEBUG` to prevent console spam.
- Migrations run automatically on startup.
- **Master Key Auto-Gen:** If `api_keys` contains no master keys at boot, generate a default Master Key and output it once clearly to `stdout`.

---

## 🧪 Testing & Validation Standards

- **Integration Tests:** Located in `tests/`. Use SQLite in-memory (`sqlite::memory:`) for test isolation.
- **Coverage Mandatory Requirements:**
  1. **Positive RBAC:** Authorized keys successfully read/write allowed groups.
  2. **Negative RBAC:** Unauthorized attempts MUST return HTTP `403 Forbidden`.
  3. **Webhook Signatures:** Mock HTTP endpoints (e.g., via Tokio task) verifying payload delivery and HMAC `X-Signature-256` validity — for **every** `auth_mode`: `CANONICAL_V1` (bare hex + `X-Timestamp`), `BODY_ONLY` (`sha256=` prefix, no timestamp), `API_KEY_ONLY` and `NONE` (asserting the *absence* of signature headers, not merely delivery). A custom `hmac_template` with a hardcoded path must be verified positively (the template's path validates) **and** negatively (the `target_url`-derived path does not), or the assertion passes for the wrong reason.
  4. **Multi-Group & Temporal Querying:** Validate `GET /api/ips` with group filters and `max_age`/`since` constraints.
  5. **Request Authentication (HMAC):** each of the three auth headers is individually mandatory (`401` when any is dropped — in particular the pre-HMAC "key + timestamp only" shape); the anti-replay window is enforced symmetrically at ±300s using *correctly signed* stale/future timestamps, so the rejection provably comes from the freshness check and not the HMAC; and the signature binds method, path, and body (replaying an authentic signature over a tampered body, or onto a different route, MUST fail).
  6. **Signing Secret Handling:** a `NULL` `signing_secret` fails closed; `signing_secret` never appears in any read endpoint's response; and with `VAULT_ENCRYPTION_KEY` set, the stored value is ciphertext yet still authenticates (round trip through the real request path).

*Test-suite convention:* keys seeded directly into the database use a deterministic signing secret derived from their plaintext key, so the request-building helper can rediscover it from the `X-API-Key` header. Keys minted through `POST /api/keys` or `/rotate` carry a server-generated random secret and must be signed with it explicitly.

Compilation via `cargo build` or `cargo check` is recommended to validate syntax. Integration tests reside in `tests/` using SQLite in-memory (`sqlite::memory:`).

To test endpoints manually during development, requests must be signed. A bare `curl -H "X-API-Key: ..."` no longer authenticates. Use this helper (it is the same computation `scripts/test_e2e.sh` performs):

```bash
KEY="<PLAINTEXT_API_KEY>"
SECRET="<SIGNING_SECRET>"          # returned once by POST /api/keys or /rotate

# call METHOD PATH [JSON_BODY]  — PATH excludes the host, includes the query string.
call() {
  local method="$1" path="$2" body="${3:-}"
  local ts; ts=$(date -u +%s)
  # CANONICAL_V1: the four fields joined by real newlines, no trailing newline.
  # The FULL path is signed, query string included — do not strip it.
  local sig; sig=$(printf '%s\n%s\n%s\n%s' "$method" "$path" "$ts" "$body" \
                   | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.*= //')
  curl -sS -X "$method" \
    -H "X-API-Key: $KEY" -H "X-Timestamp: $ts" -H "X-Signature-256: $sig" \
    ${body:+-H "Content-Type: application/json" -d "$body"} \
    "http://localhost:3000$path"
}
```

- **Auth check:**
  `call GET /api/auth/me`
- **Ban an IP (adds it to a banlist group):**
  `call POST /api/ban '{"target_address": "192.168.1.100/32", "group_name": "fail2ban", "cause": "SSH brute force"}'`
- **List IPs (Filtered by groups):**
  `call GET "/api/ips?groups=fail2ban,sshd&limit=10"`
- **Delete IP:**
  `call DELETE "/api/ips?target_address=192.168.1.100/32&group_name=fail2ban"`

Note the query string is **part of the signed target** — see the signing rules in §1. Repeating an identical call within the same second is a replay and returns `401`; wait a second or vary the request.

### 1. Mandatory Test Matrix per Endpoint
For every route registered under `/api`, tests MUST assert three distinct outcomes:
  1. **Positive Assertion (200/201 OK):** Valid payload with sufficient permissions returns expected JSON structure and persists changes in DB.
  2. **Authentication Check (401 Unauthorized):** Missing, invalid, or revoked `X-API-Key` header immediately rejects the request.
  3. **Authorization Boundary (403 Forbidden):** Valid API key lacking explicit scope or group permission is denied access.
  4. **Validation Check (400 Bad Request):** Malformed CIDR blocks, bad URLs, or invalid JSON payloads are rejected before processing.

### 2. Required Endpoint Test Coverage

  - **Authentication Profile (`GET /api/auth/me`):**
    - Verify returned global scopes and group permissions match the database state.
  - **IP Records (`POST /api/ban`, `POST /api/white`, `GET /api/ips`, `DELETE /api/ips`):**
    - Verify IP insertion and `last_seen_at` updates on duplicate records.
    - Test filtering via `?groups=g1,g2` and temporal filtering via `?max_age=3600`.
    - Assert non-authorized keys cannot write to groups where `can_write = false`.
  - **API Keys Management (`GET /api/keys`, `POST /api/keys`, `DELETE /api/keys/{id}`, `POST /api/keys/{id}/permissions`):**
    - Test master-only access for key generation and revocation.
    - Verify cascading deletion cleans `api_key_group_permissions` without orphan records.
  - **Group Management (`GET /api/groups`, `POST /api/groups`, `DELETE /api/groups/{id}`):**
    - Test auto-provisioning of permissions when a key creates a new group.
  - **Webhooks (`GET /api/webhooks`, `POST /api/webhooks`, `DELETE /api/webhooks/{id}`):**
    - Verify URL validation (HTTP/HTTPS required, private IPs blocked).
    - Test HMAC SHA-256 signature header (`X-Signature-256`) generation.
    - Test `auth_mode` validation and each mode's preconditions (`400`), and that `secret_token`/`api_key` never appear in a listing.
  - **Audit Trail (`GET /api/audit-logs`):**
    - Verify mutating actions write audit entries and read access is restricted to `is_master` keys.

### 3. API Contract Flexibility & Lifecycle Validation
  - **Query & Group Identification:**
    Endpoints manipulating group permissions (`/api/keys/{id}/permissions`) or records (`/api/ips`, `/api/ban`, `/api/white`) MUST accept both `group_id` (UUID) and `group_name` (string) seamlessly.
  - **Flexible Body / Query Deserialization (`DELETE /api/ips`):**
    `DELETE /api/ips` MUST accept parameters both via URL Query strings (`?target_address=...&group_name=...`) and via JSON request body (`{"target_address": "...", "group_name": "..."}`).
  - **Key Rotation & Editing:**
    `POST /api/keys/{id}/rotate` MUST generate a new secret while keeping key ID/name intact and invalidating the old secret. `PUT /api/keys/{id}` MUST allow updating key name, bound IPs, and global scopes.
  - **Signing-Secret Rotation (`POST /api/keys/{id}/rotate-secret`):**
    Replaces **only** the HMAC `signing_secret`, in place. The key's id, name, `key_hash`/`X-API-Key`, `bound_ips`, global scopes, and every `api_key_group_permissions` row MUST be left untouched — this is the narrow sibling of `/rotate`, for routine credential hygiene without forcing a full identity change on every client. It is also the documented recovery path for a key whose `signing_secret` is `NULL` (created before HMAC auth existed).
    Master or `can_manage_keys` only; writes a `KEY_SECRET_ROTATE` audit entry; returns the new secret exactly once and MUST NOT reissue `plaintext_key`. The previous secret stops working immediately.
  - **Revoking Group Permissions:**
    `DELETE /api/keys/{id}/permissions/{group_identifier}` MUST remove specific group permission mappings from a key.
  - **Audit Log Interface & Endpoint:**
    All mutating actions MUST write audit logs, accessible via `GET /api/audit-logs` for Master keys and rendered in a dedicated UI panel.

*End of directives. Write safe, panic-free (`no .unwrap()`), and elegant Rust code.*