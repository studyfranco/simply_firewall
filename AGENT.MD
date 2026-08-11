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

## 🔄 Peer Repository Synchronization

`example/` holds working clones of the sibling services this project is kept convergent with —
currently `example/simply_hook_executor`. They are **real git clones with their own remotes**, not
flat snapshots.

### Mandatory: pull before you analyse

**Before reading any source under `example/`, and before producing a convergence, parity, or security
report, run:**

```bash
git -C example/<peer_repo> pull
```

Do this even when the directory looks current. An audit that compares against a stale clone certifies
agreement with code that no longer exists, and it does so *silently* — every check passes, the report
reads clean, and the conclusion is worthless. This has already happened once: a snapshot that had
drifted by nineteen files, including six under `src/api/`, was audited as though it were current.

Log the outcome of the pull ("Already up to date", or the commit range) in `AGENT_NOTES.MD` alongside
the report. A reader needs to know *which* peer commit a conclusion was drawn from; "the peer" is not
a reference anyone can check later.

`./scripts/verify_convergence.sh` performs this pull automatically, so running the gate satisfies the
requirement for its own comparisons. It does **not** satisfy it for reports you write by reading files
directly — do it yourself in that case.

### Two things not to do

- **Do not `rsync` over a peer clone.** `rsync --delete` *protects* excluded paths rather than
  removing them, so `--exclude=.git` leaves the clone's git directory intact but its worktree
  overwritten — and any local commits unreachable. Use `git pull`.
- **Do not commit inside `example/`.** These are read-only references. `example/*` is gitignored here,
  so changes made there are invisible to this repository's history and will be lost on the next sync.

---

## 🎯 Project Overview

`simply_ip_vault` is an enterprise-grade, central Firewall and ACL management API written in Rust. It acts as the single source of truth for IP banning/whitelisting and dispatches signed, templated webhook events to downstream systems or other `simply_ip_vault` instances. It features an integrated Vanilla JS dashboard governed by a granular multi-tenant Role-Based Access Control (RBAC) system.

---

## 🛠️ Tech Stack & Constraints

- **Backend:** Rust + Axum (0.8+) + Tokio (1.x).
- **ORM (SQL-Agnostic):** SeaORM (2.0+). Defaults to **SQLite** for zero-config local development/testing, but MUST remain strictly **SQL-agnostic** (PostgreSQL-ready). **Never write vendor-specific raw SQL queries.**
  - **Zero raw SQL for DML in `src/`.** No `execute_unprepared`, no `Statement::from_string`, no `*_raw`, and no string-built queries for `SELECT`/`INSERT`/`UPDATE`/`DELETE`. Use typed entity methods (`Entity::find()`, `ActiveModel`) or SeaQuery builders. This is not a style rule: a hand-built statement is a place where a `WHERE owner_key_id = …` can be forgotten — a tenancy breach that compiles — and where a value can be interpolated instead of bound. The entity API makes the first a type error and the second impossible.
  - Two exemptions, both narrow. **`src/migration/`**, where DDL genuinely cannot be expressed portably (generated columns, per-engine storage classes) and is reviewed as schema rather than as queries. And **`PRAGMA`** in `apply_sqlite_pragmas`, which configures the *engine* rather than querying it, is SQLite-only, and has no typed representation in SeaORM at all.
  - Enforced by `scripts/verify_convergence.sh` (`check_no_raw_sql`). Outside `src/db.rs` there is **no** exemption — any raw-SQL call is a finding. Inside `db.rs` the test is what the statement *does*: a hit is reported when `SELECT`/`INSERT INTO`/`UPDATE`/`DELETE FROM` appears in its window. An earlier version exempted anything near the word "pragma", which that file contains almost everywhere, and reported CLEAN against a planted `execute_unprepared("DELETE FROM api_keys")`.
- **Database setup lives in `src/db.rs`**, not in `state.rs`: `connect`, `apply_sqlite_pragmas`, and `run_migrations`, mirroring `simply_hook_executor`'s module of the same name.
  - **The SQLite pool holds exactly one connection, and that is load-bearing.** SQLite permits one writer, and a DDL sequence spread across connections does not survive: `m20260808_000009` drops `master_marker` and re-adds it as a generated column, and at any pool size ≥ 2 the `ADD` reaches a connection whose schema still has the old one (`duplicate column name`). SeaORM's `Database::connect` pins this to 1 for SQLite; hand-building a pool opts out of that default **silently**, which is how it got broken once already. `SQLITE_MAX_CONNECTIONS` restores it and a test asserts it against the live pool.
  - **Four session pragmas**, set through `SqliteConnectOptions` so they are replayed when SQLx reopens a connection: `foreign_keys=ON`, `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`. The first two are already SQLx defaults — measured, not assumed — so those calls are assertions rather than changes. Only `journal_mode` is persistent (file header); the rest are per-connection, which is invisible here only because the pool holds one connection.
  - `apply_sqlite_pragmas` is still called at startup and is still never fatal: it reads `journal_mode` back so the log reports what actually took effect. An in-memory database legitimately cannot use WAL, and the whole test suite runs on one.
- **Module layout:** `src/api/` is split by domain — `guards.rs` (every authorization decision), `keys.rs`, `records.rs`, `groups.rs`, `webhooks.rs`, `audit.rs`, and `mod.rs` for helpers more than one domain needs. `mod.rs` re-exports every item flat, so `api::create_api_key` resolves exactly as it did when this was one 3,674-line file: the router, the integration suites, and `scripts/` needed no changes. **The paths are the API; the files are an implementation detail** — do not "tidy" the re-exports into module-qualified paths.
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
  | `X-Signature-256` | `sha256=<hex>` — HMAC-SHA256 over the **CANONICAL_V1** string (below), keyed with the key's `signing_secret`. The `sha256=` prefix is **mandatory**; a bare hex digest is rejected with `401`. |

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
  - **Storage prefixes — exactly two, and the set is closed:** `v1.xchacha20poly1305.<nonce>.<ct>` (encrypted) and `v1.plain.<hex>` (unencrypted). Nothing else is readable.
  - **`open()` is strictly fail-closed:** a stored value carrying neither prefix is a `CryptoError::MalformedCiphertext`, surfacing as `500`. Two shapes have been retired from this list, both for the same reason:
    - *(2026-08-02)* An **unprefixed bare secret** used to be returned verbatim. That was a silent failure mode wearing a compatibility costume — "no recognized prefix" is not evidence of a pre-prefix row, and every other cause is worse. A `v1.plain.` value whose prefix was lost to a botched migration, a truncated column, or a partial write would have had its surviving text fed to `Hmac::new_from_slice` as key material, producing a fleet of `401`s that point at the client rather than at the database.
    - *(2026-08-02, cleanup pass)* The **`aesgcm256:<nonce><ct>`** read path is gone, along with the `aes-gcm` dependency and the SHA-256-of-the-raw-env-text key derivation that fed it. It was a decrypt-only bridge with no writer, kept alive solely for rows predating XChaCha20-Poly1305; keeping a second AEAD and a second key-derivation rule compiled in to serve a format the service can no longer produce is cost without a corresponding risk reduction. `SecretCipher::Sealed` is now a one-field variant holding only the XChaCha20 cipher.
    - **Upgrade note (both retirements):** a deployment still holding an unprefixed **or** an `aesgcm256:` secret must rotate it (`POST /api/keys/{id}/rotate-secret`, master-only) *before* upgrading, or that key stops authenticating with a `500`. Rotation is per key and leaves `key_hash`, `bound_ips`, scopes and all group grants untouched. **Check for stragglers before deploying:** `SELECT id, name, prefix FROM api_keys WHERE signing_secret IS NOT NULL AND signing_secret NOT LIKE 'v1.%';`
- **CIDR Restriction:** API Keys are bound to CIDR network ranges (`bound_ips`, supporting comma-separated IPv4/IPv6 ranges like `127.0.0.1/32, 10.0.0.0/8, ::/0`). Middleware MUST validate the client's IP against these bounds.
- **Resilient IP Extraction:** Do NOT use external IP extraction crates. `X-Forwarded-For`/`X-Real-IP` are honoured **only when the TCP peer is itself a configured `TRUSTED_PROXIES` member**; otherwise the peer address is authoritative. When the peer is trusted, the chain is walked **right to left, skipping hops that are themselves trusted proxies**, stopping at the first untrusted one — rightmost-first is what makes a client-supplied prefix unforgeable, and skipping trusted hops is what makes a *chain* work. Falls back to `ConnectInfo` whenever the headers are absent, unparseable, or name nothing but proxies. `TRUSTED_PROXIES` accepts CIDRs, bare addresses, and **hostnames** (resolved with a 30s positive / 5s negative TTL, so a dead name cannot trigger a lookup per request). An unresolvable entry disables **that entry only** and never the service. This walk is byte-identical to `simply_hook_executor`'s; `scripts/verify_convergence.sh` asserts it.
- **Listen address:** `BIND_HOST` (or `HOST`) and `PORT`, defaulting to `0.0.0.0:3000`. The host must be a literal IP — resolving a name could yield several addresses with no principled way to choose, and binding the wrong interface is a security problem.
- **Request body ceiling:** a single router-wide `DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES)` = **3 MiB**, applied outside the `/api` nest so it also covers the static fallback. `middleware::MAX_SIGNED_BODY_BYTES` is *derived from the same constant* — two independently-chosen limits would leave a band of sizes accepted by one layer and refused by the other.

### 2. Granular Multi-Tenant RBAC (M:N)

> **`RBAC_MODEL.md` is normative for everything in this section.** It is the byte-identical
> specification shared with `simply_hook_executor`, and where it and this document disagree, this
> document is stale. Rules are cited below by their identifiers there (R1–R7, §3–§7).

- **Three tiers, and the boundary between the lower two is one flag.** `RBAC_MODEL.md` §2:
  - **Master** — `is_master`. Exactly one exists (§5), *and its identity is pinned at startup* (below). Bypasses all checks.
  - **Parent** — `can_manage_keys == true`. May create keys, but every key it creates is a Daughter.
  - **Daughter** — `can_manage_keys == false`. Cannot create or manage keys at all.
- **Global Rights:** An `ApiKey` can be `is_master` (bypasses all checks) or hold global booleans (`can_manage_keys`, `can_manage_webhooks`, `can_create_groups`). All three booleans are **Master-granted only** (R4): `guard_scope_elevation` refuses a non-master requesting any of them with `403`, on create and on update alike. A Parent creating a key therefore produces a Daughter by construction — not because the handler forces the flags to `false`, but because a payload asking for them is rejected outright. Refusing beats silently forcing: a caller that asked for `can_manage_keys` and got a `200` would walk away believing the key holds it.
  - **Revocation is not elevation.** The guard blocks `Some(true)` over a currently-false scope; `Some(false)` is permitted, and an *omitted* field leaves the scope unchanged. The dashboard relies on this — see the UI section.
- **Master Key Guarantees (`RBAC_MODEL.md` §5):** exactly one Master key exists, and the API cannot create, alter, or remove it.
  - **Uniqueness is a schema invariant, and the engine derives it.** `api_keys.master_marker` is `INTEGER GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` under a **plain unique index**. A marker column rather than a partial unique index on `is_master = true`, because MySQL has no partial indexes and the data layer stays SQL-agnostic; NULLs do not collide on any supported engine. Application logic alone was never sufficient — `bootstrap_master_key` checks then inserts, which two processes starting together both pass.
    - **The marker must never be application-maintained.** It was, until `m20260808_000009`, and that did not satisfy §5: a writer could set `is_master = true` and omit the marker, NULLs do not collide, and the database accepted a second master. Verified live. The column is deliberately **absent from `api_key::Model`** — SeaORM builds column lists from the entity, so its absence is what keeps it out of every `INSERT`, and every engine rejects a write naming a generated column. Do not add the field back. See `SCHEMA.MD`, "Master Uniqueness".
  - **`is_master` is bootstrap-only, and the *type* is what enforces it.** The field is absent from `CreateApiKeyPayload` and `UpdateApiKeyPayload`, both of which carry `#[serde(deny_unknown_fields)]`, so a payload naming it is refused during deserialization and never reaches a handler. `crate::extract::StrictJson` renders that as **`400`** with serde's own message. §5 requires exactly this shape — "rejecting it at the handler is not sufficient, since a later handler can reintroduce the path" — and a handler guard (`guard_no_master_flag`) did the job until it was deleted in favour of the type. Note the two halves are both needed: removing the field without `deny_unknown_fields` makes serde *ignore* it, which is worse than either accepting or rejecting, because a caller that posts `is_master: true` and gets a `200` walks away believing it holds a master key. The dashboard's "Master Access" checkbox was removed for the same reason.
  - **The Master is immutable through the API except for its own `bound_ips`,** which it alone may edit. Renaming, re-scoping, both rotation endpoints, and deletion are all refused (`guard_master_immutable`). A payload mixing `bound_ips` with any other field is refused whole rather than partially applied.
  - **Why rotation is refused, when it is the one credential most worth rotating.** `POST /keys/{id}/rotate` returns the new plaintext in its response body, so an API-reachable master rotation is an API-reachable way to mint a working master credential from any session that already holds one. Re-minting is instead: delete the row directly in the database; the service re-mints at next boot. That requires database access, which an HTTP-only compromise does not have.
  - **Upgrade path.** The migration backfills a single existing master and **refuses to run** on a database that already holds two, naming the offending ids and the `UPDATE` that resolves it rather than silently demoting someone.
  - **Identity is pinned at boot, and that is a different guarantee from uniqueness.** `main.rs` calls `AppState::pin_master_key()` after migrations and **before binding the listener**: it asserts exactly one row has `is_master`, asserts the §5 unique index is still present, and stores that row's id in a write-once `OnceLock`. All three failures are fatal — a service that cannot say which key is Master would answer the question with whichever row a query returned first.
    - **Why the unique index is not enough.** It guarantees *at most one* master row; it says nothing about **which**. An attacker with database access does not need two masters: demoting the real one and promoting itself keeps the count at exactly one and satisfies every constraint. Uniqueness defends cardinality, pinning defends identity, and neither substitutes for the other.
    - **Enforced at the boundary, not in the guards.** `middleware.rs` clears `is_master` on the key model before it enters the request extensions unless the id matches the pin. There are ~40 downstream reads of `key.is_master`; putting the check in each would mean the first guard written without it is a silent hole. Demoted rather than rejected, because a promoted row is still a valid key holding whatever scopes it legitimately has — and a `401` here would make the flag observable to the caller.
    - The pin never moves once set. Re-resolving on any later event (a reconnect, a reload, a future admin endpoint) would hand back exactly what pinning denies.
- **Group Rights:** Managed via junction table `ApiKeyGroupPermission` linking keys to `IpGroup` with explicit flags (`can_read`, `can_write`, `can_delete`, `can_manage`).
- **Least Privilege:** `can_write` or `can_delete` require `can_read` to be true.
- **Auto-Provisioning:** When an API Key creates a new `IpGroup`, the backend MUST automatically generate full read/write/delete permissions for that key on the new group.
- **Managing a group is a conjunction (R2), and it is the same test in both directions.** To touch *any* key's permission rows on a group, a non-master must hold **both** the global `can_manage_keys` scope **and** `can_manage = true` on its own row for that group. `RBAC_MODEL.md` R2: "Neither alone is sufficient. `can_manage_keys` is never a global bypass of per-resource RBAC."

  | Caller holds | Grant / widen | Revoke / reduce |
  | :--- | :--- | :--- |
  | `can_manage_keys` only (no row, or a row without `can_manage`) | ❌ | ❌ |
  | `can_manage` on the group only (no global scope) | ❌ | ❌ |
  | **Both** | ✅, bounded per verb | ✅ |
  | `is_master` | ✅ | ✅ |

  Each half answers a different question and neither is useful alone. `can_manage_keys` is authority over **credentials** — it says the caller may administer keys at all, and nothing about *which* groups it may reach; on its own it made per-group RBAC advisory, since a key scoped to one group could rewrite every other key's access to every group in the installation. `can_manage` is authority over **one resource** — it says which group; on its own it admitted a key holding no global scope whatsoever to rewriting other keys' credentials, which is exactly the tier boundary §1 draws (a Daughter key "may never" manage resources).
  - **Granting is additionally bounded per verb (R1 + R7).** Each verb being conferred is checked independently against the caller's own row: holding `can_read` does not confer the right to grant `can_write`. R7 states the composition — "Granting is bounded by R1 and R2 together, simultaneously and without exception."
  - **Revoking requires no proof over the verb removed, and self-revocation is permitted (R6).** Removing a verb raises nobody's authority, the caller's included. The threat it carries is **integrity** — this service keeps `fail2ban`-style automation writing to shared banlists, so stripping the key that maintains another tenant's list stops that tenant's blocking, a denial-of-service presenting as "bans stopped landing" several audit-log pages from its cause — and R2's conjunction is what bounds it.
  - **Classification is by effect, not by route (R6, final sentence).** A payload to the update endpoint that adds a verb the target lacks (or creates the row) is a grant; one that only lowers an existing row is a revocation reached through the general endpoint instead of the dedicated one. `widens_permissions` decides which rule applies, so "revoke the row" and "update the row to a lower value" can never drift apart. Both share the same R2 admission test; the classification only decides whether the per-verb R1 ceiling applies on top.
  - **Only Master grants any global scope (R4).** `MASTER_ONLY_SCOPES` is `can_manage_keys`, `can_create_groups`, **and `can_manage_webhooks`**. §1 puts resource-creation rights at the same tier as `can_manage_keys`, granted strictly by Master and never implied by it — "managing keys and being able to point a dispatch target at an arbitrary URL are separate powers." `can_manage_webhooks` was previously delegable on the reasoning that it "confers no authority over keys or groups"; that reasoning was too narrow. A webhook is a standing export of everything happening in a group to a URL its creator chooses, and the scope was **freely amplifiable** — a parent that did not hold it could hand it out, which is R1's plainest violation. Because every global scope is now master-only, R1's "may only grant rights it currently holds" is satisfied for globals by the strictly stronger R4.
  - **Creating a group does not confer authority over it (R2).** Auto-provisioning grants the creator read/write/delete and **not** `can_manage` — creating a resource does not mint the row R2 requires. A Parent that creates a group can therefore use it but cannot delegate access to it until a Master grants `can_manage`. This is a deliberate consequence of R2, not an oversight; `owner_key_id` (§3) is where creator authority is due to live.
- **Lineage & Ownership (`RBAC_MODEL.md` §3, R3).** Two columns, and the distinction between them is load-bearing.
  - **`api_keys.parent_key_id`** records who created a key. **R3: it confers no authority.** "`parent_key_id` exists solely for cascading deletion and visibility scoping. A daughter of the Master key is an ordinary daughter key with no elevated standing. Rights are never derived from key lineage." No permission guard reads it, and a differential test asserts two keys with identical scopes and grants answer every authority question identically regardless of who created them.
  - **`ip_groups.owner_key_id` / `webhook_configs.owner_key_id`** carry **lifecycle authority**: deleting or renaming the entity itself is restricted to the Master and the owner. §3 names what does *not* confer it — "Holding manage rights or any operational verb confers no lifecycle authority: a parent that merely uses a resource must not be able to delete it." `can_manage` is authority over a resource's **permission rows**; ownership is authority over its **existence**. Conflating them means the key trusted to hand out read access can also delete the thing everyone is reading.
  - **Ownership is granted, never traded.** `PUT /api/groups/{id}/owner` and `PUT /api/webhooks/{id}/owner` are **master-only**, and deliberately not delegable to the current owner: a transferable owner flag would let a tenant pass the authority-to-destroy onward without the master who granted it seeing the transfer — the same amplification R1 forbids for verbs, one level up. A master key cannot itself be recorded as an owner; `NULL` already means master-only, and two spellings of one state invite guards that check the wrong one.
  - **A webhook is a dispatch target, not resource data.** §4: "visible exclusively to their creator and Master … never exposed by the shared-resource rule." Read, update and delete are scoped by `owner_key_id`, **not** by readability of the group it watches — which is what they used to be, meaning any `can_manage_webhooks` holder with `can_read` on a group could edit or delete another tenant's integration in it. A webhook outside the caller's scope answers `404`, not `403`.
  - **No group-rename endpoint exists**, so §3's rename clause is vacuous for groups today; it binds `PUT /api/webhooks/{id}`, which does rename.
- **Visibility Scopes & Oracle Discipline (`RBAC_MODEL.md` §4).** Three scopes, and two distinct disclosure controls that must both hold.

  | Scope | Who | What is visible |
  | :--- | :--- | :--- |
  | Master | `is_master` | everything, in full |
  | Own subtree | a key and its `parent_key_id` descendants | full, minus raw secrets: global flags, `bound_ips`, all group rights |
  | Shared resource | a key holding a permission row on a group the caller **manages** (R2's conjunction) | **minimal only**: id, name, and that key's rights *on the shared groups alone* |
  | Dispatch target | `webhook_configs` | creator (`owner_key_id`) and Master only; never exposed by the shared-resource rule |

  - `GET /api/keys` returns each entry tagged `"view": "full"` or `"view": "minimal"`. An absent field in the minimal shape means **withheld**, not `false` — the dashboard reads `view` rather than inferring from absence, because rendering a withheld flag as `false` would describe another tenant's key as unprivileged. It previously returned **every key in the system in full** to any `can_manage_keys` holder, which §4 names directly: "A single shared resource must never become a keyhole into another parent's whole configuration."
  - **Credential operations are bounded by the own-subtree scope, not the shared one.** Seeing a key's name because it shares a group is not authority to rotate its credential, so `PUT`/`DELETE /api/keys/{id}` and both rotation endpoints resolve through the subtree and answer `404` outside it.
  - **Oracle discipline.** An id outside the caller's visibility scope returns the **identical status and body** a nonexistent id would. This replaced a `403` from `guard_master_target` whose stated reasoning — "the caller can already see the key in `GET /api/keys`" — was true when listing was unscoped and is false now; a `403` on `POST /keys/{id}/rotate` was a way to enumerate the master key.
  - **This must not be satisfied by regressing authenticate-then-authorize.** Those are two different controls over two different callers: oracle discipline governs an *authenticated* caller distinguishing absent from invisible; the `401`-before-`403` ordering governs an *unauthenticated* caller probing key bindings. Collapsing every refusal into `404` would turn a CIDR rejection into "no such key", which is the inference the ordering rule exists to prevent. A refusal that is a property of the **caller** (a missing global scope) is correctly a uniform `403` for every id; only refusals that vary *with the id* need to be `404`.
- **Cascade Deletion & Pre-flight Inventory (`RBAC_MODEL.md` §6).** `DELETE /api/keys/{id}` deletes a *subtree*, and refuses until every resource that subtree owns has an explicit fate.
  1. Walk the target's entire `parent_key_id` subtree.
  2. Inventory every group and webhook owned by **any** key in it — the entire subtree, not just the target. A daughter's webhook would otherwise vanish silently, which §6 forbids.
  3. Non-empty inventory with no resolution map → **`409`** plus the inventory itself: `entity_type`, `id`, `name`, `owner_key_id`, `owner_name` per entity, and `subtree_key_count`.
  4. On resubmission, require a resolution for **every** inventoried entity. Partial maps are refused; so is one naming an entity outside the inventory; so is a duplicate.
  5. Only then write: resolutions first, then the whole subtree. `api_key_group_permissions` follows by foreign key — and nothing else does, which is the point.
  - **Body on `DELETE`.** Optional, parsed from `Bytes` rather than `Json<T>` because an empty body has always been valid here and `Json` rejects one. `{"resolutions": [{"entity_type": "group"|"webhook", "id": "...", "action": "delete"} | {"action": "reassign", "owner_key_id": "..."}]}`.
  - **Every validation runs before the first write.** A partial map that applied the resolutions it *did* carry before discovering the gap would destroy data the caller never decided about — so the refusal leaves the installation byte-identical, and the tests assert that rather than the status code.
  - **Reassigning into the doomed subtree is refused.** It reads as a rescue and is a deferred orphaning: the new owner disappears microseconds later and the entity lands unowned, which is master-only.
  - **Why refuse rather than cascade.** Deleting a key is routine credential hygiene; deleting the banlist that key maintained is not, and the two must not be spelled the same way. §6: "Data is never destroyed implicitly."
  - **A master's view never depends on a permission row.** Because the last manager of a group can revoke itself, a group can end up with no rows at all. Every master read path (`list_ip_groups`, `list_ips`) branches on `is_master` *before* consulting `api_key_group_permissions`, so such a group stays listable, viewable, and re-grantable rather than becoming invisible until someone queries the database directly.

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
  | `CANONICAL_V1` *(default)* | the resolved `hmac_template` | `X-Signature-256: sha256=<hex>`, `X-Timestamp`, plus `X-API-Key` when `api_key` is set |
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
- **Dynamic Permission Rendering:** On startup, `app.js` calls `GET /api/auth/me` and `enforceRBACUI()` renders the interface for the key's tier. The tier is *derived* from the returned flags by `keyTier(k)` — `is_master` → Master, else `can_manage_keys` → Parent, else Daughter — rather than sent as its own field, so there is no second source of truth that can disagree with the flags beside it.
  - **Master:** everything.
  - **Parent:** the key-creation form, without the Master-only scope toggles. It sees `#apikey-scope-note` explaining R4 instead. Same treatment on the edit modal.
  - **Daughter:** no key-creation form at all, and no group/webhook creation forms. Listings stay — a Daughter granted access to a group must still see it.
  - Tier badges (`badge-tier-master` / `-parent` / `-daughter`) appear on every full-view row of the Keys table and on a header chip for the signed-in key. **Never on a `view: "minimal"` row**: tier is derived from global flags, and §4 withholds those in the minimal view, so labelling such a key "Daughter" would assert the absence of scopes the caller was not shown.
  - **Hidden, not disabled.** A disabled *unchecked* checkbox beside a key that actually holds the scope reads as "this key does not have it", which is a false statement rendered in UI.
  - **Master-only fields are omitted from the payload, not sent as `false`.** This is load-bearing on the edit form: `update_api_key` treats an absent field as "unchanged" and a present one as an assignment, and `guard_scope_elevation` permits `Some(false)` as a revocation. If the hidden checkboxes were still submitted, a Parent renaming a Daughter that Master had granted `can_create_groups` would silently revoke it — the checkbox reads `false` because it is hidden, not because the key lacks the scope.
- The JS implements a global fetch wrapper that injects `X-API-Key` and signs every request. **`401` and `403` are handled differently, and must stay that way:** `401` means the credential is invalid, so the session is cleared and the login screen returns; `403` means the key is valid but lacks permission for this one action, so the server's specific message is surfaced as a toast and the session is left alone. A `403` also triggers `resyncCapabilities()`, which re-reads `/auth/me` and re-applies the gating in the background — a refusal usually means this UI's picture of the key's rights is stale, and the offending control should disappear rather than stay there to be clicked again.

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
  3. **Webhook Signatures:** Mock HTTP endpoints (e.g., via Tokio task) verifying payload delivery and HMAC `X-Signature-256` validity — for **every** `auth_mode`: `CANONICAL_V1` (`sha256=` prefix + `X-Timestamp`), `BODY_ONLY` (`sha256=` prefix, no timestamp), `API_KEY_ONLY` and `NONE` (asserting the *absence* of signature headers, not merely delivery). A custom `hmac_template` with a hardcoded path must be verified positively (the template's path validates) **and** negatively (the `target_url`-derived path does not), or the assertion passes for the wrong reason.
  4. **Multi-Group & Temporal Querying:** Validate `GET /api/ips` with group filters and `max_age`/`since` constraints.
  5. **Request Authentication (HMAC):** each of the three auth headers is individually mandatory (`401` when any is dropped — in particular the pre-HMAC "key + timestamp only" shape); the anti-replay window is enforced symmetrically at ±300s using *correctly signed* stale/future timestamps, so the rejection provably comes from the freshness check and not the HMAC; and the signature binds method, path, and body (replaying an authentic signature over a tampered body, or onto a different route, MUST fail).
  6. **Signing Secret Handling:** a `NULL` `signing_secret` fails closed; `signing_secret` never appears in any read endpoint's response; and with `VAULT_ENCRYPTION_KEY` set, the stored value is ciphertext yet still authenticates (round trip through the real request path).

- **Adversarial tests for infrastructure claims (mandatory).** Any guarantee this codebase claims at
  the **database, type-system, or extractor** layer requires at least one test written from the
  perspective of an **uncooperative writer** — one that bypasses the application entirely (raw SQL, or
  a payload the type cannot express). A test that reaches the guarantee through our own handlers,
  entities, or fixtures can only ever prove that *our* code behaves; it cannot distinguish "this is
  impossible" from "we always do it correctly".

  This is not a style preference. §5's master-uniqueness constraint was bypassable for six phases while
  every signal said otherwise: the compliance test passed, the mutation fired, `AGENT_NOTES.MD` and the
  migration's own doc comment both asserted schema-level enforcement. All of them were blind for one
  reason — the test supplied the uniqueness marker itself, so it exercised a cooperative writer. A
  direct `INSERT` setting `is_master` with the marker omitted was accepted on a live database.

  Mark such tests `ADVERSARIAL(§N)` in their doc comment. `scripts/verify_convergence.sh` fails when an
  infrastructure-level rule (currently §5 and §7) has none. Application *decisions* — R1–R7, §3, §4,
  §6 — are deliberately exempt: they are made by handlers, so exercising the API is the correct way to
  test them, and demanding impossible evidence is how a gate gets switched off.

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
    -H "X-API-Key: $KEY" -H "X-Timestamp: $ts" -H "X-Signature-256: sha256=$sig" \
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
    `POST /api/keys/{id}/rotate` MUST generate a new secret while keeping key ID/name intact and invalidating the old secret. `PUT /api/keys/{id}` MUST allow updating key name, bound IPs, and global scopes. **Neither reaches the Master key** — see the Master Key Guarantees in §2; the Master's only API-editable field is its own `bound_ips`, and both rotation endpoints and `DELETE` refuse it outright.
  - **Signing-Secret Rotation (`POST /api/keys/{id}/rotate-secret`):**
    Replaces **only** the HMAC `signing_secret`, in place. The key's id, name, `key_hash`/`X-API-Key`, `bound_ips`, global scopes, and every `api_key_group_permissions` row MUST be left untouched — this is the narrow sibling of `/rotate`, for routine credential hygiene without forcing a full identity change on every client. It is also the documented recovery path for a key whose `signing_secret` is `NULL` (created before HMAC auth existed).
    Master or `can_manage_keys` only; writes a `KEY_SECRET_ROTATE` audit entry; returns the new secret exactly once and MUST NOT reissue `plaintext_key`. The previous secret stops working immediately.
  - **Key Deletion (`DELETE /api/keys/{id}`):**
    Deletes the target **and its entire `parent_key_id` subtree**, gated on §6's pre-flight inventory. Takes an optional JSON body carrying the resolution map. Returns `409` with the inventory when resources are owned and unresolved, `400` for a malformed, over-complete or self-defeating map, `204` on execution. The master key is refused outright (§5), as is self-deletion.
  - **Resource Ownership Reassignment:**
    `PUT /api/groups/{id}/owner` and `PUT /api/webhooks/{id}/owner`, body `{"owner_key_id": "<uuid>|null"}`. **Master-only** (§3). Refuses a nonexistent key and refuses the master key itself. `null` clears ownership, returning the resource to master-only lifecycle authority. This is also the sole recovery path for the `NULL` ownership backfill — every group and webhook predating the column arrives unowned.
  - **Revoking Group Permissions:**
    `DELETE /api/keys/{id}/permissions/{group_identifier}` MUST remove specific group permission mappings from a key.
  - **Audit Log Interface & Endpoint:**
    All mutating actions MUST write audit logs, accessible via `GET /api/audit-logs` for Master keys and rendered in a dedicated UI panel.

*End of directives. Write safe, panic-free (`no .unwrap()`), and elegant Rust code.*