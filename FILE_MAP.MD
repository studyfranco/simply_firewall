# FILE_MAP.MD — what lives where in `src/`, and why

An index of every `.rs` file in `src/`, written for someone (or something) arriving cold and needing
to know where a change belongs before making it.

Each entry records three things:

- **Role & scope** — what the file holds, and explicitly what it must *not* hold. The second half is
  the load-bearing one: most drift in this codebase has been a function landing in a plausible-looking
  file rather than the right one.
- **Key exports** — the primary functions, types, and constants.
- **Rationale** — why the code lives here, usually recording a decision that is not obvious from the
  code alone.

> Companion documents: `AGENT.MD` (architectural and security ruleset), `SCHEMA.MD` (database
> schema), `RBAC_MODEL.md` (normative authorization specification, byte-identical with
> `simply_hook_executor`, **read-only**), `AGENT_NOTES.MD` (session worklog and audit history).

---

## Top level

### `src/main.rs` — process entry point *only*

**Role & scope.** The startup sequence, in order, and nothing else: load env → build cipher and
proxy list → connect → pragmas → migrate → bootstrap master → **pin master** → build state → bind →
serve → graceful shutdown. Also holds `bootstrap_master_key`, which is the only writer of
`is_master = true` in the entire service.

**Must not hold** request handling, authorization logic, or anything a test needs to call. Everything
testable lives in the library so integration tests can reach it; `main.rs` is the part that only runs
in production.

**Key exports.** `main`, `shutdown_signal`, `bootstrap_master_key` (all private — this is a binary).

**Rationale.** The ordering is a security control, not a convenience. `pin_master_key()` runs
**after** migrations and bootstrap but **before** `TcpListener::bind`, so the Master's identity is
fixed before a single request can be served. Moving it later reintroduces exactly the tampering
window it exists to close.

### `src/lib.rs` — router assembly and the crate's public surface

**Role & scope.** `create_app` (the full route table, middleware layering, static fallback),
`setup_state`, and the crate-wide `MAX_REQUEST_BODY_BYTES`. Declares every module.

**Must not hold** handler bodies or business logic. A route line here should read as a mapping from
path to handler and nothing more.

**Key exports.** `create_app`, `setup_state`, `MAX_REQUEST_BODY_BYTES`.

**Rationale.** Middleware order is asserted here and matters: the body limit is applied *outside* the
`/api` nest so it covers the static fallback too, and authentication is layered so it runs before any
handler. `scripts/verify_convergence.sh` checks the body-limit constant and its application against
the peer.

### `src/db.rs` — connection setup, session pragmas, migrations

**Role & scope.** `connect` (pool construction), `apply_sqlite_pragmas`, `run_migrations`. The only
place in `src/` outside `migration/` permitted to issue raw SQL, and then only `PRAGMA`.

**Must not hold** any DML. `scripts/verify_convergence.sh::check_no_raw_sql` flags a
`SELECT`/`INSERT`/`UPDATE`/`DELETE` keyword appearing anywhere in this file's raw-statement windows.

**Key exports.** `connect`, `apply_sqlite_pragmas`, `run_migrations`, `SQLITE_BUSY_TIMEOUT_MS`,
`SQLITE_MAX_CONNECTIONS`.

**Rationale.** `SQLITE_MAX_CONNECTIONS = 1` is not a tuning knob. SQLite permits one writer, and a DDL
sequence spread across connections does not survive — `m20260808_000009` drops `master_marker` and
re-adds it as a generated column, and at any pool size ≥ 2 the `ADD` reaches a connection whose schema
still holds the old one. SeaORM's `Database::connect` pins this to 1 for SQLite; building a pool by
hand opts out of that default *silently*, which is how it was broken once. The four pragmas are
declared on `SqliteConnectOptions` rather than issued as statements so SQLx replays them when it
reopens a connection.

### `src/state.rs` — shared application state and the Master pin

**Role & scope.** `AppState` and its constructors, `WebhookEvent`, `StartupConfigError`, and the
Master-identity pin (`master_key_id`, `pin_master_key`, `resolve_master_key_id`,
`is_effective_master`, `MasterPinError`, `MASTER_MARKER_INDEX`).

**Must not hold** database setup — that moved to `db.rs`.

**Key exports.** `AppState`, `WebhookEvent`, `StartupConfigError`, `MasterPinError`,
`MASTER_MARKER_INDEX`.

**Rationale.** Everything in `AppState` is built **once at startup** and carried, never re-derived
per request, because each field is an input to an authorization decision and a value that can change
under a running process cannot be reasoned about. `master_key_id` is `Arc<OnceLock<Uuid>>` rather than
a plain `Uuid` specifically so a second assignment is impossible rather than merely discouraged.

> **Known divergence.** `simply_hook_executor` factors this into a dedicated `src/master.rs` with a
> `MasterPin` type. See `AGENT_NOTES.MD` Session 41, proposal **P1**.

### `src/middleware.rs` — authentication, and the Master-pin boundary

**Role & scope.** `auth_middleware`: key lookup, HMAC signature verification, anti-replay, `bound_ips`
enforcement, and the demotion of any key claiming `is_master` that is not the pinned Master. Also
`ClientIp`.

**Must not hold** per-resource authorization — that is `api/guards.rs`. This file answers "who is
calling and may they call at all", never "may they touch *this* group".

**Key exports.** `auth_middleware`, `ClientIp`.

**Rationale.** Two orderings here are security controls and are asserted by the convergence script.
Signature verification runs **before** the `bound_ips` check, so a 401/403 pair cannot be used as an
oracle for whether a key exists. And the Master demotion happens at the single point a key model
enters the request extensions — there are ~40 downstream reads of `key.is_master`, and a per-guard
check would mean the first guard written without one is a silent hole.

### `src/crypto.rs` — at-rest encryption and request signing

**Role & scope.** `SecretCipher` (XChaCha20-Poly1305 sealing of `signing_secret`), CANONICAL_V1
payload construction, HMAC computation and constant-time verification, `generate_signing_secret`.

**Must not hold** key *hashing* for lookup (`hash_key` is an API-layer concern in `api/mod.rs`) or any
policy about who may use a secret.

**Key exports.** `SecretCipher`, `CryptoError`, `generate_signing_secret`, `canonical_v1_payload`,
`compute_signature`, `verify_signature`.

**Rationale.** `SecretCipher::open` is strictly fail-closed: a stored value without a recognized
prefix is an error, never returned verbatim. `verify_signature` uses constant-time comparison, and the
convergence script forbids any `==` on a signature, MAC, or digest anywhere in `src/`.

### `src/config.rs` — environment parsing and client-address resolution

**Role & scope.** `TrustedProxies` (CIDR/hostname parsing, DNS resolution with TTLs and a boot grace
period), `resolve_client_ip` (the `X-Forwarded-For` chain walk), `normalize_ip`, bind-address parsing.

**Must not hold** anything requiring a database or application state.

**Key exports.** `TrustedProxies`, `ProxyMatcher`, `InvalidTrustedProxies`, `resolve_client_ip`,
`normalize_ip`, `is_trusted`, `resolve_bind_addr`, `parse_bind_addr`, `parse_trusted_proxies`.

**Rationale.** The chain walk is meant to be character-for-character identical to the peer's, and
`verify_convergence.sh` diffs it: a difference means one service trusts an address the other would
not. Walked right-to-left skipping trusted hops, which is what makes a client-supplied prefix
unforgeable. An unresolvable hostname disables *that entry only* and never the service.

### `src/replay.rs` — anti-replay guard

**Role & scope.** `ReplayGuard`: records accepted signatures within the freshness window and refuses
repeats.

**Must not hold** freshness/skew policy — that is `middleware.rs`.

**Key exports.** `ReplayGuard`.

**Rationale.** Expiry runs on the **monotonic** clock (`tokio::time::Instant`), never wall-clock: an
NTP step must not evict live entries. Entries key on the raw digest rather than header text. A
saturated guard is never flushed wholesale — the convergence script asserts `seen.clear()` appears
nowhere, because clearing would let every recorded signature replay at once.

### `src/extract.rs` — strict request extractors

**Role & scope.** `StrictJson<T>`: `Json` whose deserialization failures become `AppError` with the
correct status.

**Must not hold** anything domain-specific.

**Key exports.** `StrictJson`.

**Rationale.** This is a `RBAC_MODEL.md` §5 control, not ergonomics. §5 requires `is_master` be
removed from the payload *type*, "rejecting it at the handler is not sufficient". Removing a field
alone makes serde *ignore* it, which is worse than accepting or rejecting; `deny_unknown_fields` turns
the absence into a refusal and `StrictJson` renders that refusal as `400` with serde's own message —
which is also what lets a test prove the control lives in the type rather than in a guard. Only the
two *content* error variants are remapped, so a body over the size limit still answers `413`.

### `src/webhooks.rs` — outbound dispatch worker

**Role & scope.** The background task that consumes `WebhookEvent`s and dispatches signed HTTP calls:
auth-mode handling, HMAC templating, SSRF checks, retry behaviour.

**Must not hold** the webhook *configuration* endpoints — those are `api/webhooks.rs`. This file is
the sender; that one is the CRUD surface.

**Key exports.** the dispatch worker entry point and `AuthMode` handling.

**Rationale.** Dispatch is a background concern with its own failure semantics; a failed delivery must
never fail the request that triggered it. The naming collision with `api/webhooks.rs` is the one
genuinely confusing thing in the tree — see `AGENT_NOTES.MD` Session 41, proposal **P4**.

### `src/retention.rs` — soft-delete purge worker

**Role & scope.** `run_retention_worker` and the purge query for expired soft-deleted IP records;
`retention_days_from_env`.

**Key exports.** `run_retention_worker`, `purge_expired_ip_records`, `retention_days_from_env`,
`RETENTION_DAYS_ENV`, `DEFAULT_RETENTION_DAYS`.

**Rationale.** The purge guards on **both** `is_deleted` and `deleted_at is not null`, asserted by the
convergence script: a row soft-deleted without a timestamp must never be swept by a date comparison
that treats `NULL` as ancient.

### `src/error.rs` — the error type and its HTTP rendering

**Role & scope.** `AppError` and its `IntoResponse`. Every failure a handler can return.

**Must not hold** domain logic. A variant is a status code plus a message shape.

**Key exports.** `AppError` with variants `DbError`, `InvalidInput`, `Unauthorized`, `Forbidden`,
`NotFound`, `Conflict`, `ConflictWithDetails`, `BodyRejected`, `Internal`.

**Rationale.** Two variants exist for specific specification requirements. `ConflictWithDetails`
carries §6's pre-flight inventory as structured data merged into the response at the top level, so a
client reading only `error` behaves exactly as it does for `Conflict`. `BodyRejected` carries an
extractor's own status so that normalizing the response *shape* does not also normalize its *meaning*
— flattening everything to `400` would demote `413`.

---

## `src/api/` — HTTP handlers, split by domain

Re-exported **flat** by `mod.rs`: `api::create_api_key` resolves exactly as it did when this was one
3,674-line file. The router, all four test suites, and `scripts/` reference those flat paths.
**The paths are the API; the files are an implementation detail** — do not "tidy" the re-exports into
module-qualified paths.

### `src/api/mod.rs` — module wiring and cross-domain helpers

**Role & scope.** Module declarations, the flat re-exports, and exactly those helpers that **more than
one** domain needs: `generate_random_key`, `hash_key`, `normalize_ip_or_cidr`, `create_audit_log`, the
group-resolution family, `IP_EVENT_ACTIONS`, `ReassignOwnerPayload`.

**Must not hold** anything used by a single domain — that belongs in the domain's own file.

**Rationale.** A helper is here because pushing it into a domain module would make every other domain
depend on that one. `ReassignOwnerPayload` is shared because §3 ownership is cross-domain by nature.

> **Known divergence.** `simply_hook_executor` keeps the equivalent helpers in a dedicated
> `src/api/support.rs`, leaving its `api/mod.rs` as pure wiring. See Session 41, proposal **P2**.

### `src/api/guards.rs` — every authorization decision

**Role & scope.** The single place a permission decision is *made*. Each function answers one question
from `RBAC_MODEL.md` and returns `Ok(())` or a refusal.

**Must not hold** handler logic, response types, or database writes.

**Key exports.** `guard_group_manage` (R2), `guard_delegated_group_grant` (R1/R7),
`guard_scope_elevation` (R4), `guard_resource_lifecycle` (§3), `guard_master_target`,
`guard_master_immutable` (§5), `caller_group_permission`, `resource_owner`,
`resolve_owner_assignment`, `widens_permissions`, `MASTER_ONLY_SCOPES`.

**Rationale.** This file is the point of the whole `api/` split. 463 lines holding no handler logic
and no response types means it can be read straight against `RBAC_MODEL.md` without opening an
endpoint — which is the only way to check the specification is actually enforced rather than merely
cited.

### `src/api/keys.rs` — API key endpoints

**Role & scope.** Identity (`get_me`), creation, listing with §4 visibility scoping, update, deletion
with §6 cascade and pre-flight inventory, both rotation endpoints, and per-group permission grants.

**Key exports.** `get_me`, `create_api_key`, `list_api_keys`, `update_api_key`, `delete_api_key`,
`rotate_api_key`, `rotate_signing_secret`, `update_key_group_permissions`,
`revoke_key_group_permission`, plus their payload/response DTOs.

**Rationale.** The largest module (1,372 lines) and deliberately **not** split further. R1–R7 are about
how keys delegate to other keys, so subtree walking, visibility scoping, lifecycle and permission
grants are one subject; splitting them would put a rule's mechanism in one file and its guard in
another, which is the arrangement the `api/` split exists to undo.

### `src/api/records.rs` — IP record endpoints

**Role & scope.** Ban/whitelist upsert, listing with filters and pagination, soft delete, restore, and
purge. The specification's *resource data*.

**Key exports.** `handle_ban`, `handle_white`, `list_ips`, `delete_ip`, `delete_ip_record`,
`restore_ip_record`, `purge_ip_records`, `QueryFilters`, `IpRecordResponse`.

**Rationale.** Records inherit authorization from their group's permission row rather than carrying
one of their own, so every handler here resolves a group first and then defers to `guards.rs`.

### `src/api/groups.rs` — IP Group endpoints

**Role & scope.** Creation, listing, deletion, and owner reassignment for the specification's *managed
resource* — shared, carrying per-key permission rows, governed by the R2 conjunction.

**Key exports.** `create_ip_group`, `list_ip_groups`, `delete_ip_group`, `reassign_group_owner`,
`CreateIpGroupPayload`.

### `src/api/webhooks.rs` — webhook config endpoints

**Role & scope.** CRUD and owner reassignment for the specification's *creator-private entity* —
visible only to its `owner_key_id` and Master, never exposed by the shared-resource visibility rule.

**Must not hold** dispatch logic; that is top-level `src/webhooks.rs`.

**Key exports.** `create_webhook`, `list_webhooks`, `update_webhook`, `delete_webhook`,
`reassign_webhook_owner`, `WebhookSummary`.

### `src/api/audit.rs` — audit log endpoint

**Role & scope.** `list_audit_logs`, Master-only.

**Key exports.** `list_audit_logs`, `AuditLogQuery`.

**Rationale.** Its own module rather than a tail on another because it is the one read surface
spanning every domain — filing it under any single one would be arbitrary. It needs nothing from
`super`, which is a useful signal that the boundary is real.

---

## `src/entities/` — SeaORM models

One file per table (`api_key`, `api_key_group_permission`, `ip_group`, `ip_record`,
`ip_record_group_membership`, `webhook_config`, `audit_log`), plus `mod.rs` and `prelude.rs`.

**Must not hold** business logic, defaults that encode policy, or authorization helpers.

**Rationale worth knowing.** `api_key::Model` deliberately **omits** `master_marker`. The column
exists and is `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` under a unique index;
SeaORM builds explicit column lists from the entity, so leaving the field out is what guarantees no
query ever names it — and every engine rejects a write to a generated column. Declaring it, even
read-only, would put it into every `INSERT` and break all key creation. **Do not add it back.**

---

## `src/migration/` — schema migrations

Ordered in `mod.rs`; each file is one applied migration and is **immutable history** — `sea-orm`
records migrations by name and will not re-run an edited one. Only documentation may be corrected in
place.

This is the one directory where raw SQL is permitted, because DDL for generated columns and per-engine
storage classes cannot be expressed portably through SeaQuery.

Migrations of particular note:

- `m20260807_000007_add_api_key_master_marker` — **superseded, and documents its own defect.** It
  added an application-maintained marker, which did not satisfy §5: a writer could set `is_master` and
  omit the marker, and NULLs do not collide in a unique index. Retained unmodified with the reasoning
  intact.
- `m20260808_000009_derive_master_marker` — the actual §5 enforcement. Engine-derived marker, per-
  backend storage class pinned by unit test (Postgres `STORED`, SQLite/MySQL `VIRTUAL`), and an abort
  with both offending rows named if the database already holds two Masters.
- `m20260807_000008_add_lineage_and_ownership` — `parent_key_id` and both `owner_key_id` columns. No
  DDL foreign keys: SQLite has no `ALTER TABLE … ADD CONSTRAINT`, so the application-level equivalents
  are covered by a CI test instead (§7).
