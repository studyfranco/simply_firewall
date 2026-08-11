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

**Rationale.** The ordering is a security control, not a convenience. `MasterPin::pin_at_boot()` runs
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

**Key exports.** `connect`, `apply_sqlite_pragmas`, `run_migrations`, `has_index`,
`SQLITE_BUSY_TIMEOUT_MS`, `SQLITE_MAX_CONNECTIONS`.

**`has_index` replaced `SchemaManager::has_index`, and the reason matters.** That helper picks its
catalog query behind cargo feature gates, and this crate enables only `sqlx-sqlite` on
`sea-orm-migration` — so its PostgreSQL arm was compiled out and the §5 boot check answered
`BackendNotSupported` against a database whose index was present. **The service could not start on
PostgreSQL at all.** Catalog inspection has no entity API, so it is necessarily raw SQL, which is why
it lives here rather than in `master.rs`: this module is the one `tests/source_hygiene.rs` allowlists,
and it is startup-only rather than request-reachable.

**Rationale.** `SQLITE_MAX_CONNECTIONS = 1` is not a tuning knob. SQLite permits one writer, and a DDL
sequence spread across connections does not survive — `m20260808_000009` drops `master_marker` and
re-adds it as a generated column, and at any pool size ≥ 2 the `ADD` reaches a connection whose schema
still holds the old one. SeaORM's `Database::connect` pins this to 1 for SQLite; building a pool by
hand opts out of that default *silently*, which is how it was broken once. The four pragmas are
declared on `SqliteConnectOptions` rather than issued as statements so SQLx replays them when it
reopens a connection.

### `src/state.rs` — shared application state

**Role & scope.** `AppState` and its constructors, `WebhookEvent`, and `StartupConfigError`.

**Must not hold** database setup (that is `db.rs`) or the Master-pin *mechanism* (that is
`master.rs`). `AppState` holds the pin as a field; it does not implement it.

**Key exports.** `AppState`, `WebhookEvent`, `StartupConfigError`, `AppState::with_pinned_master`.

**Rationale.** Everything in `AppState` is built **once at startup** and carried, never re-derived
per request, because each field is an input to an authorization decision and a value that can change
under a running process cannot be reasoned about. Every shared field is behind an `Arc` so that a
`#[derive(Clone)]` cannot silently give a handler its own copy of a security primitive.

### `src/master.rs` — the Master identity pin

**Role & scope.** `MasterPin` (`new`, `pinned_to`, `get`, `pin_at_boot`, `resolve`, `authenticate`),
`MasterPinError`, `MASTER_MARKER_INDEX`. Everything that decides *which* key is Master, and the
demotion that enforces it.

**Must not hold** any other authorization rule. This file answers exactly one question — "is this key
the Master this process pinned?" — and §1–§4/§6/§7 all belong in `api/guards.rs`.

**Key exports.** `MasterPin`, `MasterPinError`, `MASTER_MARKER_INDEX`.

**Rationale.** §5's uniqueness index guarantees *at most one* master row and says nothing about
**which** row. An attacker with database access does not need two masters — demoting the real one and
promoting itself keeps the count at one and satisfies every constraint. The index defends the
cardinality; this file defends the identity, and neither substitutes for the other.

`MasterPin::authenticate` is the single choke point: it mutates the authenticated record so every
downstream `key.is_master` read is automatically correct. `pinned_to` exists for the negative path —
a pin fixed to an id the database does not agree with cannot be reached through `pin_at_boot`, which
by construction only ever pins the row that really is the sole Master.

Mirrors `simply_hook_executor::master`, closing proposal **P1** from `AGENT_NOTES.MD` Session 41.
`scripts/verify_convergence.sh` asserts `pin_at_boot`, the `OnceLock` field, the runtime index check,
and that `key.is_master = false` appears in **exactly one** non-migration file.

### `src/middleware.rs` — authentication, and the Master-pin boundary

**Role & scope.** `auth_middleware`: key lookup, HMAC signature verification, anti-replay, `bound_ips`
enforcement, and the single call to `MasterPin::authenticate`. Also `ClientIp`.

**Must not hold** per-resource authorization — that is `api/guards.rs`. This file answers "who is
calling and may they call at all", never "may they touch *this* group". Nor the demotion *logic*:
it calls `master.rs`, it does not reimplement it.

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
period), `resolve_client_ip` (the `X-Forwarded-For` chain walk), `normalize_ip`, bind-address parsing,
and `validate_initial_master_key`.

**Must not hold** anything requiring a database or application state. Every function here is pure
enough to unit-test without a process, which is why the master-key rule lives here rather than inline
in `main.rs` — the branch that refuses a weak credential is worth being able to test directly.

**Key exports.** `TrustedProxies`, `ProxyMatcher`, `InvalidTrustedProxies`, `resolve_client_ip`,
`normalize_ip`, `is_trusted`, `resolve_bind_addr`, `parse_bind_addr`, `parse_trusted_proxies`,
`validate_initial_master_key`, `InvalidInitialMasterKey`, `INITIAL_MASTER_KEY_ENV`,
`MASTER_KEY_HEX_LEN`.

**Rationale.** The chain walk is meant to be character-for-character identical to the peer's, and
`verify_convergence.sh` diffs it: a difference means one service trusts an address the other would
not. Walked right-to-left skipping trusted hops, which is what makes a client-supplied prefix
unforgeable. An unresolvable hostname disables *that entry only* and never the service.

`MASTER_KEY_HEX_LEN = 64` is not a policy number picked here — it is exactly what
`api::generate_random_key` emits, so the rule demands of an operator precisely what the service
demands of itself, and a unit test asserts that correspondence rather than restating the constant. The
refusal is fatal: `INITIAL_MASTER_KEY` accepted any non-empty string until Session 44, with a startup
warning as its only objection, and the credential it guards is the one that administers every other
credential.

> **Deliberate divergence.** `simply_hook_executor` accepts any non-empty `INITIAL_MASTER_KEY`. This
> service is stricter on purpose.

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
correct status. `OptionalStrictJson<T>`: the same, for endpoints whose body may be absent entirely,
yielding `T::default()`.

**Must not hold** anything domain-specific. `OptionalStrictJson`'s parse failure is worded generically
for exactly this reason — it serves any bodyless-optional payload, so a message naming one caller's
field would be wrong for the second adopter.

**Key exports.** `StrictJson`, `OptionalStrictJson`.

**Rationale.** This is a `RBAC_MODEL.md` §5 control, not ergonomics. §5 requires `is_master` be
removed from the payload *type*, "rejecting it at the handler is not sufficient". Removing a field
alone makes serde *ignore* it, which is worse than accepting or rejecting; `deny_unknown_fields` turns
the absence into a refusal and `StrictJson` renders that refusal as `400` with serde's own message —
which is also what lets a test prove the control lives in the type rather than in a guard. Only the
two *content* error variants are remapped, so a body over the size limit still answers `413`.

`OptionalStrictJson` replaced a hand-rolled `axum::body::Bytes` + `serde_json::from_slice` in
`delete_api_key`. `DELETE /api/keys/{id}` is a conversation — the first request carries no body and
gets §6's inventory back, the resubmission carries the resolution map — and neither `Json` (which
rejects an empty body) nor `Option<Json<T>>` (which keys on `Content-Type`, not emptiness) expresses
that. Emptiness is decided from the **bytes**, and reading through `Bytes` keeps the request under the
router's `DefaultBodyLimit`, so the `413` control still applies.

### `src/dispatch.rs` — outbound dispatch worker

**Role & scope.** The background task that consumes `WebhookEvent`s and dispatches signed HTTP calls:
auth-mode handling, HMAC templating, SSRF checks, retry behaviour.

**Must not hold** the webhook *configuration* endpoints — those are `api/webhooks.rs`. This file is
the sender; that one is the CRUD surface.

**Key exports.** the dispatch worker entry point and `AuthMode` handling.

**Rationale.** Dispatch is a background concern with its own failure semantics; a failed delivery must
never fail the request that triggered it. Named `dispatch` and not `webhooks` because it sat one
directory from `src/api/webhooks.rs` and the two do opposite jobs — that one is the CRUD surface for
webhook *configuration*, this one is the runtime that *sends*. Two files distinguished only by a path
prefix get imported wrongly and, worse, reviewed wrongly: a diff header reading `webhooks.rs` does not
say which of the two security models applies. Closes proposal **P4** from Session 41.

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

### `src/api/mod.rs` — module wiring only

**Role & scope.** Module declarations and the flat re-exports. Nothing else.

**Must not hold** a single line of executable code. It held ~180 lines of helpers until Session 42;
they are now `support.rs`. A helper added here is the beginning of the drawer re-filling.

**Key exports.** the flat re-export surface — `pub(crate) use guards::*`, `pub(crate) use support::*`,
and a `pub use` per domain module.

**Rationale.** The re-export shape is deliberate. `guards` and most of `support` are `pub(crate)`, so a
`pub` glob over them would re-export nothing and clippy says so; the four genuinely public items
(`generate_random_key`, `hash_key`, `normalize_ip_or_cidr`, `ReassignOwnerPayload`) are therefore named
explicitly, since the integration suites mint keys directly against the database and need the
credential primitives.

### `src/api/support.rs` — shared plumbing, decides nothing

**Role & scope.** Helpers that **three or more** handler domains need: `generate_random_key`,
`hash_key`, `normalize_ip_or_cidr`, `create_audit_log`, `format_key_reference`, the group-resolution
family (`get_or_create_group`, `resolve_group_ref`, `resolve_group_by_identifier`,
`resolve_group_ref_flexible`), `IP_EVENT_ACTIONS`, `ReassignOwnerPayload`.

**Must not hold** anything that makes an authorization decision. That is the boundary against
`guards.rs`, and it is testable rather than stylistic: nothing here inspects *who* is calling or
returns a refusal that depends on the caller. A helper that starts deciding belongs in `guards.rs`.
Nor anything a single domain uses — that belongs in the domain's own file.

**`create_audit_log` takes its actor by value, not as `Option`.** Since `m20260811_000010` the three
attribution columns are `NOT NULL`, and the signature is what makes that unbreakable from application
code: there is no `None` to thread through, so an unattributed write cannot be written rather than
being silently defaulted to `"anonymous"`. See `SCHEMA.MD` for why a fallback would have been worse.

**Key exports.** as above.

**Rationale.** A helper is here because pushing it into a domain module would make every other domain
depend on that one, and because leaving it in `mod.rs` made that file wiring plus a utility drawer at
once. `format_key_reference` came from `guards.rs` in Session 42: it renders a string for a log line,
decides nothing, and five of its seven call sites were already outside that module. Closes proposal
**P2**. Mirrors `simply_hook_executor::api::support`.

### `src/api/health.rs` — unauthenticated liveness and readiness probes

**Role & scope.** `health_check` (`GET /health`, `/healthz`) and `readiness_check` (`GET /ready`,
`/readyz`). The only endpoints in the service that answer without a credential.

**Must not hold** anything that returns data, names a resource, discloses a build identifier, or
reports an error in detail. Both handlers are reachable by anyone who can open a socket, so they are
held to a rule the authenticated routes are not: **disclose nothing an anonymous caller could not
already infer.**

**Key exports.** `health_check`, `readiness_check`.

**Rationale.** Mounted in `lib.rs` on the **root** router, outside the `/api` nest and therefore
outside `auth_middleware` — the callers are Docker's `HEALTHCHECK`, a Kubernetes probe and a load
balancer, none of which can compute an HMAC over a body with a rolling timestamp. Requiring a
credential would make the probe fail exactly when the credential store is what broke. The convergence
script asserts that placement, because moving them inside the nest would make them uncallable in a way
that looks like a broken healthcheck rather than a misplaced route.

Liveness and readiness are kept apart deliberately. `/health` takes no `State` at all — the compiler,
not a comment, is what stops it depending on the database — while `/ready` proves the database answers
and the Master identity is pinned. An orchestrator *restarts* a container whose liveness probe fails,
so a liveness check that consulted the database would turn a dependency outage into an unbounded
restart loop.

Named `health.rs` to match the peer. It was `system.rs` until the Session 44 parity audit, which is
the peer's name for a *different* module — its effective-configuration endpoint — so the old name was
actively misleading rather than merely different.

> **Deliberate divergences.** The peer probes with a literal `SELECT 1`; this service uses a typed
> SeaORM query, because `verify_convergence.sh` bans raw SQL for DML anywhere in `src/` and an
> allowlisted exception would be a hole in a gate worth more than one saved query. The peer also does
> not check the Master pin. Both make this side stricter.

### `src/api/guards.rs` — every authorization decision

**Role & scope.** The single place a permission decision is *made*. Each function answers one question
from `RBAC_MODEL.md` and returns `Ok(())` or a refusal.

**Must not hold** handler logic, response types, or database writes. Nor the §4 **subtree mechanics**
(`collect_key_subtree`, `find_administrable_key`, and friends), which are in `keys.rs` — see below.

**Key exports.** `guard_group_manage` (R2), `guard_delegated_group_grant` (R1/R7),
`guard_scope_elevation` (R4), `guard_resource_lifecycle` (§3), `guard_master_target`,
`guard_master_immutable` (§5), `caller_group_permission`, `resource_owner`,
`resolve_owner_assignment`, `widens_permissions`, `MASTER_ONLY_SCOPES`.

**Rationale.** This file is the point of the whole `api/` split. ~457 lines holding no handler logic
and no response types means it can be read straight against `RBAC_MODEL.md` without opening an
endpoint — which is the only way to check the specification is actually enforced rather than merely
cited.

**Membership here is decided by "does it make an authorization decision?", never by how many domains
call it.** Most of these are called only from `keys.rs` today, and that is not a reason to move them.
They enforce named rules of the specification, and scattering R1/R4/R7 into the handler files is
precisely what the `api/` split undid. `holds_any_group_manage` is private to this module and used
only within it — also fine, for the same reason.

### `src/api/keys.rs` — API key endpoints

**Role & scope.** Identity (`get_me`), creation, listing with §4 visibility scoping, update, deletion
with §6 cascade and pre-flight inventory, both rotation endpoints, and per-group permission grants.

**Key exports.** `get_me`, `create_api_key`, `list_api_keys`, `update_api_key`, `delete_api_key`,
`rotate_api_key`, `rotate_signing_secret`, `update_key_group_permissions`,
`revoke_key_group_permission`, plus their payload/response DTOs. Also the §4 visibility mechanics:
`collect_key_subtree`, `groups_the_caller_manages`, `caller_can_administer_key`,
`find_administrable_key`.

**Rationale.** The largest module (~1,365 lines) and deliberately **not** split further. R1–R7 are
about how keys delegate to other keys, so subtree walking, visibility scoping, lifecycle and
permission grants are one subject; splitting them would put a rule's mechanism in one file and its
guard in another, which is the arrangement the `api/` split exists to undo.

**On the four subtree helpers.** They have lived here since the original split (`036794a`) and belong
here: they *resolve* the caller's §4 subtree — a recursive walk of `parent_key_id`, and a database
traversal rather than a rule — and every one of their call sites is a key handler. `guards.rs` holds
the predicates that answer yes/no from an already-resolved pair. A Session 43 proposal to move them
*out of* `guards.rs` was checked and found to be describing a state that already held; recorded here
so the same move is not proposed a third time.

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

**Must not hold** dispatch logic; that is top-level `src/dispatch.rs`.

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

One file per table, plus `mod.rs` (declarations) and `prelude.rs` (the `Entity` re-export set). Every
file is generated-shaped: `Model`, `ActiveModel`, `Column`, `Relation`, `ActiveModelBehavior`.

**Must not hold** business logic, defaults that encode policy, or authorization helpers. A field's
presence or absence here is a schema statement, not a convenience.

| File | Table | Fields | Holds |
| :--- | :--- | ---: | :--- |
| `api_key.rs` | `api_keys` | 13 | Credentials and authority: `key_hash`, `prefix`, `signing_secret` (sealed), `bound_ips`, `is_master`, the three global scopes, `parent_key_id` |
| `api_key_group_permission.rs` | `api_key_group_permissions` | 8 | The M:N grant row — `can_read`, `can_write`, `can_delete`, `can_manage`. What every §2 check reads |
| `ip_group.rs` | `ip_groups` | 6 | Named collections (`fail2ban`, `sshd`), `group_type`, `owner_key_id` (§3) |
| `ip_record.rs` | `ip_records` | 10 | The addresses themselves, plus the soft-delete triple `is_deleted` / `deleted_at` / `deleted_by` |
| `ip_record_group_membership.rs` | `ip_record_group_memberships` | 2 | Composite-PK join of record ↔ group. Both columns cascade |
| `webhook_config.rs` | `webhook_configs` | 14 | Dispatch targets: `target_url`, `secret_token`, `auth_mode`, `hmac_template`, `events`, `owner_key_id` |
| `audit_log.rs` | `audit_logs` | 10 | The trail. `api_key_id` is `ON DELETE SET NULL`; `api_key_name`, `api_key_prefix` and `client_ip` are **`NOT NULL`** and denormalised, so it stays legible after the key is gone |
| `mod.rs` | — | — | Module declarations only |
| `prelude.rs` | — | — | `pub use …::Entity as X` for each table |

**The one rule that is not obvious.** `api_key::Model` deliberately **omits** `master_marker`. The
column exists and is `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` under a unique
index; SeaORM builds explicit column lists from the entity, so leaving the field out is what
guarantees no query ever names it — and every engine rejects a write to a generated column. Declaring
it, even read-only, would put it into every `INSERT` and break all key creation.
**Do not add it back** — `scripts/verify_convergence.sh` fails if you do.

---

## `src/migration/` — schema migrations

Ordered in `mod.rs`; each file is one applied migration and is **immutable history** — `sea-orm`
records migrations by name and will not re-run an edited one. Only documentation may be corrected in
place. This is the one directory where raw SQL is permitted, because DDL for generated columns and
per-engine storage classes cannot be expressed portably through SeaQuery.

| # | File | Adds |
| ---: | :--- | :--- |
| 1 | `m20230101_000001_initial_schema` | All seven tables and their foreign keys. CASCADE on the two join tables and on `webhook_configs.group_id`; **SET NULL** on `audit_logs.api_key_id` |
| 2 | `m20260729_000002_add_api_key_signing_secret` | `api_keys.signing_secret` — the per-key HMAC secret behind `X-Signature-256` |
| 3 | `m20260730_000003_add_webhook_signature_mode` | `webhook_configs.signature_mode` |
| 4 | `m20260730_000004_add_webhook_auth_modes` | Generalises the above into the four-valued `auth_mode`, plus `api_key` and `hmac_template` |
| 5 | `m20260801_000005_add_ip_record_soft_delete` | `is_deleted`, `deleted_at`, `deleted_by` on `ip_records` |
| 6 | `m20260804_000006_add_group_permission_can_manage` | `api_key_group_permissions.can_manage` — R2's per-resource half |
| 7 | `m20260807_000007_add_api_key_master_marker` | **Superseded, and documents its own defect.** An application-maintained marker that did *not* satisfy §5 |
| 8 | `m20260807_000008_add_lineage_and_ownership` | `api_keys.parent_key_id` (§4 subtree) and `owner_key_id` on groups and webhooks (§3) |
| 9 | `m20260808_000009_derive_master_marker` | **The actual §5 enforcement.** Engine-derived marker under a unique index |
| 10 | `m20260811_000010_audit_attribution_not_null` | `NOT NULL` on `audit_logs.api_key_name`, `.api_key_prefix`, `.client_ip`, with a `(unknown)` backfill for historical rows |
| 11 | `m20260811_000011_index_ip_record_delta_columns` | Index on `ip_records.updated_at` — the column a polling delta-sync consumer filters on |
| 12 | `m20260811_000012_webhook_hmac_only_mode` | Renames the `BODY_ONLY` auth mode to `HMAC_ONLY` and adds `signature_header` / `signature_prefix` |

Three carry reasoning worth reading before touching them:

- **#7 is kept unmodified on purpose.** It added a marker the application wrote, which a writer could
  simply omit — and NULLs do not collide in a unique index, so the constraint never fired. Retained
  with its (wrong) claim intact, because deleting the record of a defect deletes the reason the fix
  looks the way it does.
- **#9** pins the per-backend storage class by unit test (Postgres `STORED`, SQLite/MySQL `VIRTUAL`)
  and **aborts before any DDL** if the database already holds two Masters, naming both rows.
- **#8** adds no DDL foreign keys. SQLite has no `ALTER TABLE … ADD CONSTRAINT`, so the constraint
  would exist on two backends and silently not on the one CI runs. The application-level equivalents
  are covered by `tests/schema_integrity_tests.rs` instead.
- **#10 is a table rebuild on SQLite**, which has no `ALTER TABLE … ALTER COLUMN`: create, copy, drop,
  rename. That is the most dangerous shape of migration there is, because anything it forgets to
  recreate simply stops existing and nothing fails. It builds the replacement with SeaORM's schema
  builder rather than hand-written DDL so column types match the original exactly, copies **by column
  name** so a future reorder cannot transpose values, and recreates both indexes. Four tests in
  `tests/schema_integrity_tests.rs` pin the result — the `SET NULL` cascade, both indexes, the
  backfill of pre-constraint rows, and the absence of transposition.

---

## `tests/` — what each suite is responsible for

`src/` is the subject of this map, but the suites are where its guarantees are pinned, and knowing
which file owns which property saves adding a test to the wrong one.

| File | Owns |
| :--- | :--- |
| `rbac_model_compliance.rs` | One test per `RBAC_MODEL.md` rule and section (`r1_`–`r7_`, `s3_`–`s7_`). Five are marked `ADVERSARIAL(§N)` and bypass the application layer with raw SQL. `scripts/verify_convergence.sh` fails if a rule loses its test |
| `security_tests.rs` | Named attacks, each asserting the attack fails. HMAC forgery, replay, proxy spoofing, master promotion, the unauthenticated probes |
| `schema_integrity_tests.rs` | What the **engine** does — foreign-key cascades, orphan refusal, and everything `m20260811_000010`'s table rebuild had to carry across. File-backed, opened through `db::connect`, because `PRAGMA foreign_keys` is per-connection |
| `rbac_integration_tests.rs` | The features working, end to end through the router |
| `source_hygiene.rs` | Properties of the source tree: no raw SQL and no hand-written DML in `src/`, outside two startup-only exemptions. Carries a meta-test proving the scanner can see a violation |
| `frontend_syntax_test.rs` | `static/app.js` parses. Nothing else compiles or executes it |

**`source_hygiene.rs` deliberately duplicates `verify_convergence.sh::check_no_raw_sql`**, and the two
are not interchangeable. The shell gate has to be *run*; the Rust test runs on every `cargo test`, in
CI and in an IDE. More to the point, two successive versions of the shell gate were silently broken —
one used a gawk extension that is an always-false variable under `mawk`, the other exempted anything
near the word "pragma" — and each reported CLEAN against a deliberately planted violation. Both
failures were invisible because neither had a meta-test. This file has one.
