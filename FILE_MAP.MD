# `simply_ip_vault` — Exhaustive `src/` File Map

An index of every file under `src/`, its size, and its exact purpose. Written for future agents: read
this before searching the tree, and update it when you add, remove, or repurpose a file.

**Revision:** `14c8fa3` · **Generated:** 2026-08-18 · **Files indexed:** 44 · **Total:** 13,012 lines

---

## Top-level modules

| File | Lines | Purpose |
| :--- | ---: | :--- |
| `lib.rs` | 166 | Crate root. Assembles the axum router, declares module visibility, and exposes `create_app` / `setup_state` — the two entry points integration tests build against. |
| `main.rs` | 316 | Process entry point and nothing else. The boot sequence in strict order: connect → pragmas → migrate → bootstrap Master → pin Master → build state → start workers → bind → serve → graceful shutdown. The only writer of `is_master = true` in the service. |
| `config.rs` | 1,508 | All environment reads, each `OnceLock`-cached and fail-soft with a warning, plus the client-IP resolution policy (trusted proxies, `X-Forwarded-For` handling). Also holds fatal validators for bootstrap credentials. |
| `crypto.rs` | 839 | Two responsibilities: `CANONICAL_V1` request signing (HMAC-SHA256, constant-time verification, 300 s skew window) and signing-secret encryption at rest (XChaCha20-Poly1305 via `SecretCipher`). |
| `db.rs` | 537 | Connection pool construction, SQLite session pragmas (WAL, `synchronous=NORMAL`, `foreign_keys=ON`), migration runner, and a dialect-aware `has_index` used by migrations. SQLite is capped at one connection — DDL breaks above it. |
| `error.rs` | 107 | `AppError` and its `IntoResponse` mapping. The single definition of the `{"error": "…"}` envelope and of which internal failures are redacted before reaching a client. |
| `extract.rs` | 128 | Strict request extractors (`StrictJson`, `StrictPath`, `StrictQuery`). Makes rejection a property of the *type* rather than of a handler, so no endpoint can accidentally emit axum's default plain-text rejection. |
| `master.rs` | 322 | Boot-time pinning of the Master key **identity** (`MasterPin`), and the per-request demotion that enforces it. Distinct from the database's uniqueness constraint, which governs *cardinality* — an attacker with DB write access does not need two Masters, only to promote itself. |
| `middleware.rs` | 328 | Authentication middleware: key lookup by hash, signature verification, timestamp validation, replay rejection, and `bound_ips` CIDR enforcement — in that order, so an unauthenticated caller cannot probe key bindings via 401-vs-403. |
| `replay.rs` | 440 | `ReplayGuard`: the single-use ledger for `CANONICAL_V1` signatures. Fails closed on a poisoned lock, and prunes only genuinely expired entries — never wholesale, which would let every live signature replay at once. |
| `state.rs` | 208 | `AppState`: the database handle, the webhook dispatch channel, and the three security singletons (`MasterPin`, `ReplayGuard`, `SecretCipher`). Carries `for_tests` so integration tests can build state without environment reads. |
| `dispatch.rs` | 616 | The outbound webhook dispatcher — the background worker pool that actually sends notifications, with rate limiting, retry, and the four authentication modes. |
| `retention.rs` | 134 | Background retention worker: permanently drops soft-deleted IP records once they age past the configured window. |

## `src/api/` — HTTP handlers

| File | Lines | Purpose |
| :--- | ---: | :--- |
| `mod.rs` | 69 | Module declarations and the re-export surface the router binds against. |
| `guards.rs` | 457 | **The single place a permission decision is made.** Holds `guard_resource_lifecycle`, `guard_group_manage`, `guard_may_administer_any_group`, `guard_delegated_group_grant`, `guard_scope_elevation`, `guard_master_target`, `guard_master_immutable`. Read this before touching any authorization logic. |
| `support.rs` | 311 | Shared handler plumbing: `hash_key`, `key_prefix`, `generate_random_key`, `normalize_ip_or_cidr` (masks CIDR host bits at ingestion), and `create_audit_log` — which takes its actor **by value, not `Option`**, so an unattributed write is unrepresentable. |
| `keys.rs` | 1,365 | API key endpoints: identity (`/auth/me`), creation, listing, lifecycle, rotation, and per-group grants. Implements the §6 cascade with pre-flight inventory and resolution map. The largest handler module. |
| `records.rs` | 1,446 | IP record endpoints: ban/whitelist upsert, listing with delta (`since`) support, batch upsert/full-replace, soft delete, restore, and hard purge. |
| `groups.rs` | 197 | IP Group endpoints: creation, listing, deletion, owner reassignment. |
| `webhooks.rs` | 611 | Webhook config endpoints: creation, listing, update, deletion, owner reassignment, and the four auth modes. |
| `audit.rs` | 54 | Audit log query endpoint. Master-only. |
| `health.rs` | 121 | Unauthenticated liveness (`/health`, `/healthz`) and readiness (`/ready`, `/readyz`) probes. Liveness deliberately does not touch the database, so an outage cannot become a restart loop. |

## `src/entities/` — SeaORM models

| File | Lines | Purpose |
| :--- | ---: | :--- |
| `mod.rs` | 19 | Entity module declarations, mirroring the tables in `SCHEMA.MD`. |
| `prelude.rs` | 16 | Convenience re-exports of every entity type. |
| `api_key.rs` | 118 | `api_keys`: authentication tokens, global rights, CIDR bindings, lineage (`parent_key_id`), and the engine-derived `master_marker`. |
| `ip_record.rs` | 76 | `ip_records`: banned/whitelisted addresses and subnets, with soft-delete columns. |
| `ip_group.rs` | 87 | `ip_groups`: named collections of IP rules (`fail2ban`, `sshd`, …), each with an `owner_key_id`. |
| `webhook_config.rs` | 247 | `webhook_configs`: downstream HTTP endpoints notified on IP events, including auth mode and templating. |
| `audit_log.rs` | 66 | `audit_logs`: the mutating-operation audit trail. Attribution columns are `NOT NULL` by migration. |
| `api_key_group_permission.rs` | 70 | `api_key_group_permissions` M:N junction: per-group read/write/delete/manage rights. The table R2's conjunction is evaluated against. |
| `ip_record_group_membership.rs` | 54 | `ip_record_group_memberships` M:N junction associating records with groups. |

## `src/migration/` — versioned DDL

| File | Lines | Purpose |
| :--- | ---: | :--- |
| `mod.rs` | 38 | Migration registry. Migrations run automatically at startup. |
| `m20230101_000001_initial_schema.rs` | 340 | Base schema: all core tables, `key_hash` declared `unique_key()` (which implies its index). |
| `m20260729_000002_add_api_key_signing_secret.rs` | 54 | Adds `api_keys.signing_secret`, the per-key HMAC secret behind `X-Signature-256`. |
| `m20260730_000003_add_webhook_signature_mode.rs` | 57 | Adds `webhook_configs.signature_mode`. |
| `m20260730_000004_add_webhook_auth_modes.rs` | 165 | Generalizes signature mode into a four-valued `auth_mode` and adds its supporting columns. |
| `m20260801_000005_add_ip_record_soft_delete.rs` | 114 | Adds `is_deleted`, `deleted_at`, `deleted_by` to `ip_records`. |
| `m20260804_000006_add_group_permission_can_manage.rs` | 66 | Adds `api_key_group_permissions.can_manage` — the per-resource half of R2's conjunction. |
| `m20260807_000007_add_api_key_master_marker.rs` | 159 | Adds `master_marker` as an **application-maintained** column. **Superseded** — retained only so the history replays. |
| `m20260807_000008_add_lineage_and_ownership.rs` | 262 | Adds `parent_key_id` and `owner_key_id`, plus the §7 hot-path indexes. |
| `m20260808_000009_derive_master_marker.rs` | 260 | Replaces the hand-maintained marker with one the **engine derives** (`GENERATED ALWAYS AS`, `STORED` on Postgres / `VIRTUAL` elsewhere). This is what satisfies `RBAC_MODEL.md` §5. |
| `m20260811_000010_audit_attribution_not_null.rs` | 287 | Makes `api_key_name`, `api_key_prefix`, `client_ip` `NOT NULL` — structurally forbidding an unattributed audit row. No peer service has an equivalent. |
| `m20260811_000011_index_ip_record_delta_columns.rs` | 72 | Indexes `ip_records.updated_at` so delta (`since`) queries do not table-scan. |
| `m20260811_000012_webhook_hmac_only_mode.rs` | 105 | Renames the `BODY_ONLY` auth mode to `HMAC_ONLY` and makes the signature header configurable. |

---

## `tests/` — what each suite is responsible for

`src/` is the subject of this map, but the suites are where its guarantees are pinned, and knowing
which file owns which property saves adding a test to the wrong one.

| File | Owns |
| :--- | :--- |
| `rbac_model_compliance.rs` | One test per `RBAC_MODEL.md` rule and section (`r1_`–`r7_`, `s3_`–`s7_`). Five are marked `ADVERSARIAL(§N)` and bypass the application layer with raw SQL. `scripts/verify_convergence.sh` fails if a rule loses its test |
| `security_tests.rs` | Named attacks, each asserting the attack fails. HMAC forgery, replay, proxy spoofing, master promotion, the unauthenticated probes |
| `schema_integrity_tests.rs` | What the **engine** does — foreign-key cascades, orphan refusal, address canonicalisation against the UNIQUE constraint, and everything `m20260811_000010`'s table rebuild had to carry across. File-backed, opened through `db::connect`, because `PRAGMA foreign_keys` is per-connection |
| `rbac_integration_tests.rs` | The features working, end to end through the router |
| `source_hygiene.rs` | Properties of the source tree: no raw SQL and no hand-written DML in `src/`, outside two startup-only exemptions. Carries a meta-test proving the scanner can see a violation |
| `concurrency_and_contracts.rs` | Races and interface contracts. Replay-ledger atomicity under real thread contention, concurrent-delete idempotency, and a map of the response shape returned for every kind of malformed input — including the two extractors that fall outside the `{"error": …}` envelope. Name shared with the peer's suite of the same purpose |
| `frontend_syntax_test.rs` | `static/app.js` parses. Nothing else compiles or executes it |

**`source_hygiene.rs` deliberately duplicates `verify_convergence.sh::check_no_raw_sql`**, and the two
are not interchangeable. The shell gate has to be *run*; the Rust test runs on every `cargo test`, in
CI and in an IDE. More to the point, two successive versions of the shell gate were silently broken —
one used a gawk extension that is an always-false variable under `mawk`, the other exempted anything
near the word "pragma" — and each reported CLEAN against a deliberately planted violation. Both
failures were invisible because neither had a meta-test. This file has one.

---

## Reading order for a new agent

1. `RBAC_MODEL.md` — the normative rules everything below implements.
2. `SCHEMA.MD` — the tables those rules are enforced against.
3. `src/api/guards.rs` — where every permission decision is actually made.
4. `src/middleware.rs` — how a request is authenticated before any guard runs.
5. `src/master.rs` — why Master identity and Master cardinality are separate properties.
6. The handler module for whatever you are changing.

## Invariants that are easy to break

- **`create_audit_log` takes its actor by value.** Do not make it `Option`; an unattributed write must stay unrepresentable.
- **`master_marker` is engine-derived and must never become settable** on any entity, fixture, or test helper (`RBAC_MODEL.md` §5).
- **SQLite runs at one pool connection.** Raising it breaks DDL, and it means concurrent requests serialize — HTTP-level tests cannot demonstrate handler races.
- **Guards live in `guards.rs`.** An inline permission check in a handler is drift, and it is what separates the converged peers from the diverging one.
