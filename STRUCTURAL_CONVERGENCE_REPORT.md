# Structural & Formal Convergence Report — `simply_ip_vault` ↔ `simply_hook_executor`

**Date:** 2026-08-11 · **Mode:** strictly read-only. No file under `src/`, `tests/` or `scripts/` was
modified in either project.

**Scope.** The **current project** — this repository, at HEAD `6f1c4c7` — against its **peer**, read
exclusively from `example/simply_hook_executor`, pulled to its current head `4865a82` before analysis.
No source outside these two trees was consulted.

**Companion to** `SECURITY_COMPARISON_REPORT.md`, which covers the security posture. This report covers
architecture: whether the two codebases share a foundational structure, or merely happen to implement
the same rules.

---

## 1. Top-level module hierarchy

| Current project | Peer | Role | Status |
| :--- | :--- | :--- | :--- |
| `main.rs` (316) | `main.rs` (347) | Startup order, bootstrap, graceful shutdown | ✅ |
| `lib.rs` (152) | `lib.rs` (163) | Router assembly, body limit, module declarations | ✅ |
| `config.rs` (1 397) | `config.rs` (1 642) | Env parsing, trusted proxies, client-IP resolution, master-key validation | ✅ |
| `crypto.rs` (839) | `crypto.rs` (781) | At-rest AEAD, CANONICAL_V1, HMAC | ✅ |
| `db.rs` (376) | `db.rs` (427) | Pool construction, SQLite pragmas, migrations | ✅ |
| `master.rs` (320) | `master.rs` (291) | Boot-time Master identity pin | ✅ |
| `middleware.rs` (319) | `middleware.rs` (543) | Authentication, anti-replay, `bound_ips` | ✅ |
| `replay.rs` (440) | `replay.rs` (406) | Anti-replay guard | ✅ |
| `retention.rs` (134) | `retention.rs` (150) | Background purge worker | ✅ |
| `state.rs` (169) | `state.rs` (80) | `AppState` | ✅ |
| `error.rs` (107) | `error.rs` (140) | `AppError` and its `IntoResponse` | ✅ |
| `dispatch.rs` (532) | `executor.rs` (1 389) | **The domain worker** — sends webhooks / runs hooks | ⚖️ Domain-specific |
| `extract.rs` (128) | *(in `api/support.rs`)* | Strict JSON extractors | ⚠️ Placement divergence |
| **13 files** | **13 files** | **11 733 / 12 501 lines** | **11 identical names** |

**11 of 13 top-level modules share an identical name and an identical responsibility.** Both exceptions
are explained rather than accidental:

- `dispatch.rs` ↔ `executor.rs` is the **only place the two projects genuinely do different things**.
  One dispatches signed HTTP notifications; the other executes local processes. A shared name here
  would be worse than the divergence — it would imply a shared threat model that does not exist, and
  the 2.6× size difference reflects genuinely different problems.
- `extract.rs` is discussed in §5.

---

## 2. `src/api/` — separation of concerns

| Current project | Lines | Peer | Lines | Role | Status |
| :--- | ---: | :--- | ---: | :--- | :--- |
| `mod.rs` | 69 | `mod.rs` | 95 | Declarations and flat re-exports. **No executable code** | ✅ |
| `guards.rs` | 457 | `guards.rs` | 932 | Every authorization decision. Writes nothing | ✅ |
| `support.rs` | 280 | `support.rs` | 426 | Plumbing used by ≥3 domains. Decides nothing | ✅ |
| `keys.rs` | 1 365 | `keys.rs` | 1 274 | Key CRUD, `/auth/me`, grants, §6 cascade | ✅ |
| `audit.rs` | 54 | `audit.rs` | 78 | Audit-trail reads | ✅ |
| `health.rs` | 121 | `health.rs` | 131 | Unauthenticated probes | ✅ |
| `records.rs` | 962 | `executions.rs` | — | Domain: addresses / execution records | ⚖️ Domain |
| `groups.rs` | 197 | `hooks.rs` | — | Domain: managed resource | ⚖️ Domain |
| `webhooks.rs` | 580 | — | — | Domain: dispatch-target config | ⚖️ Domain |
| — | — | `system.rs` | 101 | Effective-configuration readback | ⚠️ Absent here |

**The three structural modules — `mod.rs`, `guards.rs`, `support.rs` — are identically named,
identically scoped, and governed by the same written rules on both sides:**

| Rule | Current project | Peer |
| :--- | :--- | :--- |
| `guards` is one module, not one per domain | ✅ stated in the `mod.rs` header | ✅ stated in the `mod.rs` header |
| Nothing in `support` makes an authorization decision | ✅ stated and testable | ✅ stated and testable |
| Handlers re-exported **flat** so paths survive the split | ✅ | ✅ |
| `mod.rs` holds no executable code | ✅ 69 lines | ✅ 95 lines |

Both projects split a ~3 700-line `api.rs` into domain modules and both chose to re-export flat so
`api::create_api_key` still resolves. Neither forced its call sites to change. This was not
coordinated.

**One asymmetry:** the peer's `api/system.rs` (`get_settings`, master-only configuration readback) has
no counterpart here. That is a **missing feature**, not a structural defect — this project has no
equivalent surface to expose.

---

## 3. `src/entities/` — data layer

| Current project | Peer | Relationship |
| :--- | :--- | :--- |
| `api_key.rs` | `api_key.rs` | ✅ Identical role and name |
| `audit_log.rs` | `audit_log.rs` | ✅ Identical role and name |
| `api_key_group_permission.rs` | `api_key_hook_permission.rs` | ⚖️ Same M:N grant role, named for its resource |
| `ip_group.rs` | `hook.rs` | ⚖️ The **managed resource** in each domain |
| `ip_record.rs` | `execution.rs` | ⚖️ The domain's record type |
| `ip_record_group_membership.rs` | — | ⚖️ Join table, this project only |
| `webhook_config.rs` | — | ⚖️ Separate **dispatch target**, this project only |
| — | `hook_parameter.rs` | ⚖️ Parameter contract, peer only |
| `mod.rs`, `prelude.rs` | `mod.rs`, `prelude.rs` | ✅ Identical convention |

The naming pattern is uniform: `<resource>.rs` per table, `api_key_<resource>_permission.rs` for its
grant table. Both use the same SeaORM shape (`Model` / `ActiveModel` / `Column` / `Relation`) and both
keep `prelude.rs` as the `Entity` re-export set.

The structural divergence recorded in earlier audits persists and remains correct: this project has
two entities for the specification's two roles (`ip_groups` = managed resource, `webhook_configs` =
dispatch target); the peer's `hooks` holds both roles at once. A consequence of the domain, not of
rigour, and it is why §4's third visibility scope is real here and vacuous there.

---

## 4. Naming conventions

### Security surface — 25 of 25 symbols identical

| Symbol | Category |
| :--- | :--- |
| `auth_middleware`, `ClientIp` | Middleware |
| `resolve_client_ip`, `normalize_ip`, `parse_trusted_proxies` | Proxy trust |
| `canonical_v1_payload`, `compute_signature`, `verify_signature`, `generate_signing_secret` | Signing |
| `SecretCipher` | At-rest crypto |
| `ReplayGuard` | Anti-replay |
| `apply_sqlite_pragmas`, `run_migrations` | Database |
| `MasterPin`, `pin_at_boot`, `authenticate`, `pinned_to` | §5 identity |
| `validate_initial_master_key` | Credential validation **(new on the peer)** |
| `create_audit_log` | Observability |
| `hash_key`, `generate_random_key` | Credentials |
| `StrictJson`, `OptionalStrictJson` | Input strictness |
| `health_check`, `readiness_check` | Probes |

**Every one is present in both trees under the same name.** No renames outstanding.

### Guards and payloads

| Convention | Current project | Peer | Status |
| :--- | :--- | :--- | :--- |
| Guard prefix | `guard_*` × 7, `require_*` × 0 | `guard_*` × 11, `require_*` × 0 | ✅ **Unified** — the peer dropped `require_` in `4865a82` |
| Request payloads | `<Verb><Noun>Payload` × 9 | `<Verb><Noun>Payload` × 6 | ✅ |
| Response DTOs | `MeResponse`, `<Noun>Response` | same | ✅ |
| Compliance tests | `r<N>_…` / `s<N>_…`, 12 prefixes | `r<N>_…` / `s<N>_…`, 12 prefixes | ✅ |

The mixed `require_`/`guard_` prefix was the **only unforced naming divergence** the 2026-08-10 report
identified. It is now closed: the peer uses `guard_` exclusively.

---

## 5. Divergences, and whether each is justified

| # | Divergence | Justified? | Reasoning |
| ---: | :--- | :--- | :--- |
| 1 | `dispatch.rs` ↔ `executor.rs` | ✅ **Yes** | The one genuine domain difference. A shared name would imply a shared threat model that does not exist |
| 2 | `extract.rs` (top level) vs extractors inside `api/support.rs` | ✅ **Yes — this project's is better** | `StrictJson` is a `RBAC_MODEL.md` §5 *type-level control*. `support.rs` is documented on both sides as "plumbing that decides nothing". Converging would bury a named specification control inside a helper module |
| 3 | Peer has `api/system.rs`; this project has none | ✅ **Yes** | A missing feature, not a misplacement |
| 4 | Domain modules (`records`/`groups`/`webhooks` vs `executions`/`hooks`) | ✅ **Yes** | Named for what they hold |
| 5 | Adversarial-test marking: `ADVERSARIAL(§N)` doc token vs `<rule>_adversarial_…` function name | ⚖️ **Convention only** | Both are load-bearing in their own gate; both projects carry 5 such tests |

**No unjustified divergence remains.** The previous edition of this report identified exactly one —
the guard prefix — and it has since been closed by the peer.

---

## 6. Error handling — strictly unified

| Aspect | Current project | Peer | Status |
| :--- | :--- | :--- | :--- |
| Error type | `AppError` in `error.rs` | `AppError` in `error.rs` | ✅ |
| Response body | `{"error": "<message>"}` | `{"error": "<message>"}` | ✅ **Identical shape** |
| Rendering | `impl IntoResponse for AppError` | same | ✅ |

### Variant taxonomy

| Variant | Current | Peer | HTTP |
| :--- | :---: | :---: | :--- |
| `Unauthorized` | ✅ | ✅ | `401` |
| `Forbidden` | ✅ | ✅ | `403` |
| `NotFound` | ✅ | ✅ | `404` |
| `Conflict` | ✅ | ✅ | `409` |
| `ConflictWithDetails` | ✅ | ✅ **(new)** | `409` + structured detail |
| `InvalidInput` | ✅ | ✅ | `400` |
| `Json` | ✅ | ✅ | `400` |
| `BodyRejected` | ✅ | ✅ | **passthrough** — preserves `413` |
| `DbError` | ✅ | ✅ | `500` |
| `Internal` | ✅ | ✅ | `500` |
| `TooManyRequests` | ❌ | ✅ | `429` — concurrency budget |

**10 of 11 variants shared with identical status mappings**, up from 9 in the previous edition: the
peer adopted `ConflictWithDetails` in `4865a82`. The single remaining singleton, `TooManyRequests`, is
required by exactly one domain — the peer's execution concurrency budget — and this project has no
equivalent to rate-limit.

The most security-relevant agreement is `BodyRejected`, which both projects introduced for the same
reason: normalising the response *shape* must not normalise its *meaning*, so an oversized body still
answers `413` rather than being flattened into `400`.

---

## 7. Observability — audit trail

| Field | Current | Peer | Status |
| :--- | :---: | :---: | :--- |
| `id` | ✅ | ✅ | ✅ |
| `api_key_id` | ✅ | ✅ | ✅ nullable, `ON DELETE SET NULL` both sides |
| `api_key_name` | ✅ | ✅ | ✅ **`NOT NULL` both sides** |
| `api_key_prefix` | ✅ | ✅ | ✅ **`NOT NULL` both sides** |
| `client_ip` | ✅ | ✅ | ✅ **`NOT NULL` both sides** |
| `action` | ✅ | ✅ | ✅ |
| `details` | ✅ | ✅ | ✅ |
| `timestamp` | ✅ | ✅ | ✅ |
| `target_address` / `target_resource` | ✅ | ✅ | ⚠️ Same role, different name |
| `group_names` | ✅ | — | ⚖️ Domain-specific |

**8 of 10 fields identical in name, semantics and nullability.** The attribution columns converged this
cycle: this project made them `NOT NULL` in `m20260811_000010`, matching what the peer has had since
its initial schema.

The design agreement underneath is the notable part. Both store the acting key's name and prefix as a
**point-in-time snapshot** rather than relying on the FK, and both chose `SET NULL` over `CASCADE` on
`audit_logs.api_key_id` — so deleting a credential cannot erase the record of what it did, and the
denormalised columns are what keeps the row legible afterwards. Independently reasoned, identical
conclusion; the `NOT NULL` constraint is what makes it a guarantee rather than a convention.

`target_address` vs `target_resource` is the same column under two names — harmless within a service,
mildly awkward for a shared log pipeline.

### Verification gates

| Gate | Current | Peer | Status |
| :--- | :--- | :--- | :--- |
| `scripts/verify_convergence.sh` | ✅ | ✅ | ✅ |
| `scripts/test_e2e.sh` | ✅ | ✅ | ✅ |
| `RBAC_MODEL.md` byte-identity | ✅ | ✅ | ✅ |
| Compliance suite | `rbac_model_compliance.rs`, 25 tests | `rbac_model_compliance.rs`, 24 tests | ✅ Same name, 12 prefixes each |
| Adversarial coverage | 5 tests, gated | 5 tests, gated | ✅ |
| Source hygiene (raw-SQL/DML ban) | `tests/source_hygiene.rs` | `tests/source_hygiene.rs` | ✅ **Same filename** |
| Referential integrity | `schema_integrity_tests.rs` | `referential_integrity.rs` | ⚖️ Same role, different name |

---

## 8. Executive verdict

**Convergence level: high, and structural rather than incidental.**

| Dimension | Result |
| :--- | :--- |
| Top-level modules with identical names and roles | **11 / 13** |
| `api/` structural modules (`mod`, `guards`, `support`) | **3 / 3 identical** |
| Shared security symbols with identical names | **25 / 25** |
| Error variants shared, identical status mappings | **10 / 11** |
| Error response body shape | **identical** |
| Audit-log fields identical | **8 / 10** |
| Verification gates present on both sides | **7 / 7** |
| **Unjustified divergences** | **0** |

Both structural items the previous edition flagged have closed this cycle. The guard prefix is
unified; the peer adopted `ConflictWithDetails`, and this project made its audit attribution
`NOT NULL`. Two projects, converging from both directions.

What raises this above coincidence is the record of **independent convergence**. Both split a
~3 700-line `api.rs` by domain and both re-exported flat to protect call sites. Both isolated
authorization into a single cross-cutting `guards` module and wrote down the same justification for
not splitting it per-domain. Both denormalised the acting key into the audit row and chose `SET NULL`
so a deleted credential cannot erase its own trail. Both added `BodyRejected` to stop response-shape
normalisation from destroying `413`. Both factored Master pinning into a `MasterPin` type with the
same four method names. Both landed on `tests/source_hygiene.rs` as the filename for the raw-SQL ban.
None of this was coordinated, and agreement reached twice from the same constraints is worth
considerably more than agreement reached once and copied.

**Maturity.** The architecture is no longer the notable part; the *enforcement* of the architecture is.
Both repositories carry an automated convergence gate, a byte-identity check on the shared
specification, a raw-SQL ban that runs on every `cargo test`, and a gate that fails when an
infrastructure-level rule lacks an adversarial test. That last mechanism exists on both sides as the
direct institutional response to the §5 defect, where cooperative tests certified a bypassable
constraint. These are the controls that make the next such defect fail loudly rather than pass
quietly.

**Verdict: architecturally converged, with no outstanding structural work.** Every remaining difference
is documented, justified, and in every case a consequence of the domains rather than of the
engineering.
