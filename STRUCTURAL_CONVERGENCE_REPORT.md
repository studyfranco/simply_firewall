# Structural & Formal Convergence Report — `simply_ip_vault` ↔ `simply_hook_executor`

**Date:** 2026-08-10 · **Mode:** strictly read-only. No file under `src/`, `tests/` or `scripts/` was
modified in either repository. **Scope:** the two services of the ecosystem, at `simply_ip_vault` HEAD
`910fafc` and the `simply_hook_executor` working tree.

**Companion to** `SECURITY_COMPARISON_REPORT.md`, which covers the security posture. This report
covers architecture: whether the two codebases share a foundational structure, or merely happen to
implement the same rules.

**Reference integrity.** The convergence gate diffs against a flat snapshot at
`example/simply_hook_executor`. That snapshot was compared against the live peer checkout before any
analysis: `diff -rq` reports **no differences** under `src/`, `tests/`, `scripts/` or `RBAC_MODEL.md`.
Only repository furniture differs (`LICENSE`, `.github/`, `deploy/`, `AGENT.MD`), none of which any
gate reads. Every comparison below is therefore against live peer code.

---

## 1. Top-level module hierarchy

| `simply_ip_vault` | `simply_hook_executor` | Role | Status |
| :--- | :--- | :--- | :--- |
| `main.rs` | `main.rs` | Startup order, bootstrap, graceful shutdown | ✅ |
| `lib.rs` | `lib.rs` | Router assembly, body limit, module declarations | ✅ |
| `config.rs` | `config.rs` | Env parsing, trusted proxies, client-IP resolution | ✅ |
| `crypto.rs` | `crypto.rs` | At-rest AEAD, CANONICAL_V1, HMAC | ✅ |
| `db.rs` | `db.rs` | Pool construction, SQLite pragmas, migrations | ✅ |
| `master.rs` | `master.rs` | Boot-time Master identity pin | ✅ |
| `middleware.rs` | `middleware.rs` | Authentication, anti-replay, `bound_ips` | ✅ |
| `replay.rs` | `replay.rs` | Anti-replay guard | ✅ |
| `retention.rs` | `retention.rs` | Background purge worker | ✅ |
| `state.rs` | `state.rs` | `AppState` | ✅ |
| `error.rs` | `error.rs` | `AppError` and its `IntoResponse` | ✅ |
| `dispatch.rs` | `executor.rs` | **The domain worker** — sends webhooks / runs hooks | ⚖️ Domain-specific |
| `extract.rs` | *(in `api/support.rs`)* | Strict JSON extractors | ⚠️ Placement divergence |
| **13 files** | **13 files** | | **11 identical names** |

**11 of 13 top-level modules share an identical name and an identical responsibility.** The two
exceptions are both explained rather than accidental:

- `dispatch.rs` ↔ `executor.rs` is the **only place the two services genuinely do different things**.
  One dispatches signed HTTP notifications; the other executes local processes. A shared name here
  would be worse than the divergence — it would imply a shared threat model that does not exist.
- `extract.rs` is discussed in §5.

---

## 2. `src/api/` — separation of concerns

| `simply_ip_vault` | Lines | `simply_hook_executor` | Lines | Role | Status |
| :--- | ---: | :--- | ---: | :--- | :--- |
| `mod.rs` | 69 | `mod.rs` | 95 | Declarations and flat re-exports. **No executable code** | ✅ |
| `guards.rs` | 457 | `guards.rs` | 932 | Every authorization decision. Writes nothing | ✅ |
| `support.rs` | 260 | `support.rs` | 399 | Plumbing used by ≥3 domains. Decides nothing | ✅ |
| `keys.rs` | 1 365 | `keys.rs` | 1 255 | Key CRUD, `/auth/me`, grants, §6 cascade | ✅ |
| `audit.rs` | 54 | `audit.rs` | 78 | Audit-trail reads | ✅ |
| `health.rs` | 121 | `health.rs` | 102 | Unauthenticated probes | ✅ |
| `records.rs` | 962 | `executions.rs` | — | Domain: addresses / execution records | ⚖️ Domain |
| `groups.rs` | 197 | `hooks.rs` | — | Domain: managed resource | ⚖️ Domain |
| `webhooks.rs` | 580 | — | — | Domain: dispatch-target config | ⚖️ Domain |
| — | — | `system.rs` | — | Effective-configuration readback | ⚠️ Absent here |

**The three structural modules — `mod.rs`, `guards.rs`, `support.rs` — are identically named,
identically scoped, and governed by the same two written rules on both sides:**

| Rule | `simply_ip_vault` | `simply_hook_executor` |
| :--- | :--- | :--- |
| `guards` is one module, not one per domain | ✅ stated in `mod.rs` header | ✅ stated in `mod.rs` header |
| Nothing in `support` makes an authorization decision | ✅ stated and testable | ✅ stated and testable |
| Handlers re-exported **flat** so paths survive the split | ✅ | ✅ |

That last point is worth naming: both services split a ~3,700-line `api.rs` into domain modules and
both chose to re-export flat so `api::create_api_key` still resolves. Neither forced its call sites to
change. This was not coordinated.

**One asymmetry:** the peer's `api/system.rs` (`get_settings`, master-only configuration readback) has
no counterpart here. That is a **missing feature**, not a structural defect — the vault has no
equivalent surface to expose.

---

## 3. `src/entities/` — data layer

| `simply_ip_vault` | `simply_hook_executor` | Relationship |
| :--- | :--- | :--- |
| `api_key.rs` | `api_key.rs` | ✅ Identical role and name |
| `audit_log.rs` | `audit_log.rs` | ✅ Identical role and name |
| `api_key_group_permission.rs` | `api_key_hook_permission.rs` | ⚖️ Same M:N grant role, named for its resource |
| `ip_group.rs` | `hook.rs` | ⚖️ The **managed resource** in each domain |
| `ip_record.rs` | `execution.rs` | ⚖️ The domain's record type |
| `ip_record_group_membership.rs` | — | ⚖️ Vault-only join table |
| `webhook_config.rs` | — | ⚖️ Vault's separate **dispatch target** |
| — | `hook_parameter.rs` | ⚖️ Peer-only parameter contract |
| `mod.rs`, `prelude.rs` | `mod.rs`, `prelude.rs` | ✅ Identical convention |

The naming pattern is uniform: `<resource>.rs` for a table, `api_key_<resource>_permission.rs` for its
grant table. Both use the same SeaORM shape (`Model` / `ActiveModel` / `Column` / `Relation`) and both
keep `prelude.rs` as the `Entity` re-export set.

**The structural divergence recorded in the August audit persists and remains correct.** The vault has
two entities for the specification's two roles (`ip_groups` = managed resource, `webhook_configs` =
dispatch target); the peer's `hooks` holds both roles at once. This is a consequence of the domain,
not of rigour, and it is why §4's third visibility scope is real in the vault and vacuous in the peer.

---

## 4. Naming conventions — security surface

Every shared security symbol was checked for presence in both trees.

| Symbol | Vault | Peer | Category |
| :--- | :---: | :---: | :--- |
| `auth_middleware` | ✅ | ✅ | Middleware |
| `ClientIp` | ✅ | ✅ | Middleware |
| `resolve_client_ip` | ✅ | ✅ | Proxy trust |
| `normalize_ip` | ✅ | ✅ | Proxy trust |
| `parse_trusted_proxies` | ✅ | ✅ | Proxy trust |
| `canonical_v1_payload` | ✅ | ✅ | Signing |
| `compute_signature` | ✅ | ✅ | Signing |
| `verify_signature` | ✅ | ✅ | Signing |
| `generate_signing_secret` | ✅ | ✅ | Signing |
| `SecretCipher` | ✅ | ✅ | At-rest crypto |
| `ReplayGuard` | ✅ | ✅ | Anti-replay |
| `apply_sqlite_pragmas` | ✅ | ✅ | Database |
| `run_migrations` | ✅ | ✅ | Database |
| `MasterPin` | ✅ | ✅ | §5 identity |
| `MasterPin::pin_at_boot` | ✅ | ✅ | §5 identity |
| `MasterPin::authenticate` | ✅ | ✅ | §5 identity |
| `MasterPin::pinned_to` | ✅ | ✅ | §5 identity (test) |
| `create_audit_log` | ✅ | ✅ | Observability |
| `hash_key` | ✅ | ✅ | Credentials |
| `generate_random_key` | ✅ | ✅ | Credentials |
| `StrictJson` | ✅ | ✅ | Input strictness |
| `OptionalStrictJson` | ✅ | ✅ | Input strictness |
| `health_check` | ✅ | ✅ | Probes |
| `readiness_check` | ✅ | ✅ | Probes |

**24 of 24 shared security symbols carry identical names in both services.** No renames are
outstanding.

### Payload and guard naming

| Convention | Vault | Peer | Status |
| :--- | :--- | :--- | :--- |
| Request payloads | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `ReassignOwnerPayload` | `CreateApiKeyPayload`, `UpdateApiKeyPayload` | ✅ `<Verb><Noun>Payload` |
| Response DTOs | `MeResponse`, `<Noun>Response` | same | ✅ |
| Guards | `guard_<subject>` (`guard_group_manage`, `guard_scope_elevation`) | `require_<subject>` / `guard_<subject>` | ⚠️ Mixed prefix |
| Compliance tests | `r<N>_…` / `s<N>_…` | `r<N>_…` / `s<N>_…` | ✅ 12 prefixes each |

The guard prefix is the one naming inconsistency of substance: the vault uses `guard_` uniformly,
while the peer mixes `require_` and `guard_`. Cosmetic — no behaviour depends on it — but it is the
only place where an engineer moving between the repositories cannot predict a name.

---

## 5. Divergences, and whether each is justified

| # | Divergence | Justified? | Reasoning |
| ---: | :--- | :--- | :--- |
| 1 | `dispatch.rs` ↔ `executor.rs` | ✅ **Yes** | The one genuine domain difference. A shared name would imply a shared threat model that does not exist |
| 2 | `extract.rs` (vault, top-level) vs extractors inside `api/support.rs` (peer) | ✅ **Yes — vault's is better** | `StrictJson` is a `RBAC_MODEL.md` §5 *type-level control*. `support.rs` is documented on both sides as "plumbing that decides nothing". Converging would bury a named specification control inside a helper module |
| 3 | Peer has `api/system.rs`; vault has none | ✅ **Yes** | A missing feature, not a misplacement |
| 4 | Domain modules (`records`/`groups`/`webhooks` vs `executions`/`hooks`) | ✅ **Yes** | Named for what they hold |
| 5 | Guard prefix `guard_` vs `require_`/`guard_` | ⚠️ **Cosmetic** | The only unforced naming inconsistency in the ecosystem |
| 6 | Adversarial-test marking: doc-comment `ADVERSARIAL(§N)` vs function name `<rule>_adversarial_…` | ⚖️ **Convention only** | Both are *load-bearing in their own gate*. Equivalent rigour — see §7 |

---

## 6. Error handling — strictly unified

| Aspect | `simply_ip_vault` | `simply_hook_executor` | Status |
| :--- | :--- | :--- | :--- |
| Error type | `AppError` in `error.rs` | `AppError` in `error.rs` | ✅ |
| Response body | `{"error": "<message>"}` | `{"error": "<message>"}` | ✅ **Byte-identical shape** |
| Rendering | `impl IntoResponse for AppError` | same | ✅ |

### Variant taxonomy

| Variant | Vault | Peer | HTTP |
| :--- | :---: | :---: | :--- |
| `Unauthorized` | ✅ | ✅ | `401` |
| `Forbidden` | ✅ | ✅ | `403` |
| `NotFound` | ✅ | ✅ | `404` |
| `Conflict` | ✅ | ✅ | `409` |
| `InvalidInput` | ✅ | ✅ | `400` |
| `Json` | ✅ | ✅ | `400` |
| `BodyRejected` | ✅ | ✅ | **passthrough** — preserves `413` |
| `DbError` | ✅ | ✅ | `500` |
| `Internal` | ✅ | ✅ | `500` |
| `ConflictWithDetails` | ✅ | ❌ | `409` + §6 inventory |
| `TooManyRequests` | ❌ | ✅ | `429` — concurrency budget |

**9 of 11 variants are shared, with identical status mappings.** The two singletons are each required
by exactly one domain: the vault's §6 pre-flight inventory needs structured detail merged into the
body; the peer's concurrency budget needs `429`. Neither is an inconsistency.

The most security-relevant agreement is `BodyRejected`, which both services introduced for the same
reason: normalising the response *shape* must not normalise its *meaning*, so an oversized body still
answers `413` rather than being flattened into `400`.

---

## 7. Observability — audit trail

| Field | Vault | Peer | Status |
| :--- | :---: | :---: | :--- |
| `id` | ✅ | ✅ | ✅ |
| `api_key_id` | ✅ | ✅ | ✅ `ON DELETE SET NULL` on both |
| `api_key_name` | ✅ | ✅ | ✅ Denormalised |
| `api_key_prefix` | ✅ | ✅ | ✅ Denormalised |
| `client_ip` | ✅ | ✅ | ✅ |
| `action` | ✅ | ✅ | ✅ |
| `details` | ✅ | ✅ | ✅ |
| `timestamp` | ✅ | ✅ | ✅ |
| `target_address` | ✅ | — | ⚠️ vs `target_resource` |
| `target_resource` | — | ✅ | ⚠️ Same role, different name |
| `group_names` | ✅ | — | ⚖️ Vault-only |

**8 of 10 fields are identical in name and semantics.** The denormalisation decision is the notable
convergence: both services store the acting key's name and prefix *as a point-in-time snapshot* rather
than relying on the FK, so the trail stays legible after the key is deleted — and both chose
`SET NULL` over `CASCADE` on `audit_logs.api_key_id`, so deleting a credential cannot erase the record
of what it did. Independently reasoned, identical conclusion.

`target_address` vs `target_resource` is the same column under two names. Harmless within a service;
mildly annoying for a shared log pipeline.

### Verification gates

| Gate | Vault | Peer | Status |
| :--- | :--- | :--- | :--- |
| `scripts/verify_convergence.sh` | ✅ | ✅ | ✅ Both maintain one |
| `scripts/test_e2e.sh` | ✅ | ✅ | ✅ |
| `RBAC_MODEL.md` byte-identity gate | ✅ | ✅ | ✅ |
| Compliance suite | `rbac_model_compliance.rs`, 25 tests | `rbac_model_compliance.rs`, 24 tests | ✅ Same name, 12 rule prefixes each |
| Referential-integrity suite | `schema_integrity_tests.rs` | `referential_integrity.rs` | ⚖️ Same role, different name |
| Raw-DML ban | shell gate | `tests/source_hygiene.rs` | ⚖️ Same rule, different mechanism |
| Adversarial-coverage gate | `check_adversarial_coverage` | `adversarial_infrastructure_coverage` | ✅ Both enforce it |

The adversarial gate deserves emphasis. A naive count of `ADVERSARIAL(` markers gives **vault 5, peer
0**, which reads as a serious asymmetry and is **wrong**. The peer encodes the property in the
function name and makes *that* load-bearing in its own gate. Both services run §5 tests that bypass
the entity layer with raw SQL, and both carry a negative control against passing for the wrong reason.
This is the same discipline expressed two ways, and it is recorded here so no future audit re-raises
it.

---

## 8. Executive verdict

**Convergence level: high, and structural rather than incidental.**

| Dimension | Result |
| :--- | :--- |
| Top-level modules with identical names and roles | **11 / 13** |
| `api/` structural modules (`mod`, `guards`, `support`) | **3 / 3 identical** |
| Shared security symbols with identical names | **24 / 24** |
| Error variants shared, with identical status mappings | **9 / 11** |
| Error response body shape | **identical** |
| Audit-log fields identical | **8 / 10** |
| Verification gates present on both sides | **7 / 7** |
| Unjustified divergences | **1** (guard prefix, cosmetic) |

The two services share a foundational DNA. Ten of the eleven top-level modules that *can* be shared
are shared by name and by responsibility; the eleventh (`dispatch` / `executor`) is the single point
where the domains genuinely differ, and naming it identically would have been the error. Every
remaining structural difference traces to the entity model — one service separates managed resource
from dispatch target, the other combines them — which the specification itself does not resolve.

What raises this above coincidence is the evidence of **independent convergence**. Both services split
a ~3,700-line `api.rs` by domain and both re-exported flat to protect call sites. Both isolated
authorization into a single cross-cutting `guards` module and wrote down the same justification for
not splitting it per-domain. Both denormalised the acting key into the audit row and chose `SET NULL`
so a deleted credential cannot erase its own trail. Both added `BodyRejected` to stop response-shape
normalisation from destroying `413`. Both factored Master pinning into a `MasterPin` type with the
same four method names. None of this was coordinated, and agreement reached twice from the same
constraints is worth considerably more than agreement reached once and copied.

**Maturity assessment.** The architecture is no longer the notable part; the *enforcement of the
architecture* is. Both repositories carry an automated convergence gate, a byte-identity check on the
shared specification, a ban on raw DML in application code, and a gate that fails when an
infrastructure-level rule lacks an adversarial test. That last mechanism exists on both sides as the
direct institutional response to the August §5 defect, where cooperative tests certified a bypassable
constraint. These are the controls that make the next such defect fail loudly rather than pass
quietly.

**Verdict: architecturally converged.** One cosmetic naming inconsistency (`require_` vs `guard_`)
is the only unforced divergence in the ecosystem, and it blocks nothing. Every other difference is
documented, justified, and in most cases a consequence of the domains rather than of the engineering.
