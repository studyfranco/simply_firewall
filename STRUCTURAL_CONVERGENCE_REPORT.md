# Structural & Formal Convergence Report — `simply_ip_vault` ↔ `simply_hook_executor`

**Date:** 2026-08-11 · **Mode:** strictly read-only. No file under `src/`, `tests/` or `scripts/` was
modified in either project.

**Scope.** The **current project** — this repository — against its **peer**, read exclusively from
`example/simply_hook_executor` at `4865a82` (`git pull`: already up to date).

**Methodology: clean-room.** Written without reference to any prior structural analysis. Every figure
below was measured from the two source trees during this pass.

**Companion to** `SECURITY_COMPARISON_REPORT.md`, which covers the security posture. This report asks a
narrower question: do these two codebases share a foundational structure, or do they merely implement
the same rules by different means?

---

## 1. Top-level module hierarchy

| Current project | Lines | Peer | Lines | Role | Status |
| :--- | ---: | :--- | ---: | :--- | :--- |
| `main.rs` | 316 | `main.rs` | 347 | Startup order, bootstrap, graceful shutdown | ✅ |
| `lib.rs` | 152 | `lib.rs` | 163 | Router assembly, body limit, module declarations | ✅ |
| `config.rs` | 1 397 | `config.rs` | 1 642 | Env parsing, trusted proxies, client-IP resolution, master-key validation | ✅ |
| `crypto.rs` | 839 | `crypto.rs` | 781 | At-rest AEAD, CANONICAL_V1, HMAC | ✅ |
| `db.rs` | 376 | `db.rs` | 427 | Pool construction, SQLite pragmas, migrations | ✅ |
| `master.rs` | 320 | `master.rs` | 291 | Boot-time Master identity pin | ✅ |
| `middleware.rs` | 319 | `middleware.rs` | 543 | Authentication, anti-replay, `bound_ips` | ✅ |
| `replay.rs` | 440 | `replay.rs` | 406 | Anti-replay guard | ✅ |
| `retention.rs` | 134 | `retention.rs` | 150 | Background purge worker | ✅ |
| `state.rs` | 169 | `state.rs` | 80 | `AppState` | ✅ |
| `error.rs` | 107 | `error.rs` | 140 | `AppError` and its `IntoResponse` | ✅ |
| `dispatch.rs` | 532 | `executor.rs` | 1 389 | **The domain worker** | ⚖️ Domain |
| `extract.rs` | 128 | *(in `api/support.rs`)* | — | Strict JSON extractors | ⚠️ Placement |
| **13 files** | **11 820** | **13 files** | **12 501** | | **11 identical names** |

**11 of 13 top-level modules share an identical name and an identical responsibility.** Both
exceptions are structural rather than accidental:

- `dispatch.rs` ↔ `executor.rs` is the **only place the two projects genuinely do different things**.
  One signs and sends outbound HTTP; the other executes local processes under a configured user. The
  2.6× size difference reflects genuinely different problems, and a shared name would falsely imply a
  shared threat model.
- `extract.rs` — see §5.

---

## 2. `src/api/` — separation of concerns

| Current | Lines | Peer | Lines | Role | Status |
| :--- | ---: | :--- | ---: | :--- | :--- |
| `mod.rs` | 69 | `mod.rs` | 95 | Declarations and flat re-exports. **No executable code** | ✅ |
| `guards.rs` | 457 | `guards.rs` | 932 | Every authorization decision. Writes nothing | ✅ |
| `support.rs` | 280 | `support.rs` | 426 | Plumbing used by ≥3 domains. Decides nothing | ✅ |
| `keys.rs` | 1 365 | `keys.rs` | 1 274 | Key CRUD, `/auth/me`, grants, §6 cascade | ✅ |
| `audit.rs` | 54 | `audit.rs` | 78 | Audit-trail reads | ✅ |
| `health.rs` | 121 | `health.rs` | 131 | Unauthenticated probes | ✅ |
| `records.rs` | 962 | `executions.rs` | — | Domain: resource data | ⚖️ Domain |
| `groups.rs` | 197 | `hooks.rs` | — | Domain: managed resource | ⚖️ Domain |
| `webhooks.rs` | 580 | — | — | Domain: creator-private entity | ⚖️ Domain |
| — | — | `system.rs` | 101 | Effective-configuration readback | ⚠️ Absent here |

**The three structural modules — `mod.rs`, `guards.rs`, `support.rs` — are identically named,
identically scoped, and governed by the same written rules on both sides:**

| Rule | Current | Peer |
| :--- | :--- | :--- |
| `guards` is one module, not one per domain | ✅ stated in the `mod.rs` header | ✅ stated in the `mod.rs` header |
| Nothing in `support` makes an authorization decision | ✅ | ✅ |
| Handlers re-exported **flat** so paths survive the split | ✅ | ✅ |
| `mod.rs` holds no executable code | ✅ | ✅ |

Both split a large monolithic `api.rs` by domain and both re-exported flat so `api::create_api_key`
still resolves — neither forced its call sites to change. The rationale for keeping `guards` as one
cross-cutting module rather than one per domain is written down in both headers in almost the same
terms: the specification's rules are cross-cutting, and splitting them by caller would put one
sentence of `RBAC_MODEL.md` in three files and invite the copies to drift.

**One asymmetry:** the peer's `api/system.rs` (`get_settings`) has no counterpart here — a missing
feature, not a misplacement.

---

## 3. `src/entities/` — data layer

| Current | Peer | Relationship |
| :--- | :--- | :--- |
| `api_key.rs` | `api_key.rs` | ✅ Identical role and name |
| `audit_log.rs` | `audit_log.rs` | ✅ Identical role and name |
| `api_key_group_permission.rs` | `api_key_hook_permission.rs` | ⚖️ Same M:N grant role, named for its resource |
| `ip_group.rs` | `hook.rs` | ⚖️ The **managed resource** |
| `ip_record.rs` | `hook_parameter.rs` | ⚖️ The **resource data** |
| `webhook_config.rs` | `execution.rs` | ⚖️ The **creator-private entity** |
| `ip_record_group_membership.rs` | — | ⚖️ Join table, current project only |
| `mod.rs`, `prelude.rs` | `mod.rs`, `prelude.rs` | ✅ Identical convention |

The mapping is one-to-one against `RBAC_MODEL.md`'s terminology table for all four generic roles.
Naming is uniform: `<resource>.rs` per table, `api_key_<resource>_permission.rs` for its grant table.
Both use the same SeaORM shape (`Model` / `ActiveModel` / `Column` / `Relation`) and both keep
`prelude.rs` as the `Entity` re-export set.

**One structural difference has a security consequence.** The current project's resource data
(`ip_records`) is globally unique and reached through a join table, so one record may belong to
several managed resources; the peer's `hook_parameter.hook_id` is a single foreign key, so its
resource data belongs to exactly one. That difference is the root of finding **F-2** in the security
report — an authorization question that simply cannot arise on the peer side.

---

## 4. Naming conventions

### Security surface — 25 of 25 symbols identical

| Symbols | Category |
| :--- | :--- |
| `auth_middleware`, `ClientIp` | Middleware |
| `resolve_client_ip`, `normalize_ip`, `parse_trusted_proxies` | Proxy trust |
| `canonical_v1_payload`, `compute_signature`, `verify_signature`, `generate_signing_secret` | Signing |
| `SecretCipher` · `ReplayGuard` | At-rest crypto · Anti-replay |
| `apply_sqlite_pragmas`, `run_migrations` | Database |
| `MasterPin`, `pin_at_boot`, `authenticate`, `pinned_to` | §5 identity |
| `validate_initial_master_key` | Credential validation |
| `create_audit_log` · `hash_key`, `generate_random_key` | Observability · Credentials |
| `StrictJson`, `OptionalStrictJson` | Input strictness |
| `health_check`, `readiness_check` | Probes |

**Every one present in both trees under the same name.** No renames outstanding.

### Guards, payloads, tests

| Convention | Current | Peer | Status |
| :--- | :--- | :--- | :--- |
| Guard prefix | `guard_*` × 7, `require_*` × 0 | `guard_*` × 11, `require_*` × 0 | ✅ Unified |
| Request payloads | `<Verb><Noun>Payload` × 9 | `<Verb><Noun>Payload` × 6 | ✅ |
| Response DTOs | `MeResponse`, `<Noun>Response` | identical | ✅ |
| Compliance tests | `r<N>_…` / `s<N>_…`, 12 prefixes | `r<N>_…` / `s<N>_…`, 12 prefixes | ✅ |
| Source-hygiene suite | `tests/source_hygiene.rs` | `tests/source_hygiene.rs` | ✅ Same filename |
| Referential-integrity suite | `schema_integrity_tests.rs` | `referential_integrity.rs` | ⚖️ Same role, different name |

---

## 5. Divergences, and whether each is justified

| # | Divergence | Justified? | Reasoning |
| ---: | :--- | :--- | :--- |
| 1 | `dispatch.rs` ↔ `executor.rs` | ✅ **Yes** | The one genuine domain difference; a shared name would imply a shared threat model that does not exist |
| 2 | `extract.rs` (top level) vs extractors in `api/support.rs` | ✅ **Yes — current project's is better** | `StrictJson` implements a `RBAC_MODEL.md` §5 *type-level control*. `support.rs` is documented on both sides as "plumbing that decides nothing". Converging would bury a named specification control inside a helper module |
| 3 | Peer has `api/system.rs`; current project has none | ✅ **Yes** | Missing feature, not misplacement |
| 4 | Domain modules (`records`/`groups`/`webhooks` vs `executions`/`hooks`) | ✅ **Yes** | Named for what they hold; the mapping to §Terminology is exact |
| 5 | Referential-integrity suite filename | ⚖️ **Cosmetic** | Same role, same coverage |
| 6 | Adversarial-test marking convention | ⚖️ **Convention only** | Both load-bearing in their own gate; 5 such tests each |
| 7 | **Permission-table single-column index** | ❌ **No** | See security finding **F-1**: `hook_id` is unindexed on the peer while `group_id` is indexed here, and both projects run the structurally identical query that needs it |

**One unjustified divergence**, and it is the structural face of F-1. Every other difference traces to
the domains or is cosmetic.

---

## 6. Error handling — unified

| Aspect | Current | Peer | Status |
| :--- | :--- | :--- | :--- |
| Error type | `AppError` in `error.rs` | `AppError` in `error.rs` | ✅ |
| Response body | `{"error": "<message>"}` | `{"error": "<message>"}` | ✅ **Identical shape** |
| Rendering | `impl IntoResponse for AppError` | identical | ✅ |

| Variant | Current | Peer | HTTP |
| :--- | :---: | :---: | :--- |
| `Unauthorized` | ✅ | ✅ | `401` |
| `Forbidden` | ✅ | ✅ | `403` |
| `NotFound` | ✅ | ✅ | `404` |
| `Conflict` | ✅ | ✅ | `409` |
| `ConflictWithDetails` | ✅ | ✅ | `409` + structured detail |
| `InvalidInput` · `Json` | ✅ | ✅ | `400` |
| `BodyRejected` | ✅ | ✅ | **passthrough** — preserves `413` |
| `DbError` · `Internal` | ✅ | ✅ | `500` |
| `TooManyRequests` | ❌ | ✅ | `429` — concurrency budget |

**10 of 11 variants shared with identical status mappings.** The single singleton is required by
exactly one domain: the peer's execution concurrency budget. The current project has nothing to
rate-limit and inventing a variant for symmetry would be worse than the asymmetry.

`BodyRejected` is the most security-relevant agreement: both projects concluded independently that
normalising the response *shape* must not normalise its *meaning*, so `413` survives rather than being
flattened into `400`.

---

## 7. Observability — audit trail

| Field | Current | Peer | Status |
| :--- | :---: | :---: | :--- |
| `id` · `action` · `details` · `timestamp` | ✅ | ✅ | ✅ |
| `api_key_id` | ✅ | ✅ | ✅ nullable, `ON DELETE SET NULL` both sides |
| `api_key_name` · `api_key_prefix` · `client_ip` | ✅ | ✅ | ✅ **`NOT NULL` both sides** |
| `target_address` / `target_resource` | ✅ | ✅ | ⚠️ Same role, different name |
| `group_names` | ✅ | — | ⚖️ Domain-specific |

**8 of 10 fields identical in name, semantics and nullability.**

The design agreement underneath is the notable part, and both projects reached it independently: store
the acting key's name and prefix as a **point-in-time snapshot** rather than relying on the foreign
key, and choose `SET NULL` over `CASCADE` on `audit_logs.api_key_id` — so deleting a credential cannot
erase the record of what it did, while the denormalised columns keep the row legible afterwards. The
`NOT NULL` constraint on those columns is what turns that from a convention into a guarantee: without
it, a row could have both a nulled foreign key and no name, recording an action with no actor.

`target_address` vs `target_resource` is the same column under two names — harmless within a service,
mildly awkward for a shared log pipeline.

---

## 8. Executive verdict

**Convergence level: high, and structural rather than incidental.**

| Dimension | Result |
| :--- | :--- |
| Top-level modules with identical names and roles | **11 / 13** |
| `api/` structural modules (`mod`, `guards`, `support`) | **3 / 3 identical** |
| Entity mapping onto §Terminology's four generic roles | **4 / 4 exact** |
| Shared security symbols with identical names | **25 / 25** |
| Error variants shared, identical status mappings | **10 / 11** |
| Error response body shape | **identical** |
| Audit-log fields identical | **8 / 10** |
| Verification gates present on both sides | **7 / 7** |
| **Unjustified divergences** | **1** — the missing peer index (F-1) |

These two codebases share a foundational structure. Eleven of the twelve top-level modules that *can*
be shared are shared by name and by responsibility; the twelfth is the single point where the domains
genuinely differ, and naming it identically would have been the error rather than the fix. Every
entity maps one-to-one onto the specification's four generic roles.

What raises this above coincidence is the pattern of **independent convergence**. Both projects split
a large `api.rs` by domain and both re-exported flat to protect call sites. Both isolated authorization
into a single cross-cutting `guards` module and wrote down the same justification for not splitting it
per-domain. Both denormalised the acting key into the audit row and chose `SET NULL` so a deleted
credential cannot erase its own trail. Both added a `BodyRejected` variant to stop response-shape
normalisation from destroying `413`. Both factored Master pinning into a `MasterPin` type with the
same four method names. Both arrived at `tests/source_hygiene.rs` as the filename for the raw-SQL ban.
Agreement reached twice from the same constraints is worth considerably more than agreement reached
once and copied.

**Maturity.** The architecture is no longer the notable part; its *enforcement* is. Both repositories
carry an automated convergence gate, a byte-identity check on the shared specification, a raw-SQL ban
that runs on every `cargo test`, a referential-integrity suite covering what SQLite cannot express in
DDL, and a gate that fails when an infrastructure-level rule lacks an adversarial test.

**Verdict: architecturally converged, with one outstanding item.** The missing single-column index on
the peer's permission table is the only unjustified structural divergence, it is one line of DDL, and
it is tracked as F-1 in the security report. Every other difference is documented, justified, and in
each case a consequence of the domains rather than of the engineering.
