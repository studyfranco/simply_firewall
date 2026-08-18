# Structural and Formal Convergence Report

**Subject:** `simply_ip_vault` (current project) compared against the three peer services vendored in `example/`.
**Method:** Clean-room structural analysis of current sources only.
**Date:** 2026-08-18

| Project | Commit |
| :--- | :--- |
| `simply_ip_vault` | `14c8fa3` |
| `example/simply_hook_executor` | `15b8af6` |
| `example/simply_ip_exporter` | `80a3b31` |
| `example/simply_ip_sync` | `72cce13` |

## 1. Module Topology

### 1.1 Core modules — presence matrix

| `src/` module | Vault | Executor | Exporter | Sync | Role |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `lib.rs` | ✅ | ✅ | ✅ | ✅ | Router assembly, public surface |
| `main.rs` | ✅ | ✅ | ✅ | ✅ | Boot sequence only |
| `config.rs` | ✅ | ✅ | ✅ | ✅ | Environment reads, client-IP resolution |
| `crypto.rs` | ✅ | ✅ | ✅ | ✅ | Signing + secrets at rest |
| `db.rs` | ✅ | ✅ | ✅ | ✅ | Pool, pragmas, migrations |
| `error.rs` | ✅ | ✅ | ✅ | ✅ | `AppError` → HTTP mapping |
| `extract.rs` | ✅ | ✅ | ✅ | ✅ | Strict request extractors |
| `master.rs` | ✅ | ✅ | ✅ | ✅ | Boot-time Master identity pin |
| `middleware.rs` | ✅ | ✅ | ✅ | ✅ | Authenticate → authorize ordering |
| `replay.rs` | ✅ | ✅ | ✅ | ✅ | Single-use signature ledger |
| `state.rs` | ✅ | ✅ | ✅ | ✅ | Shared `AppState` |
| `retention.rs` | ✅ | ✅ | ❌ | ❌ | Background expiry worker |
| `entities/` | ✅ | ✅ | ✅ | ✅ | SeaORM models |
| `migration/` | ✅ | ✅ | ✅ | ✅ | Versioned DDL |
| `api/` | ✅ | ✅ | ✅ | ✅ | Handler modules |
| `api/guards.rs` | ✅ | ✅ | ❌ | ✅ | Centralised permission decisions |

**Eleven core modules are present under identical names in all four services.** The foundational DNA is
unambiguously shared: any engineer who can navigate one of these repositories can navigate the others.

### 1.2 Domain-specific modules

| Vault | Executor | Exporter | Sync |
| :--- | :--- | :--- | :--- |
| `dispatch.rs` (outbound webhooks) | `executor.rs` (process execution) | `feed.rs`, `cache.rs`, `ratelimit.rs`, `ipfilter.rs`, `sync.rs`, `vault_client.rs` | `client.rs`, `scheduler.rs`, `retry.rs`, `jobs/`, `parsers/` |

Each service adds exactly the modules its domain requires and no more. The divergence here is expected
and correct — it is the *core* set above that must converge, not the domain set.

### 1.3 `api/` submodule comparison

| Vault | Executor | Exporter | Sync | Shared concern |
| :--- | :--- | :--- | :--- | :--- |
| `audit.rs` | `audit.rs` | `audit.rs` | `audit.rs` | Audit log endpoint |
| `health.rs` | `health.rs` | `health.rs` | `health.rs` | Liveness/readiness |
| `keys.rs` | `keys.rs` | `keys.rs` | `keys.rs` | Key lifecycle |
| `support.rs` | `support.rs` | `support.rs` | `support.rs` | Shared handler plumbing |
| `guards.rs` | `guards.rs` | — | `guards.rs` | Permission decisions |
| `mod.rs` | `mod.rs` | `mod.rs` | `mod.rs` | Re-export surface |
| `groups.rs`, `records.rs`, `webhooks.rs` | `hooks.rs`, `executions.rs`, `system.rs` | `endpoints.rs`, `auth.rs` | `sources.rs`, `vaults.rs`, `sync_tasks.rs`, `sync_logs.rs` | Domain resources |

Six `api/` files carry the same name and the same responsibility across the ecosystem;
`simply_ip_exporter` is the sole service missing `guards.rs`.

## 2. Naming Conventions

| Convention | Vault | Executor | Exporter | Sync | Uniform? |
| :--- | :--- | :--- | :--- | :--- | :---: |
| Error enum | `AppError` | `AppError` | `AppError` | `AppError` | ✅ |
| Shared state | `AppState` | `AppState` | `AppState` | `AppState` | ✅ |
| Strict body extractor | `StrictJson` | `StrictJson` | `StrictJson` | `StrictJson` | ✅ |
| Strict path extractor | `StrictPath` | `StrictPath` | `StrictPath` | `StrictPath` | ✅ |
| Master pin type | `MasterPin` | `MasterPin` | `MasterPin` | `MasterPin` | ✅ |
| Replay ledger | `ReplayGuard` | `ReplayGuard` | `ReplayGuard` | `ReplayGuard` | ✅ |
| Secret cipher | `SecretCipher` | `SecretCipher` | `SecretCipher` | `SecretCipher` | ✅ |
| Guard function prefix | `guard_*` | `guard_*` | *(inline)* | `guard_*` | ⚠️ |
| Payload type suffix | `*Payload` | `*Payload` | `*Payload` | `*Payload` | ✅ |
| Key digest helper | `hash_key` | `hash_key` | `hash_key` | `hash_key` | ✅ |
| Key prefix helper | `key_prefix` | `key_prefix` | `key_prefix` | `key_prefix` | ✅ |
| Signature scheme const | `CANONICAL_V1` | `CANONICAL_V1` | `CANONICAL_V1` | `CANONICAL_V1` | ✅ |
| Audit writer | `create_audit_log` | `create_audit_log` | `create_audit_log` | `create_audit_log` | ✅ |

**Naming is standardised to an unusual degree.** Twelve of thirteen tracked identifiers are spelled
identically across four independently maintained repositories.

### 2.1 Index naming

| Project | Convention | Consistent internally? |
| :--- | :--- | :---: |
| `simply_ip_vault` | `idx-<table>-<column>` | ⚠️ two legacy `idx_ip_records_*` underscore names remain |
| `simply_hook_executor` | `idx_<table>_<column>` | ✅ |
| `simply_ip_exporter` | `idx_<table>_<column>` | ✅ |
| `simply_ip_sync` | `idx-<table>-<column>` | ✅ |

The ecosystem is split two-and-two between hyphen and underscore index naming, and the vault contains
two stragglers in the minority style. Cosmetic, but it defeats naive cross-repo index audits — a fact
this audit confirmed the hard way.

## 3. Error Handling

| Property | Vault | Executor | Exporter | Sync |
| :--- | :--- | :--- | :--- | :--- |
| Envelope | `{"error": "…"}` | `{"error": "…"}` | `{"error": "…"}` | `{"error": "…"}` |
| `AppError` variants | 10 | 11 | 9 | 9 |
| `NotFound` → 404 | ✅ | ✅ | ✅ | ✅ |
| `Forbidden` → 403 | ✅ | ✅ | ✅ | ✅ |
| `Unauthorized` → 401 | ✅ | ✅ | ✅ | ✅ |
| `InvalidInput` → 400 | ✅ | ✅ | ✅ | ✅ |
| Internal errors redacted | ✅ | ✅ | ✅ | ✅ |
| Structured conflict detail | ✅ | ✅ | ❌ | ✅ |
| Envelope total across `Path`/`Query` rejections | ✅ | ✅ | ⚠️ path only | ✅ |

The envelope shape is unified. Three services additionally guarantee the envelope holds for axum's
built-in extractor rejections, which by default emit **plain text** rather than JSON;
`simply_ip_exporter` covers `Path` but not `Query`.

## 4. Observability and Audit

| Column | Vault | Executor | Exporter | Sync |
| :--- | :---: | :---: | :---: | :---: |
| `id` | ✅ | ✅ | ✅ | ✅ |
| `api_key_id` | ✅ | ✅ | ✅ | ✅ |
| `api_key_name` | ✅ | ✅ | ✅ | ✅ |
| `api_key_prefix` | ✅ | ✅ | ✅ | ✅ |
| `client_ip` | ✅ | ✅ | ✅ | ✅ |
| `action` | ✅ | ✅ | ✅ | ✅ |
| target column | `target_address` | `target_resource` | `target_resource` | `target_resource` |
| `group_names` | ✅ | — | — | — |
| `details` | ✅ | ✅ | ✅ | ✅ |
| `timestamp` | ✅ | ✅ | ✅ | ✅ |

**The audit schema is unified in eight of nine columns.** The vault diverges by naming its target column
`target_address` and adding `group_names` — both justified by its domain, in which the audited subject is
an IP address that may belong to several groups. A consumer writing a cross-service audit reader must
special-case the vault on exactly one field name.

## 5. Structural Divergence Summary

| Divergence | Services affected | Justified? | Rationale |
| :--- | :--- | :---: | :--- |
| `retention.rs` absent | Exporter, Sync | ✅ | Neither owns soft-deleted data requiring expiry |
| Domain modules differ | All | ✅ | Each service's actual problem domain |
| `guards.rs` absent | Exporter | ❌ | Ownership-only model still merits one decision site |
| `StrictQuery` absent | Exporter | ❌ | Leaves a plain-text rejection path |
| `target_address` / `group_names` | Vault | ✅ | Domain-appropriate audit subject |
| Index naming split | All | ⚠️ | Cosmetic; impedes cross-repo tooling |
| Skew constant vs configurable | Vault, Sync fixed | ⚠️ | Same 300 s value; differing operability |
| Adapted vs verbatim `RBAC_MODEL.md` | Sync adapted; Exporter verbatim | ⚠️ | See security report F-3 |

## 6. Executive Verdict

**These four services share a genuine, deliberate, and verifiable common architecture.** Eleven core
modules appear under identical names with identical responsibilities in every repository. Twelve of
thirteen tracked security identifiers are spelled the same. The error envelope, the HTTP status mapping,
and eight of nine audit columns are unified. This is not incidental resemblance between services built by
the same team — it is enforced convergence, and it holds.

**`simply_ip_vault` is the ecosystem's structural reference implementation.** It carries the complete
core module set, the most thorough index coverage, the largest test suite, and the only migration that
structurally forbids unattributed audit rows. Where it diverges — the audit target column, two legacy
index names — the divergence is either domain-justified or cosmetic.

**`simply_hook_executor` and `simply_ip_sync` are fully converged peers.** Both carry the complete core
set including `guards.rs`, both wrap all three extractor families, and `simply_ip_sync` additionally
demonstrates the correct pattern for domain-adapting the normative specification without diluting it.

**`simply_ip_exporter` is structurally converged but incompletely so.** It has every core module except
`guards.rs`, and its authorization decisions are consequently scattered across handler bodies rather than
concentrated in one auditable site. Combined with its missing `StrictQuery` and the payload-strictness
finding in the security report, the pattern is consistent: the exporter adopted the ecosystem's
*structure* faithfully but not all of its *disciplines*.

**Convergence level:**

| Pairing | Structural convergence |
| :--- | :--- |
| Vault ↔ Executor | **Full** |
| Vault ↔ Sync | **Full** |
| Vault ↔ Exporter | **Partial** — core structure shared, three disciplines unadopted |
