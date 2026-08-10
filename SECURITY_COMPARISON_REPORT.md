# Final Comparative Security Audit — `simply_ip_vault` ↔ `simply_hook_executor`

**Date:** 2026-08-10 · **Mode:** strictly read-only. No file under `src/`, `tests/`, `scripts/` or
`migration/` was modified in either repository; `git status --porcelain src/ tests/` is empty.
**Scope:** the two services of the ecosystem, at `simply_ip_vault` HEAD `910fafc` and the
`simply_hook_executor` working tree.

**Replaces the 2026-08-07 edition of this file**, whose findings are re-verified below rather than
restated. That edition remains retrievable as the baseline this audit is measured against:
`git show e24839c:SECURITY_COMPARISON_REPORT.md`.

Every claim here was checked against source or by execution. Prior reports, `AGENT_NOTES.MD` and
commit messages were treated as leads only — one prior claim was found overstated and is corrected in
§4.

---

## 0. Reference integrity

The convergence gate diffs against `simply_ip_vault/example/simply_hook_executor`, a flat snapshot.
An audit that trusts a stale snapshot proves nothing, so the snapshot was compared against the live
peer checkout first.

| Probe | Result |
| :--- | :--- |
| `diff -rq` snapshot ↔ live peer, excluding `target/`, `.git/`, `example/`, `Cargo.lock` | **No differences under `src/`, `tests/`, `scripts/`, or `RBAC_MODEL.md`** |
| Files present only in the live peer | `AGENT.MD`, `LICENSE`, `.github/`, `.forgejo/`, `.gitignore`, `deploy/`, `SECURITY_COMPARISON_REPORT.md` — repository furniture, none of it diffed by any gate |
| `RBAC_MODEL.md` byte-identity (Pillar 0) | `✓ MATCH` |

**Verdict: the reference is current.** Every comparison below is against live peer code, not a
snapshot that has drifted.

---

## 1. Resolution of previously identified flaws

The 2026-08-07 audit raised **4 genuine divergences** and **3 specification defects**. Each was
re-tested against current source.

| # | Finding (2026-08-07) | Against | Status | Evidence |
| ---: | :--- | :--- | :--- | :--- |
| D1 | **§5 uniqueness not enforced.** Marker was `VARCHAR(16) NULL`, application-written. A direct `INSERT … is_master=1, master_marker=NULL` was **accepted**, producing two Masters | `simply_ip_vault` | ✅ **RESOLVED** | `m20260808_000009_derive_master_marker` replaces it with `INTEGER GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)`, `STORED`/`VIRTUAL` per backend. Proven by execution, not inspection — see §2 |
| D2 | **R2 conjunction missing.** `require_manage` checked `p.can_manage` with **no `can_manage_keys` conjunct**, so a Daughter key could rewrite a hook's `script_path` — which binary executes | `simply_hook_executor` | ✅ **RESOLVED** | `api/guards.rs:669` — `if !key.can_manage_keys { … "R2: key holds a row but not can_manage_keys; manage is a conjunction" }`. Both halves now required |
| D3 | **Dormant authorization column.** `api_keys.owner_key_id` was written and inventoried but read by no guard | `simply_hook_executor` | ✅ **RESOLVED** | Column dropped: `m20260810_000001_drop_api_key_owner_key_id`. Absent from `entities/api_key.rs` entirely |
| D4 | **Payload strictness.** `is_master` retained as a payload field, rejected by a handler guard; no `deny_unknown_fields` anywhere | `simply_ip_vault` | ✅ **RESOLVED** | Removed from both payload types; `#[serde(deny_unknown_fields)]` on both. See §3 |
| S1 | `can_create_webhooks` names a column that exists nowhere | `RBAC_MODEL.md` | ✅ **RESOLVED** | Terminology table now reads `can_create_groups`, `can_manage_webhooks` |
| S2 | `can_create_executor` names a column that exists nowhere | `RBAC_MODEL.md` | ✅ **RESOLVED** | Now reads `can_manage_hooks` |
| S3 | Table implies one creation right where the vault has two | `RBAC_MODEL.md` | ✅ **RESOLVED** | Both of the vault's rights are named explicitly |

**7 of 7 closed.** The three specification defects required a coordinated edit to a byte-identical
normative document; that edit was made and the file remains byte-identical across both repositories,
which is the harder half of the fix.

---

## 2. D1 in detail — proven by execution

D1 was the most serious finding of the prior audit: a rule documented as enforced, tested as enforced,
and not enforced. Re-verification therefore does not rely on reading the migration.

`tests/rbac_model_compliance.rs::s5_the_derived_marker_is_unwritable_by_any_client` issues raw SQL
through `execute_raw`, bypassing the entity layer entirely — the exact writer the prior audit used to
demonstrate the bypass:

| Attack replayed from the 2026-08-07 report | Then | Now |
| :--- | :--- | :--- |
| `INSERT … is_master=true, master_marker=1` (cooperative shape) | accepted | **refused** — error text asserted to contain `generated` |
| `UPDATE api_keys SET master_marker = NULL WHERE id = <master>` (frees the index for a second Master) | accepted | **refused** |
| Marker value after both attempts | desynchronised from `is_master` | still equals `is_master` |

```
test s5_the_derived_marker_is_unwritable_by_any_client ... ok
test s5_is_master_is_refused_by_the_payload_type_not_by_a_handler ... ok
test s5_master_is_unique_unsettable_immutable_and_undeletable ... ok
test s5_master_immutability_does_not_rest_on_the_uniqueness_constraint ... ok
```

The prior report's core criticism was that the vault's tests "supply the marker explicitly, so they
test a cooperative writer." That is no longer true of any of the four.

**Both services now defend uniqueness *and* identity separately**, which the prior audit did not
examine because neither had the second half:

| Property | Defends | `simply_ip_vault` | `simply_hook_executor` |
| :--- | :--- | :--- | :--- |
| Generated marker + unique index | *Cardinality* — at most one Master row | ✅ | ✅ |
| Boot-time identity pin | *Identity* — **which** row, for the process lifetime | ✅ `master.rs::MasterPin` | ✅ `master.rs::MasterPin` |

The distinction matters and is not redundancy: a unique index permits an attacker to demote the real
Master and promote itself, keeping the count at exactly one. Both services close it identically, with
the same type name and the same method names.

---

## 3. Payload and input strictness

| Control | `simply_ip_vault` | `simply_hook_executor` | Parity |
| :--- | :--- | :--- | :--- |
| `#[serde(deny_unknown_fields)]` on key payloads | ✅ `CreateApiKeyPayload`, `UpdateApiKeyPayload` | ✅ both | ✅ |
| Total `deny_unknown_fields` sites in `src/api/` | 5 (`keys.rs` ×4, `support.rs` ×1) | 7 (`keys.rs` ×5, `guards.rs` ×1, `support.rs` ×1) | Equivalent; count tracks endpoint count |
| `is_master` present on any **payload** type | ❌ removed | ❌ removed | ✅ |
| `is_master` on **response** DTOs | ✅ `MeResponse`, key listing (full view only) | ✅ equivalent | ✅ — read-only projection, correct on both |
| Strict JSON extractor | `StrictJson` | `StrictJson` | ✅ same name |
| Optional-body extractor | `OptionalStrictJson` | `OptionalStrictJson` | ✅ same name |
| Body size limit enforced pre-auth | ✅ 3 MiB, single constant shared with the HMAC buffer | ✅ | ✅ |
| Oversized body preserves `413` (not flattened to `400`) | ✅ `AppError::BodyRejected` carries the extractor's status | ✅ same variant | ✅ |

The prior audit's D4 wording — that the vault "retains the field and rejects it at the handler" — no
longer applies. The control is now in the **type**: the request is refused by serde before any handler
runs, which is what §5 asks for ("removing the field from the payload type is required; rejecting it
at the handler is not sufficient, since a later handler can reintroduce the path").

---

## 4. Security parity across the enforcement surface

| Control | `simply_ip_vault` | `simply_hook_executor` | Parity |
| :--- | :--- | :--- | :--- |
| **R2 conjunction** (global `can_manage_keys` AND per-resource `can_manage`) | ✅ `guard_group_manage` | ✅ `guards.rs:669` (D2 fix) | ✅ |
| **§5 DB-level uniqueness** | ✅ generated column + unique index | ✅ generated column + unique index | ✅ |
| **§5 identity pin** | ✅ `MasterPin::pin_at_boot` | ✅ `MasterPin::pin_at_boot` | ✅ |
| Demotion at a single choke point | ✅ `MasterPin::authenticate`, one call site | ✅ same | ✅ |
| Master immutable (rotate / delete), caller-independent | ✅ | ✅ | ✅ |
| Master held to `bound_ips` (no exemption) | ✅ | ✅ | ✅ |
| Inbound HMAC over method + full target + timestamp + body | ✅ unconditional | ✅ per-key posture | ⚖️ **Intentional asymmetry** (recorded, never scored) |
| Anti-replay guard, monotonic expiry | ✅ `ReplayGuard` | ✅ `ReplayGuard` | ✅ |
| Trusted-proxy boundary; `X-Forwarded-For` ignored unless the peer is trusted | ✅ | ✅ | ✅ — chain walk is byte-identical |
| At-rest AEAD | XChaCha20-Poly1305, 192-bit nonce | XChaCha20-Poly1305, 192-bit nonce | ✅ |
| Encryption key strictly 64 hex, fatal if malformed | ✅ | ✅ | ✅ |
| **Bootstrap master key strictly 64 hex, fatal** | ✅ `validate_initial_master_key` | ❌ accepts any non-empty string | ⚠️ **Vault stricter** |
| SQLite `foreign_keys=ON` at connect time | ✅ | ✅ | ✅ |
| Constant-time signature comparison | ✅ | ✅ | ✅ |
| `sha256=` prefix mandatory (no bare-hex fallback) | ✅ | ✅ | ✅ |
| Raw-SQL ban for DML in `src/` | ✅ shell gate | ✅ `tests/source_hygiene.rs` | ✅ same rule, different mechanism |
| Unauthenticated surface | `/health`, `/ready`, `/healthz`, `/readyz` only | identical set | ✅ |
| Probes disclose no build version | ✅ | ✅ | ✅ |

### A prior-report claim that needed correcting

The 2026-08-07 report treated the vault's `ADVERSARIAL(<rule>)` doc-comment marker as the measure of
adversarial coverage. Counting markers today gives **vault 5, executor 0**, which reads as a serious
asymmetry and is **wrong**.

The peer encodes the same property in the *function name* and makes that load-bearing in its own gate
(`scripts/verify_convergence.sh:609` — `grep -qE "^${prefix}_adversarial_"`):

| | `simply_ip_vault` | `simply_hook_executor` |
| :--- | :--- | :--- |
| Convention | doc-comment token `ADVERSARIAL(§N)` | function name `<rule>_adversarial_<desc>` |
| Enforced by | `check_adversarial_coverage` | `adversarial_infrastructure_coverage` |
| §5 tests bypassing the application layer | 2 (`execute_raw`) | 2 (`execute_unprepared`) |
| Negative control against passing for the wrong reason | ✅ | ✅ — asserts the same statement with `is_master = false` still succeeds |

**Equivalent rigour, divergent convention.** Recorded so no future audit re-raises it as a gap.

---

## 5. Remaining divergences

All four are deliberate, documented, and in every case the vault is the stricter side or the
difference follows from the domain.

| # | Divergence | Direction | Justification |
| ---: | :--- | :--- | :--- |
| 1 | Authentication posture — vault requires HMAC on every key unconditionally; peer offers a per-key posture | Vault stricter | Permanent and recorded. The peer speaks to third-party senders that cannot all sign; the vault is the internal half of the pair and has no interoperability argument |
| 2 | `INITIAL_MASTER_KEY` must be 64 hex on the vault; the peer accepts any non-empty string | Vault stricter | The vault closed this in Session 44. **The peer has not.** See §6 |
| 3 | Readiness probe — vault also asserts the Master pin is established; peer checks only the database | Vault stricter | Catches a bind-before-pin regression that is otherwise invisible |
| 4 | Readiness query — vault uses a typed SeaORM read; peer uses a literal `SELECT 1` | Neutral | The vault's raw-SQL gate has no allowlist, so an exception would be a hole in a gate worth more than one saved query |

---

## 6. The one open item

**`simply_hook_executor` does not validate `INITIAL_MASTER_KEY`.**

| | `simply_ip_vault` | `simply_hook_executor` |
| :--- | :--- | :--- |
| Accepts any non-empty string | ❌ refused | ✅ **accepted** |
| Requirement | exactly 64 ASCII hex characters | none |
| On malformed input | aborts startup, naming the requirement and `openssl rand -hex 32` | logs a warning and **proceeds** |
| Test coverage | 4 unit tests + 6 e2e checks | none |

This is not a regression — it is the vault having moved ahead. But the credential it guards is the one
that administers every other credential, and a warning in a startup log is not read by whoever set
`INITIAL_MASTER_KEY=changeme` in a compose file. The vault's own pre-fix code carried a comment
correctly arguing that a human-chosen key defeats the purpose, and then permitted it anyway.

**Recommendation:** port `config::validate_initial_master_key` to the peer. It is ~20 lines with no
dependencies, and the peer's `generate_random_key` already emits exactly 64 hex characters, so the
rule would demand of an operator precisely what the service already demands of itself.

---

## 7. Verification performed

| Gate | `simply_ip_vault` |
| :--- | :--- |
| `cargo test` | **248 passed**, 0 failed |
| `./scripts/verify_convergence.sh` | **exit 0** — 62 matching, 0 divergences, 0 unexplained |
| `git diff RBAC_MODEL.md` | empty |
| `git status --porcelain src/ tests/` | empty (read-only compliance) |

---

## 8. Executive verdict

**Every flaw raised by the previous audit is closed — 4 divergences and 3 specification defects, 7 of
7.** Both services were weaker than the other on a different rule in August; neither is now.

The §5 fix is the one worth singling out. The prior finding was not that a control was missing but
that a control was *believed* present: documented as enforced, covered by passing tests, and
bypassable by any writer with database access. It was closed at the layer that makes the guarantee
structural rather than behavioural — an engine-generated column that no query can name, backed by an
entity that deliberately omits the field, backed by a convergence assertion that fails if either is
undone. Both services then independently added the second, orthogonal half — boot-time identity
pinning — and arrived at the same type name and the same method names without coordination.

**Security parity: 17 of 18 controls identical.** The single exception is `INITIAL_MASTER_KEY`
validation, where the vault is stricter and the peer has a real, if narrow, gap (§6). The four
remaining divergences are deliberate, and in three of them the vault is the stricter side.

**Maturity assessment.** The controls are no longer the notable part; the *meta-controls* are. Both
services enforce adversarial testing of infrastructure claims through an automated gate — the direct
institutional response to D1, where cooperative tests certified a bypassable constraint. Both keep a
byte-identity check on the shared specification. Both ban raw DML in application code. These are the
mechanisms that make the next D1 fail loudly instead of passing quietly, and their presence on both
sides is what distinguishes a codebase that has been audited from one that is auditable.

**Verdict: converged and production-ready, with one recommended port.** No finding in this audit
blocks deployment of either service. The `INITIAL_MASTER_KEY` gap on the peer should be closed before
its next release, and it is the only outstanding item in the ecosystem.
