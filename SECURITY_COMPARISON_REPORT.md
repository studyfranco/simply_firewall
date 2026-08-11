# Independent Security Audit — `simply_ip_vault` ↔ `simply_hook_executor`

**Date:** 2026-08-11 · **Mode:** strictly read-only. No file under `src/`, `tests/`, `scripts/` or
`migration/` was modified in either project.

**Scope.** The **current project** — this repository — against its **peer**, read exclusively from
`example/simply_hook_executor` at `4865a82`.

**Methodology: clean-room.** This audit was conducted without reading any prior audit report. Every
finding below was derived from two sources only: the normative text of `RBAC_MODEL.md`, and the
current `.rs` source of both projects. Rules were enumerated from the specification first, then each
was traced to its enforcement site in both codebases. Where this audit reaches the same conclusion a
previous one did, that is convergence rather than citation.

---

## 0. Reference state

| Probe | Result |
| :--- | :--- |
| `git pull` in `example/simply_hook_executor` | **Already up to date** at `4865a82` |
| Peer working tree | clean — 0 modified files |
| `RBAC_MODEL.md` byte-identity | **identical**, `md5 cb0b76abd6c00f28af9bee951f804f7b` |
| Current project gates | `cargo test` 260 passed · `verify_convergence.sh` exit 0 |

---

## 1. Findings

Two findings. Neither is an authorization bypass; one is a specification-conformance gap and the other
is a gap in the specification itself.

| ID | Finding | Against | Class | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **F-1** | Permission-table join column `hook_id` is not indexed, while an authenticated hot path filters on it alone | **Peer** | §7 conformance | **Low** |
| **F-2** | Deleting resource data shared across several managed resources is authorised by rights on **any one** of them | **Current** | Specification gap | **Low–Moderate** |

### F-1 — `api_key_hook_permissions.hook_id` is unindexed (peer)

`RBAC_MODEL.md` §7 requires *"Indexes on `parent_key_id`, `owner_key_id`, the key-hash lookup column,
and **the permission-table join columns** — every column the authenticated hot paths search on."*

The peer indexes the permission table only as a composite:

| Index | Columns | Serves |
| :--- | :--- | :--- |
| `idx-akhp-api_key_id-hook_id` | `(api_key_id, hook_id)` | filters on `api_key_id`, or on both |
| *(none)* | `hook_id` | — |

A composite index cannot serve a predicate on its non-leading column. And there is such a predicate,
on the §4 shared-resource visibility path:

```rust
// example/simply_hook_executor/src/api/keys.rs:577
ApiKeyHookPermission::find()
    .filter(api_key_hook_permission::Column::HookId.is_in(managed.clone()))
    .all(&state.db)
```

`list_api_keys` therefore performs a **full scan of the permission table** for any non-Master caller
that manages at least one hook. The table grows as *keys × hooks*.

The current project has the structurally identical query — `src/api/keys.rs:570`, filtering
`GroupId.is_in(managed_groups)` — and does index the column:

| Project | Composite index | Single-column index | Query at risk | Scan? |
| :--- | :--- | :--- | :--- | :--- |
| Current | `idx-akgp-api_key_id-group_id` | ✅ `idx-akgp-group_id` | `keys.rs:570` | No |
| Peer | `idx-akhp-api_key_id-hook_id` | ❌ **absent** | `keys.rs:577` | **Yes** |

**Assessment.** Not an authorization defect — the query returns correct results. It is a
§7 conformance gap with availability consequences: an authenticated parent key can force an unbounded
table scan on every key listing. **Remedy:** one index on `api_key_hook_permissions.hook_id`,
mirroring `idx-akgp-group_id`.

### F-2 — Cross-resource deletion of shared resource data (current project)

`ip_records.target_address` is globally `unique_key()`, so a single record is *shared* by every group
that references it, and `is_deleted` is a column on the **record**, not on the membership. A soft
delete is therefore global across all groups holding it.

Authorization requires delete rights on **any one** of those groups:

```rust
// src/api/records.rs:574  caller_may_delete_record
let group_ids = /* every group holding this record */;
let deletable = api_key_group_permission::Entity::find()
    .filter(/* … */ GroupId.is_in(group_ids) /* … can_delete */);
```

The consequence: a record in groups **A** and **B** can be removed from *both* by a caller holding
`can_delete` on **A** alone — a key with no rights over **B** changes what **B** contains.

**Is this a violation?** No — and the reason is the finding. The specification does not govern it:

| Spec section | Governs | Covers this? |
| :--- | :--- | :--- |
| §3 Lifecycle | deleting/renaming *managed resources* and *creator-private entities* | ❌ resource data is neither |
| R2 Conjunction | actions authorised by `can_manage` | ❌ this is the operational verb `can_delete` |
| §6 Cascade | data destroyed as a side effect of *key* deletion | ❌ different trigger |
| §4 Visibility | what a caller may *see* | ❌ this is a mutation |

So the implementation is conformant, and the gap is in `RBAC_MODEL.md`. It is worth closing because
§4 already articulates the principle by analogy — *"A single shared resource must never become a
keyhole into another parent's whole configuration"* — and F-2 is the mutation-side counterpart of
exactly that concern.

**No analogue exists on the peer.** `hook_parameter.hook_id` is a single foreign key, so resource data
there belongs to exactly one managed resource and cannot span an authorization boundary. This is a
consequence of the two entity models, not of engineering quality.

**Suggested remedies**, in increasing cost: state the rule explicitly in the specification; or require
delete rights on *every* group holding the record; or scope the soft delete to the membership rather
than the record.

---

## 2. Rule-by-rule enforcement

Each rule traced from the specification text to its enforcement site in both codebases.

| Rule | Requirement | Current | Peer |
| :--- | :--- | :--- | :--- |
| **R1** Non-amplification | A caller may grant only rights it holds | ✅ `guard_delegated_group_grant` | ✅ `guard_delegated_hook_grant` |
| **R2** Manage is a conjunction | Global `can_manage_keys` **AND** a `can_manage` row | ✅ `guard_group_manage` | ✅ `guard_hook_manage_conjunction` |
| **R3** Parentage confers no authority | Rights never derived from lineage | ✅ no read of `parent_key_id` in any guard | ✅ same |
| **R4** Only Master creates parents | Only Master grants `can_manage_keys` / creation rights | ✅ `guard_scope_elevation`, `MASTER_ONLY_SCOPES` | ✅ equivalent |
| **R5** Manage propagates sideways | Bounded by R1 and R2; never elevates a daughter | ✅ | ✅ |
| **R6** Revocation is never escalation | Reduction via a general update endpoint is revocation | ✅ `widens_permissions` distinguishes the directions | ✅ equivalent |
| **R7** Granting bounded by R1 **and** R2 | Simultaneously | ✅ | ✅ |
| **§3** Lifecycle | Delete/rename restricted to Master and `owner_key_id` | ✅ `guard_resource_lifecycle` | ✅ equivalent |
| **§4** Visibility & oracle | Out-of-scope is byte-identical to nonexistent | ✅ `find_administrable_key` → `NotFound` for both absent and out-of-subtree | ✅ 3 `NotFound` sites in `guards.rs` |
| **§5** Master guarantees | See §3 of this report | ✅ | ✅ |
| **§6** Cascade & inventory | Refuse, enumerate, require full resolution map | ✅ `delete_api_key` | ✅ equivalent |
| **§7** Constraints & indexing | See F-1 | ✅ | ⚠️ **F-1** |

---

## 3. §5 Master key guarantees — the most constrained section

§5 makes seven separately checkable demands. Each was verified against source on both sides.

| §5 demand | Current | Peer |
| :--- | :--- | :--- |
| Exactly one Master, by database constraint | ✅ unique index over derived marker | ✅ |
| Marker **derived by the engine** from `is_master` | ✅ `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` | ✅ |
| Marker **not writable** — absent from every entity, bootstrap, fixture and test helper | ✅ **0** occurrences of a settable marker anywhere in `src/` or `tests/`; `api_key::Model` omits the field | ✅ **0** |
| Storage mode pinned by test (Postgres `STORED`, SQLite `VIRTUAL`) | ✅ | ✅ |
| An **adversarial** test — direct insert with the marker absent or NULL | ✅ 5 adversarial tests | ✅ 5 adversarial tests |
| `is_master` not settable through any endpoint; removed from the payload **type** | ✅ present only on `MeResponse` / `ApiKeySummary`, both `Serialize` | ✅ identical placement |
| Master immutable except its own `bound_ips`; rotation refused for all; undeletable independently of the uniqueness constraint | ✅ | ✅ |

The "removed from the payload type" requirement is met structurally on both sides: the payload types
carry `#[serde(deny_unknown_fields)]`, so the request is refused by serde before a handler runs. The
specification is explicit that a handler-level check would not suffice, and neither project relies on
one.

---

## 4. Security parity

| Control | Current | Peer | Parity |
| :--- | :--- | :--- | :--- |
| §5 uniqueness — engine-generated marker + unique index | ✅ | ✅ | ✅ |
| §5 identity — boot-time pin (`MasterPin`) | ✅ | ✅ | ✅ |
| Demotion at a single choke point (`MasterPin::authenticate`) | ✅ | ✅ | ✅ |
| R2 conjunction | ✅ | ✅ | ✅ |
| Master held to `bound_ips` — no exemption | ✅ | ✅ | ✅ |
| Anti-replay guard, monotonic expiry | ✅ `ReplayGuard` | ✅ `ReplayGuard` | ✅ |
| Trusted-proxy boundary on forwarding headers | ✅ | ✅ | ✅ |
| At-rest AEAD — XChaCha20-Poly1305, 192-bit nonce | ✅ | ✅ | ✅ |
| Encryption key strictly 64 hex, fatal | ✅ | ✅ | ✅ |
| Bootstrap master key strictly 64 hex, fatal | ✅ `validate_initial_master_key` | ✅ `validate_initial_master_key` | ✅ |
| Constant-time signature comparison | ✅ | ✅ | ✅ |
| `sha256=` prefix mandatory | ✅ | ✅ | ✅ |
| SQLite `foreign_keys=ON` at connect time | ✅ | ✅ | ✅ |
| Raw-SQL / DML ban in `src/`, at `cargo test` | ✅ `tests/source_hygiene.rs` | ✅ `tests/source_hygiene.rs` | ✅ |
| Audit attribution `NOT NULL` | ✅ | ✅ | ✅ |
| Audit FK `ON DELETE SET NULL` | ✅ | ✅ | ✅ |
| Unauthenticated surface — probes only | ✅ | ✅ | ✅ |
| §7 permission-table join columns indexed | ✅ | ⚠️ **F-1** | ⚠️ |
| Inbound HMAC posture | unconditional | per-key configurable | ⚖️ Intentional |

**17 of 19 controls identical.** One difference is the deliberate authentication-posture asymmetry;
the other is F-1.

---

## 5. Payload and input strictness

| Control | Current | Peer | Parity |
| :--- | :--- | :--- | :--- |
| `deny_unknown_fields` on both key payload types | ✅ | ✅ | ✅ |
| Total sites in `src/api/` | 5 | 7 | Tracks endpoint count |
| `is_master` on any **payload** type | ❌ 0 | ❌ 0 | ✅ |
| `is_master` on **response** DTOs only | ✅ `MeResponse`, `ApiKeySummary` (both `Serialize`) | ✅ identical | ✅ |
| Strict JSON extractor | `StrictJson` | `StrictJson` | ✅ |
| Optional-body extractor | `OptionalStrictJson` | `OptionalStrictJson` | ✅ |
| Oversized body preserves `413` | ✅ `AppError::BodyRejected` | ✅ same variant | ✅ |
| Body limit applied pre-auth | ✅ 3 MiB, shared with the HMAC buffer | ✅ | ✅ |

`BodyRejected` is worth naming: both projects independently concluded that normalising the response
*shape* must not normalise its *meaning*, so an oversized body still answers `413` rather than being
flattened into `400`.

---

## 6. Verification discipline

The controls matter less than the machinery that keeps them honest.

| Mechanism | Current | Peer |
| :--- | :--- | :--- |
| `RBAC_MODEL.md` byte-identity gate | ✅ | ✅ |
| Compliance suite, one test per rule | 25 tests, 12 prefixes | 24 tests, 12 prefixes |
| Adversarial tests bypassing the application layer | 5 | 5 |
| Raw-SQL / DML ban at `cargo test` | ✅ | ✅ |
| §7 CI coverage where DDL cannot express a constraint | ✅ `schema_integrity_tests.rs` | ✅ `referential_integrity.rs` |
| Convergence script · e2e suite | ✅ · ✅ | ✅ · ✅ |

§5's adversarial requirement is satisfied on both sides: each project runs tests that write directly
to the database, bypassing the entity layer, and each carries a negative control so the test cannot
pass because the statement was merely malformed. The projects differ only in how such a test is
*marked* — a doc-comment token here, a function-name convention there — and both make their own
convention load-bearing in their own gate.

---

## 7. Executive verdict

**No authorization bypass, privilege-escalation path, or cryptographic weakness was found in either
project.** Every rule in `RBAC_MODEL.md` traces to an identifiable enforcement site in both codebases,
and §5 — the most heavily constrained section, with seven separately checkable demands — is satisfied
in full on both sides, including the requirement that the uniqueness marker be unwritable and that its
test be adversarial rather than cooperative.

**Two findings, both minor, one on each side.** F-1 is a §7 conformance gap on the peer: a
permission-table join column is unindexed while an authenticated path filters on it alone, which is an
availability concern rather than a correctness one and is fixed by a single index. F-2 is a gap in the
*specification* rather than in this project's code: the rules do not say who may delete resource data
shared across several managed resources, and the current implementation's answer — rights on any one
of them — has a cross-tenant effect that §4 would very likely have forbidden had it been considered.

**Security parity is 17 of 19 controls**, the exceptions being F-1 and the deliberate,
documented authentication-posture asymmetry.

**Maturity.** What distinguishes these codebases is not the presence of controls but the presence of
mechanisms that detect their absence: a byte-identity check on the shared specification, one
compliance test per rule with an enforced adversarial subset, a raw-SQL ban that runs on every
`cargo test`, and referential-integrity suites covering the constraints SQLite cannot express in DDL.
§5's insistence that a uniqueness test be adversarial — that a cooperative test "proves only that a
well-behaved writer behaves well" — is the sharpest expression of that posture, and both projects
honour it.

**Verdict: both projects are production-ready.** Neither finding blocks deployment. F-1 should be
closed in the peer's next release; F-2 is a question for the specification's authors rather than a
defect to patch.
