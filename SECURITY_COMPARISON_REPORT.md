# Ecosystem Security Comparison Report

**Subject:** `simply_ip_vault` (current project) audited against the three peer services vendored in `example/`.
**Method:** Clean-room. Findings derive exclusively from the current `.rs` sources and the normative `RBAC_MODEL.md`. No prior audit report was read or consulted before the analysis concluded.
**Date:** 2026-08-18

## Provenance

All peers were synchronised via `git pull --ff-only` immediately before analysis.

| Project | Role | Commit | Last commit date |
| :--- | :--- | :--- | :--- |
| `simply_ip_vault` | Current project | `14c8fa3` | 2026-08-18 |
| `example/simply_hook_executor` | Peer | `15b8af6` | 2026-08-18 |
| `example/simply_ip_exporter` | Peer | `80a3b31` | 2026-08-18 |
| `example/simply_ip_sync` | Peer | `0061099` | 2026-08-18 |

## 1. Scale and Surface

| Metric | `simply_ip_vault` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_sync` |
| :--- | ---: | ---: | ---: | ---: |
| `src/` files | 44 | 40 | 32 | 45 |
| `src/` lines | 13,012 | 12,688 | 4,801 | 7,016 |
| Entity types | 9 | 8 | 5 | 11 |
| Integration test files | 7 | 6 | 2 | 14 |
| Test functions | 197 | 182 | 33 | 108 |
| E2E harness | Yes | Yes | Yes | Yes |

`simply_ip_exporter` is roughly one third the size of the other three and carries proportionally the
thinnest test suite. Several findings below track that difference.

## 2. Cryptographic Parity

| Control | Vault | Executor | Exporter | Sync | Verdict |
| :--- | :---: | :---: | :---: | :---: | :--- |
| Request signature | HMAC-SHA256 | HMAC-SHA256 | HMAC-SHA256 | HMAC-SHA256 | **Parity** |
| Canonical payload scheme | `CANONICAL_V1` | `CANONICAL_V1` | `CANONICAL_V1` | `CANONICAL_V1` | **Parity** |
| Signature comparison | constant-time | constant-time | constant-time | constant-time | **Parity** |
| Timestamp window | 300 s | 300 s | 300 s | 300 s | **Parity (value)** |
| Window is configurable | No (`const`) | Yes (env) | Yes (env) | No (`const`) | Divergent (§6.2) |
| Replay guard module | `replay.rs` | `replay.rs` | `replay.rs` | `replay.rs` | **Parity** |
| API key digest | SHA-256 hex | SHA-256 hex | SHA-256 hex | SHA-256 hex | **Parity** |
| Secrets at rest | XChaCha20-Poly1305 | XChaCha20-Poly1305 | XChaCha20-Poly1305 | XChaCha20-Poly1305 | **Parity** |
| `bound_ips` CIDR binding | Enforced | Enforced | Enforced | Enforced | **Parity** |

No cryptographic gap was identified in any of the four services. Algorithm selection, canonicalisation,
comparison discipline and skew tolerance are uniform.

## 3. RBAC Enforcement Against `RBAC_MODEL.md`

### 3.1 Normative specification distribution

| Project | `RBAC_MODEL.md` | Relationship to vault's copy |
| :--- | :--- | :--- |
| `simply_ip_vault` | Present | Reference copy |
| `simply_hook_executor` | Present | **Byte-identical** |
| `simply_ip_exporter` | Present | **Byte-identical** |
| `simply_ip_sync` | Present | Domain-adapted (207 differing lines; R1–R7 restated for `can_sync` / `can_view_logs` verbs) |

`simply_ip_sync` deliberately re-expresses the rules in its own vocabulary while preserving rule
identity and numbering. That is a legitimate adaptation. `simply_ip_exporter` carries the vault's text
verbatim — which, as §3.3 shows, commits it to rules its schema cannot express.

### 3.2 Rule-by-rule enforcement

| Rule | Vault | Executor | Exporter | Sync |
| :--- | :---: | :---: | :---: | :---: |
| **R1** Non-amplification | Enforced (`guard_delegated_group_grant`) | Enforced (`guard_delegated_hook_grant`) | **No surface** | Enforced (`guard_delegated_grant`) |
| **R2** Manage is a conjunction | Enforced (`guard_group_manage`) | Enforced (`guard_hook_manage_conjunction`) | **No surface** | Enforced (`guard_resource_manage`) |
| **R3** Parentage confers no authority | Enforced | Enforced | Enforced (vacuously) | Enforced |
| **R4** Only Master creates parents | Enforced (`guard_scope_elevation`) | Enforced (`guard_master_to_grant_scopes`) | Enforced (`require_master`) | Enforced (`guard_scope_elevation`) |
| **R5** Manage propagates sideways | Enforced | Enforced | **No surface** | Enforced |
| **R6** Revocation is never escalation | Enforced | Enforced | **No surface** | Enforced (`guard_revocation`) |
| **R7** R1 ∧ R2 simultaneously | Enforced | Enforced | **No surface** | Enforced |
| **§3** Lifecycle restricted to Master + owner | `guard_resource_lifecycle` | `guard_lifecycle_authority` | Inline `is_master \|\| owner` | `guard_resource_lifecycle` |
| **§5** Master immutable via API | `guard_master_immutable` | `guard_master_self_edit_is_bound_ips_only` | Inline checks | `guard_master_immutable` |
| **§6** Pre-flight inventory | Enforced | Enforced | **Absent — see F-2** | Enforced |

"No surface" denotes that the service has no per-resource permission model for the rule to govern, not
that the rule is violated.

### 3.3 Authorization architecture

| Aspect | Vault | Executor | Exporter | Sync |
| :--- | :--- | :--- | :--- | :--- |
| Permission join table | `api_key_group_permission` | `api_key_hook_permission` | **None** | `api_key_sync_permission` |
| Centralised `guards.rs` | Yes (7 guards) | Yes (11 guards) | **No** | Yes (11 guards) |
| Authorization model | Ownership + per-resource grants | Ownership + per-resource grants | **Ownership only** | Ownership + per-resource grants |
| Decisions made in | One module | One module | Scattered inline in handlers | One module |

## 4. Master Key Guarantees (§5)

| Requirement | Vault | Executor | Exporter | Sync |
| :--- | :---: | :---: | :---: | :---: |
| Engine-derived `master_marker` (`GENERATED ALWAYS AS`) | Yes | Yes | Yes | Yes |
| Storage mode pinned per engine (`STORED`/`VIRTUAL`) | Yes | Yes | Yes | Yes |
| Unique index over the marker | Yes | Yes | Yes | Yes |
| `is_master` absent from every payload type | Yes | Yes | Yes | Yes |
| Master undeletable through the API | Yes | Yes | Yes | Yes |
| Boot-time identity pin (`master.rs`) | Yes | Yes | Yes | Yes |

**No uniqueness bypass was found in any service.** All four derive the marker in the database engine
rather than in application code, satisfying the explicit prohibition in §5 against an
application-maintained marker. All four additionally pin Master *identity* at boot, which is a
separate property from *cardinality* and is correctly treated as such.

## 5. Payload and Input Strictness

| Control | Vault | Executor | Exporter | Sync |
| :--- | :---: | :---: | :---: | :---: |
| `#[serde(deny_unknown_fields)]` occurrences | 8 | 11 | **0** | 10 |
| `StrictJson` extractor | Yes | Yes | Yes | Yes |
| `StrictPath` extractor | Yes | Yes | Yes | Yes |
| `StrictQuery` extractor | Yes | Yes | No | Yes |
| Errors returned in `{"error": …}` envelope | Yes | Yes | Yes | Yes |

`simply_ip_exporter` wraps its extractors correctly but applies `deny_unknown_fields` to **no payload
type at all**. See F-1.

## 6. Findings

### F-1 — `simply_ip_exporter`: unknown request fields are silently ignored (High)

`CreateKeyPayload`, `UpdateKeyPayload`, `CreateEndpointPayload`, `UpdateEndpointPayload` and
`ReassignOwnerPayload` all derive `Deserialize` without `#[serde(deny_unknown_fields)]`. Serde's
default is to discard unrecognised fields.

The exporter has correctly removed `is_master` from its payload types, so this is not presently a
privilege-escalation path. The risk is the one `RBAC_MODEL.md` §5 names directly when it requires field
*removal* rather than handler-level rejection: a caller submitting `{"name":"x","can_manage_keys":true}`
against an endpoint that does not read that field receives `200 OK` and reasonably concludes the field
was honoured. A silent drop is worse than either acceptance or refusal. The other three services reject
such payloads with `400`.

**Remediation:** add `#[serde(deny_unknown_fields)]` to all five payload types.

### F-2 — `simply_ip_exporter`: no §6 pre-flight inventory or subtree cascade (Medium)

`RBAC_MODEL.md` §6 requires that deleting a key walks the entire daughter subtree, collects every
resource owned by any key within it, and refuses the deletion with a structured inventory if that set is
non-empty. The exporter's `delete_api_key` performs `require_master`, refuses the Master row, then
issues a single `ApiKey::delete_by_id`. There is no subtree walk, no inventory and no resolution map,
despite `api_keys.parent_key_id` existing in its schema.

Its concurrency handling is sound — it checks `rows_affected` and returns `404` to the loser of a
concurrent delete, matching the peers — so this is a completeness gap against §6, not a race.

**Remediation:** implement the subtree walk and inventory refusal, or narrow the exporter's
`RBAC_MODEL.md` to remove §6 (see F-3).

### F-3 — `simply_ip_exporter`: normative spec commits it to rules it has no surface for (Medium, documentation)

The exporter ships a byte-identical copy of the vault's `RBAC_MODEL.md`, which specifies R2, R5, R6, R7
and §6 in terms of per-resource permission rows and cascade inventories. The exporter has no permission
join table and no cascade logic, so those clauses cannot be satisfied, cannot be tested, and cannot be
audited against.

`simply_ip_sync` demonstrates the correct handling: it adapted its copy to its own domain while keeping
rule numbering and semantics intact. The exporter should do the same rather than carry a specification
it structurally cannot meet — an unmeetable spec clause is indistinguishable, to a future auditor, from
an unimplemented one.

### F-4 — `simply_ip_vault`: redundant `key_hash` index (Informational)

`api_keys.key_hash` is declared `.unique_key()` in the initial schema of all four services, and a unique
constraint implies an index on every supported engine. The vault additionally creates an explicit
`idx-api_keys-key_hash`, which its own migration comment describes as "belt-and-braces". This is
harmless but constitutes a duplicate index on the authentication hot path.

**This was initially mis-detected as a peer gap.** A name-based scan suggested three peers lacked a
key-hash index; direct inspection of the column declarations showed all four satisfy §7 through
`unique_key()`. Recorded here because the naive check produces a false positive that a future audit
would otherwise repeat.

### F-5 — Audit attribution non-nullability (Informational, divergence)

The vault carries a dedicated migration making `audit_logs.api_key_name`, `.api_key_prefix` and
`.client_ip` `NOT NULL`, structurally preventing an unattributed audit row. No peer has an equivalent
migration. This is the vault holding a *stronger* position than its peers, not a gap.

## 7. Database Constraints and Indexing (§7)

| Required index target | Vault | Executor | Exporter | Sync |
| :--- | :---: | :---: | :---: | :---: |
| Key-hash lookup column | Yes (unique + explicit) | Yes (unique) | Yes (unique) | Yes (unique) |
| `parent_key_id` | Yes | Yes | Yes | Yes |
| `owner_key_id` | Yes | Yes | Yes | Yes |
| `master_marker` | Yes | Yes | Yes | Yes |
| Permission join columns | Yes | Yes | n/a (no table) | Yes |
| Total `create_index` calls | 20 | 14 | 9 | 10 |

§7 is satisfied by all four services.

## 8. Executive Verdict

**The cryptographic and Master-key layers of this ecosystem are converged and mature.** Across four
independently developed services, request signing, replay defence, secret sealing, key digesting, CIDR
binding, and §5 Master uniqueness are enforced identically and correctly. No uniqueness bypass, no
authorization flaw, and no cryptographic weakness was identified in `simply_ip_vault`,
`simply_hook_executor` or `simply_ip_sync`.

**`simply_ip_vault` carries no outstanding security finding.** It holds the largest test suite (197
functions), the most complete index coverage, and is the only service to structurally forbid
unattributed audit rows. On every axis measured it meets or exceeds the peer baseline.

**`simply_ip_exporter` is the ecosystem's outlier and the sole locus of findings.** All three actionable
findings (F-1, F-2, F-3) are its. They share one root cause: it was built on a simpler ownership-only
authorization model than its peers, but inherited their normative specification and their strictness
conventions without inheriting the mechanisms those conventions assume. None of the three is presently
exploitable; all three are gaps between what the service claims to enforce and what it does enforce, and
that gap is precisely what erodes over time.

**Maturity assessment:**

| Service | Security posture | Convergence with the model |
| :--- | :--- | :--- |
| `simply_ip_vault` | **Mature — no findings** | Full |
| `simply_hook_executor` | **Mature — no findings** | Full |
| `simply_ip_sync` | **Mature — no findings** | Full (domain-adapted) |
| `simply_ip_exporter` | **Developing — 3 findings** | Partial |
