# Comparative Security Audit — `simply_ip_vault` ↔ `simply_hook_executor`

**Date:** 2026-08-07 · **Mode:** strictly read-only — no file under `src/`, `tests/`, `migration/` or
`./example` was modified, and no commit was created. **Scope:** the state of both services after each
independently completed a six-phase implementation of `RBAC_MODEL.md`.

Every finding below was verified against source. `AGENT.MD`, `AGENT_NOTES.MD`, commit messages and
prior audit reports were treated as leads only — and one of them turned out to be wrong again, which
is the headline of this audit.

---

## 0. Reference freshness

`./example` holds **no `.git`**. It is a flat file snapshot, so `git -C ./example rev-parse HEAD`
would walk up and report *this* repository's commit — a provenance the reference does not have. No
git command was run inside it. Freshness was established from file modification times and from the
phase headings inside `example/simply_hook_executor/AGENT_NOTES.MD`.

| Probe | Result | Meaning |
| :--- | :--- | :--- |
| `example/simply_hook_executor/.git` | absent | flat snapshot, not an independent checkout |
| Peer `AGENT_NOTES.MD` last phase heading | `## Phase 5 — Compliance Suite & Mutation Validation` (line 3397) | the peer's six-phase run completed |
| Peer newest source mtime | `src/api.rs`, `src/migration/m20230107_…` — 2026-08-07 15:48 | same-day |
| Peer `AGENT_NOTES.MD` mtime | 2026-08-07 15:51 | same-day |
| This repo's newest source mtime | `src/api.rs` — 2026-08-07 20:21 | ~4.5 h later |
| Peer `RBAC_MODEL.md` mtime | 2026-08-07 09:44 | predates both implementations — the shared spec, unmoved |

**Verdict: current, with a stated lag.** The snapshot is from the same working day and reflects the
peer's *completed* Phase 5. This repository's Phases 3–5 landed after the snapshot was taken, so where
a difference below favours `simply_ip_vault`, the possibility that the peer has since closed it cannot
be excluded from here. Where a difference favours the peer, no such caveat applies — the peer's code
is older than the finding.

---

## 1. `RBAC_MODEL.md` byte-identity — the check that had never run

**It ran, for the first time, and it passes.**

Both services previously reported the peer's copy as ABSENT, so Pillar 0 had never executed against a
real file. The peer snapshot now carries `RBAC_MODEL.md`.

| Probe | Result |
| :--- | :--- |
| `cmp RBAC_MODEL.md example/simply_hook_executor/RBAC_MODEL.md` | **byte-identical** (exit 0) |
| `md5sum`, both copies | `42c0c8bd1ab010a41793fb41f7c27395` |
| Size, both copies | 7 846 bytes |
| `./scripts/verify_convergence.sh` Pillar 0 | `✓ MATCH  RBAC_MODEL.md is byte-identical across services` |

There are no substantive divergences to report, because there are no divergences at all. This is the
first audit in which the specification itself has been *verified* shared rather than assumed shared.

---

## 2. §5 master uniqueness — the mechanism, not its presence

Both services added a `master_marker` column under a plain unique index. **They are not equivalent,
and the difference is exploitable.**

`RBAC_MODEL.md` §5: uniqueness must be "enforced by a database constraint rather than by application
logic alone."

| Aspect | simply_ip_vault | simply_hook_executor | Assessment |
| :--- | :--- | :--- | :--- |
| Marker mechanism | **Application-maintained.** `VARCHAR(16) NULL`, written only by `bootstrap_master_key` (`src/main.rs:120`), migration `m20260807_000007_add_api_key_master_marker` | **Engine-generated.** `INTEGER GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)`, migration `m20230106_000001_master_key_uniqueness:56-72` | **`simply_hook_executor` — materially stronger.** The marker cannot be omitted, forged, or desynchronised from `is_master`, because nothing may write it |
| §5 satisfied? | **No.** Verified live: schema is `"master_marker" varchar(16) NULL`; a direct `INSERT … is_master=1, master_marker=NULL` **was accepted**, leaving two masters. NULLs do not collide in a unique index, so the constraint never fires | **Yes.** `is_master = true` forces `master_marker = 1` by construction; a second such row collides on `idx_api_keys_master_marker` | **`simply_hook_executor`.** The vault's constraint is precisely the "application logic alone" §5 forbids — it holds only for a cooperative writer |
| Storage mode per backend | n/a — not a generated column | `STORED` on PostgreSQL (VIRTUAL arrived in 18), `VIRTUAL` on SQLite (the only mode `ALTER TABLE` permits) and MySQL | **`simply_hook_executor`.** The vault has no equivalent decision to get right |
| Storage mode pinned by tests | n/a | Yes — unit tests at `m20230106_000001:106-136` assert the exact suffix per backend and that the DDL contains `GENERATED ALWAYS AS … is_master` | **`simply_hook_executor`.** A backend-specific DDL error would otherwise surface only against a real PostgreSQL |
| Compliance test | `s5_…`, `s7_…` assert a second master insert fails — but both **supply the marker explicitly**, so they test a cooperative writer | `s5_exactly_one_master_immutable_and_undeletable`; the bypass is unreachable by construction | **`simply_hook_executor`.** The vault's tests pass and its constraint is still bypassable — the gap is in what the test omits to try |

**This is the audit's principal finding and it is against this repository.** It was demonstrated, not
inferred: a live database built from the current migrations accepted a second master row.
`AGENT_NOTES.MD` (Phase 0) states the constraint is enforced "by the schema, not by application
logic". That claim is wrong, and the migration's own module doc repeats it.

The fix is a schema change and therefore out of scope for a read-only audit. The shape is known and
already proven on the peer side: replace the nullable column with
`GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)`, per-backend storage mode, and drop
the entity field and the `bootstrap_master_key` write, since a generated column must not be written.

---

## 3. Terminology resolution — resolved on one side, structurally open on the other

Both claims from the peer's report were verified and both are true.

| Aspect | simply_ip_vault | simply_hook_executor | Assessment |
| :--- | :--- | :--- | :--- |
| Managed resource | `ip_groups` — shared, permission rows in `api_key_group_permissions` | `hooks` — shared, permission rows in `api_key_hook_permissions` | Equivalent |
| Dispatch target | `webhook_configs`, distinct entity, creator-private via `owner_key_id` | **None.** `src/entities/` holds `hook.rs`, `execution.rs`, `hook_parameter.rs` — no Executor entity exists | **Divergent readings.** The vault has two entities for the spec's two roles; the peer has one entity holding both |
| `can_create_executor` | n/a | **Absent from `src/` entirely** — the only occurrence anywhere is a comment in `tests/rbac_model_compliance.rs:209` saying so | **Specification defect** (see §4) |
| §3 ownership means | Two ownerships: `ip_groups.owner_key_id` (managed resource) and `webhook_configs.owner_key_id` (dispatch target) | One: `hooks.owner_key_id`, covering both roles at once | Compatible in effect; the peer cannot separate lifecycle authority over "the shared thing" from "the private thing" because they are the same row |
| §4 scope 3 (creator-plus-Master) means | A real, separate scope: `list_webhooks` filters on `owner_key_id`, and a group peer gets `404` | **Collapses into scope 2.** A hook's visibility is its permission row (`require_visibility`, `src/api.rs:343`); there is no creator-private surface to scope | **Divergent.** Scope 3 is implemented in the vault and vacuous in the peer — not a peer defect, a consequence of the entity model |
| §6 inventory covers | `ip_groups` **and** `webhook_configs` owned by any key in the subtree | `hooks` only — one entity type, so `entity_type` is effectively constant | Equivalent in rigour; different in breadth because the schemas differ |

The two readings have **silently diverged**, and neither service is wrong under its own schema. The
divergence lives in the specification: `RBAC_MODEL.md` asserts that managed resource and dispatch
target are distinct roles that "an entity cannot [both] hold", and one of the two services it governs
has a schema in which they are the same entity. The peer complied by making the Hook a managed
resource and treating scope 3 as unreachable; that is the only available reading, and it means §4 has
three scopes in one service and two in the other.

---

## 4. Rights named in the specification that do not exist

| Right named in the spec's terminology table | Exists in `simply_ip_vault`? | Exists in `simply_hook_executor`? | Assessment |
| :--- | :--- | :--- | :--- |
| `can_create_webhooks` | **No.** The real column is `api_keys.can_manage_webhooks` — a *management* right covering create, update, delete and list, not a creation right | n/a | **Specification defect** — the table names a column that has never existed |
| `can_create_executor` | n/a | **No.** Absent from `src/`; the closest is `api_keys.can_manage_hooks` | **Specification defect** |
| Number of resource-creation rights implied by the table | 1 | 1 | — |
| Number actually present | **2** — `can_create_groups` (managed resources) and `can_manage_webhooks` (dispatch targets) | **1** — `can_manage_hooks` | **Specification defect.** The table assumes a one-to-one mapping that holds in neither service |

Both services resolved this identically and independently: treat the real management flags as the
resource-creation rights §1 places at Master-only tier, and make them Master-only under R4. That is
the correct reading, and both got there. **The defect is in `RBAC_MODEL.md`'s terminology table**,
which names two columns that exist nowhere and undercounts the vault's creation rights.

Because the specification is byte-identical and normative, this cannot be fixed on one side. It needs
a coordinated edit — the table should name `can_manage_webhooks` / `can_create_groups` and
`can_manage_hooks`, or state that the generic term maps to whatever each service's Master-only
creation flags are.

---

## 5. Rules "covered but not fully enforced"

The peer reported two. Both verified true. The vault was then checked for the equivalents.

| Gap | simply_ip_vault | simply_hook_executor | Assessment |
| :--- | :--- | :--- | :--- |
| **R2's wider reading** — per-resource `can_manage` without the global half authorizes changing what the resource *does* | **Does not exist.** `guard_group_manage` (`src/api.rs`) requires both halves and governs permission rows; the analogue of `script_path` is a webhook's `target_url`, gated on `owner_key_id` (`update_webhook`), which is stricter still. No endpoint renames or re-scopes a group at all | **Present and real.** `require_manage` (`src/api.rs:323-336`) checks `p.can_manage` alone, with **no `can_manage_keys` conjunct**, and gates `update_hook` — so a Daughter key with one permission row can rewrite `script_path`, i.e. **which binary executes**. Bounded by `require_master_for_privileged_hook` (elevated hooks) and `validate_script_path` (allowed roots), so the blast radius is non-privileged hooks inside permitted directories | **`simply_ip_vault` stronger.** §1's tier matrix says a Daughter "may never" manage resources; the peer's read/execute surface honours that, its definition-editing surface does not |
| **§3 applied to keys themselves** — `api_keys.owner_key_id` populated but not an authorization input | **Cannot exist.** `api_keys` has no `owner_key_id`; key administration is scoped by `parent_key_id` subtree membership, which **is** enforced (`find_administrable_key`, `caller_can_administer_key`) | **Present.** `api_keys.owner_key_id` is written on creation (`src/api.rs:2639`) and walked by §6's inventory, but every authorization read of `owner_key_id` resolves the *hook* model (`src/api.rs:1291`). No guard consults the key's own owner | **`simply_ip_vault` marginally stronger** — one lineage concept, enforced. The peer has two, enforces one, and carries an authorization-shaped column that authorizes nothing |

Neither gap appears in this repository's own report. Verified here: **that is because they do not
exist in the vault, not because they were not looked for.** The R2 gap is structurally impossible
given how narrowly `guard_group_manage` is scoped, and the §3-on-keys gap requires a column the vault
never added.

---

## 6. Remaining security-relevant implementation choices

| Aspect | simply_ip_vault | simply_hook_executor | Assessment |
| :--- | :--- | :--- | :--- |
| DDL foreign keys on `parent_key_id` / `owner_key_id` | **Omitted.** Reason recorded: SQLite has no `ALTER TABLE … ADD CONSTRAINT`, so the constraint would exist on two backends and silently not on the one CI runs. Integrity enforced in `resolve_owner_assignment` (validates on write) and `delete_api_key` (nulls on removal) | **Omitted.** Reason recorded: both FK actions are wrong — `CASCADE` violates §6's "data is never destroyed implicitly", `SET NULL` silently orphans exactly what the inventory exists to show the caller. §6's inventory *is* the integrity mechanism, and is necessarily application-level because it is interactive | **Equivalent outcome, and the peer's reasoning is the better one.** Both omit; the peer's argument survives even on a backend that supports the DDL, the vault's does not |
| Unknown / forbidden payload fields | `is_master` **retained as a field** on `CreateApiKeyPayload` and `UpdateApiKeyPayload`, rejected by `guard_no_master_flag` with **`400`** naming the field and stating why. No `deny_unknown_fields` anywhere | `is_master` **removed from the payload types entirely**; `#[serde(deny_unknown_fields)]` on `CreateApiKeyPayload`, `UpdateApiKeyPayload`, the resolution map and its entries (`src/api.rs:2424, 2732, 2855, 2869`) | **`simply_hook_executor` stronger structurally**, and it is what Phase 0's brief actually asked for — "remove it from the payload type entirely rather than guarding it at the handler, so no future handler can reintroduce the path." The vault's guard is behaviourally correct today and one careless handler away from not being. The vault's message is more actionable; that is the lesser property |
| Master rotation refused for every caller incl. the master | Yes — `guard_master_immutable(&target, "rotated")` / `"re-keyed"` keys on `target.is_master` alone, caller-independent | Yes — `refuse_master_lifecycle_action` keys on `target.is_master` alone | Equivalent |
| Master deletion refused, and independent of the uniqueness constraint | Yes — `guard_master_immutable(&target, "deleted")`, unconditional; does not consult row count or the index | Yes, and stated explicitly: "barred regardless of row count so that the rule does not silently depend on the uniqueness index … two independent controls, not one control leaning on another" | **Equivalent in behaviour.** Note the vault's independence here is what stops §2's bypass from also yielding a deletable master |
| `owner_key_id` / `parent_key_id` backfill | `NULL` everywhere. Rationale: `audit_logs` is retention-swept, `ON DELETE SET NULL`, and inconsistent across auto-provisioning paths — reconstructing ownership from it would hand out the right to delete a resource | `NULL` everywhere. Same rationale, plus a sharper one: a hook's creator is *not recorded anywhere*, since `grant_full_hook_permission` gives the creator a permission row byte-identical to a delegated one | Equivalent, independently reasoned to the same conclusion |
| What pre-upgrade rows can do afterwards | Groups: unowned → Master-only lifecycle (unchanged from before, which was Master-only). Webhooks: unowned → **Master-only for read, update and delete** — a real narrowing. Keys: no `parent_key_id` → in nobody's subtree → administrable only by Master | Hooks: unowned → Master-only lifecycle. Keys: no `parent_key_id` → outside every subtree | **Equivalent posture.** The vault's narrowing is wider in effect because webhook *visibility* moved too, which the peer had no equivalent of (see §3) |
| Rules with a firing mutation | **12 / 12.** Verified during this audit that the 401-vs-403 ordering also fires (unknown key → `403` mutation ⇒ `s4_authenticate_then_authorize_ordering_survives_oracle_discipline` FAILED); it was not exercised in Phase 5 | **14 / 14** enforcement sites | Equivalent rigour |
| Surviving mutations, documented | 2, both defence-in-depth: the two `can_manage_keys` conjunct sites mask each other (removing both fires); the fail-closed branch in `guard_delegated_group_grant` is unreachable by construction | 2, both defence-in-depth and the same shape: the global-R2 half is enforced at both `has_permission_admin_standing` and `require_hook_manage_conjunction` (removing both fires) | **Equivalent, and independently arrived at the same honest framing** — recorded rather than counted as covered |
| A mutation that initially survived and exposed a real test gap | Yes — endpoint parity (R6) changed no result until a reduction *leaving* a verb the caller lacks was added | Yes — the §4 oracle probed only one route, leaving `verb_denied` unpinned; the test now walks six routes | Equivalent; both found the same class of defect and both fixed the test rather than the report |
| Compliance suite | 14 tests, 12 rule prefixes; convergence gate greps `fn` definitions only and was **verified to fail** (dropping `r5_` ⇒ `✗ GAP`, exit 1) | 14 tests, 12 rule prefixes (three `s4_`, matching) | Equivalent |
| Assertions one side makes that the other only assumes | Vault's `s7_…` queries `sqlite_master` for the live DDL **and** asserts the constraint behaviourally, because an index that exists but is not unique passes any name check | Peer's `m20230106_000001` unit tests pin the **generated-column DDL per backend** — the vault has no equivalent because it has no generated column | **Split.** Each asserts something the other does not; the peer's is the one that would have caught §2's defect |
| Authentication posture | Full-URI HMAC + anti-replay, every key, no switch | Per-key configurable (full / body-only / none), for third-party senders | **Intentional asymmetry — do not unify** |

---

## 7. Executive summary

**Aspects compared:** 44 across seven dimensions — specification identity, §5 uniqueness mechanism,
terminology resolution, named-but-absent rights, partially-enforced rules, and fifteen
implementation choices.

**The specification is now verifiably shared.** `RBAC_MODEL.md` is byte-identical across both
repositories (`md5 42c0c8bd…`, 7 846 bytes). Pillar 0 executed against a real peer file for the first
time and passed. Every prior audit reported it ABSENT.

**Genuine divergences: 4.**

1. **§5 master uniqueness — `simply_ip_vault` is weaker, and the constraint does not hold.**
   Demonstrated on a live database: a direct insert with `is_master = 1` and `master_marker = NULL`
   was accepted, producing two masters, because NULLs do not collide in a unique index. The vault's
   marker is application-maintained; the peer's is `GENERATED ALWAYS AS` and cannot be desynchronised.
   The vault's own compliance tests pass because they supply the marker — they test a cooperative
   writer. **This is the one place where a rule in `RBAC_MODEL.md` is not actually enforced by the
   service that claims it.**
2. **R2's wider reading — `simply_hook_executor` is weaker.** `require_manage` omits the
   `can_manage_keys` conjunct, so a Daughter key with a single permission row can edit a hook's
   `script_path` — which binary runs. Bounded by the privileged-hook guard and script-root
   validation, and self-reported. The vault has no equivalent surface.
3. **§3 applied to keys — `simply_hook_executor` carries a dormant column.** `api_keys.owner_key_id`
   is written and inventoried but read by no guard. The vault has no such column and enforces key
   administration through `parent_key_id` subtree membership.
4. **Payload strictness — `simply_hook_executor` is stronger structurally.** It removed `is_master`
   from the payload types and applies `deny_unknown_fields`; the vault retains the field and rejects
   it at the handler with a `400`. Equivalent today; the peer's cannot be reintroduced by a careless
   handler.

**Intentional asymmetries: 2.** The authentication posture (permanent, recorded, never scored). And
§4's third visibility scope, which is real in the vault and vacuous in the peer — a consequence of
entity models, not of rigour.

**Specification defects: 3.** `can_create_webhooks` and `can_create_executor` name columns that exist
in neither service; the terminology table implies one resource-creation right where the vault has two;
and the table's managed-resource/dispatch-target split assumes a separation the peer's schema does not
have, leaving one service implementing three visibility scopes and the other two. All three need a
coordinated edit to the byte-identical spec — none can be fixed on one side.

**Is either service currently weaker than the other on any rule in `RBAC_MODEL.md`? Yes — both, on
different rules.**

- `simply_ip_vault` is weaker on **§5**. Its uniqueness constraint is bypassable by any writer with
  database access, which is the threat model §5 names. This is the more serious of the two: the rule
  is documented as enforced, tested as enforced, and is not enforced.
- `simply_hook_executor` is weaker on **R2**, on the hook-definition surface. A Daughter key can
  change what executes.

Everything else is equivalent or explained. Both services independently reached the same conclusions
on backfill posture, foreign-key omission, master-deletion independence from the uniqueness index, and
the honest treatment of surviving mutations — convergence that was not coordinated and is worth more
than the checklist that produced it.
