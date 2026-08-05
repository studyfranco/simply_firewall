# Canonical RBAC & Authorization Model

**Status:** Normative specification. **Scope:** `simply_ip_vault` and `simply_hook_executor`.

This document is the single source of truth for the authorization and permission model shared by both
services. It is **byte-identical in both repositories**; `scripts/verify_convergence.sh` enforces
that. Where a rule concerns a service-specific noun, the rule is stated generically and both concrete
nouns are named explicitly.

Neither repository's `AGENT.MD` overrides this document. Where an `AGENT.MD` and this specification
disagree, this specification is correct and the `AGENT.MD` is stale.

## Terminology

| Generic term | `simply_ip_vault` | `simply_hook_executor` |
| :--- | :--- | :--- |
| **Managed resource** | IP Group | Hook |
| **Resource data** | IP Record | Executor |
| **Dispatch target** | Webhook Config | Executor |
| **Resource-creation right** | `can_create_webhooks` | `can_create_executor` |
| **Per-resource permission row** | `api_key_group_permissions` | `api_key_hook_permissions` |

---

## 1. Permission Tiers

| Tier | Granted By | May Manage Resources? | Notes |
| :--- | :--- | :--- | :--- |
| **Master** (unique) | Bootstrap only | Yes, everywhere | Full system control; bypasses scoping; sees all entities. |
| **Parent** (`can_manage_keys`) | Master only | Yes, where a `can_manage` row is held | May create and delegate rights to daughter keys. |
| **Daughter** (no `can_manage_keys`) | Master or any Parent | Never | Rights ⊆ creator's rights. Cannot create keys. |

Resource-creation rights (`can_create_webhooks` in IP Vault / `can_create_executor` in Hook Executor)
sit at the same tier as `can_manage_keys`, are granted strictly by Master, and are never implied by
`can_manage_keys` or resource management rights.

---

## 2. Core Governance Rules

- **R1 — Non-amplification:** A caller may only grant rights it currently holds. A `can_read`-only
  holder can grant `can_read` and nothing more. Applies to all non-Master tiers.
- **R2 — Conjunction of Management:** Managing a specific resource requires holding both global
  `can_manage_keys` AND a `can_manage = true` row for that specific resource. Neither alone is
  sufficient. `can_manage_keys` is never a global bypass for per-resource RBAC.
- **R3 — Parentage Confers No Privilege:** `parent_key_id` exists solely for cascading deletion and
  visibility scoping. A daughter of the Master key is an ordinary daughter key. Rights are never
  derived from key lineage.
- **R4 — Master-Only Elevation:** Only the Master key may grant `can_manage_keys` or
  resource-creation rights (`can_create_webhooks` / `can_create_executor`). A parent key can never
  mint another parent key.
- **R5 — Sideways Management Delegation:** A parent holding manage rights on a resource may delegate
  manage rights on that resource to another existing parent key (bounded by R1 and R2), but cannot
  elevate a daughter key to parent status.
- **R6 — Non-Escalating Revocation:** Revoking a permission requires manage rights on the resource
  only. The revoker need not hold the verb being removed and may revoke its own permissions.
  Reducing permissions via update endpoints is classified as revocation under this rule.
- **R7 — Bounded Granting:** All permission grants are strictly bounded by R1 (non-amplification) and
  R2 (conjunction of manage rights) simultaneously.

---

## 3. Resource Lifecycle & Ownership

- Every managed entity (IP Group / Hook, Webhook Config / Executor) carries an `owner_key_id`.
- Resource lifecycle actions (deleting or renaming the resource itself) are restricted exclusively to
  Master and the designated `owner_key_id`. Holding manage rights or operational verbs confers no
  lifecycle authority.
- Master may reassign `owner_key_id` on any resource at any time.

---

## 4. Visibility & Oracle Discipline

- **Master:** Full visibility over all system resources, keys, and configurations.
- **Parent Keys:** Full visibility over their own key subtree (daughters, granted rights, bound IPs),
  excluding raw secrets.
- **Shared Resource Visibility:** A parent sees a minimal view (ID, name, resource-specific
  permissions) of any key holding permissions on a resource it manages. Global flags, bound IPs, and
  unrelated resource memberships remain hidden.
- **Webhooks & Executors:** Visible exclusively to their creator and Master.
- **Oracle Discipline:** Any resource or key outside the caller's visibility scope MUST return a
  `404 Not Found` response identical to a non-existent entity.

---

## 5. Master Key Guarantees

- Exactly one Master key exists, enforced via database partial unique index (`is_master = true`).
- The Master key is immutable via the API except for its own `bound_ips`.
- The Master key cannot be deleted through API endpoints. Re-minting requires direct DB deletion
  followed by service reboot.

---

## 6. Cascade Deletion & Pre-flight Inventory

- Deleting a key cascades recursively through its entire daughter subtree.
- Resource data is never deleted implicitly. IP Groups, IP Records, Webhook Configs, and Executors
  must persist when their owning key is deleted.
- **Pre-flight Inventory:** Deleting a key requires scanning the target subtree for owned resources.
  If owned resources exist, deletion is rejected with a structured payload listing all affected
  items.
- Deletion proceeds only when the caller provides an explicit resolution map assigning every owned
  resource to either deletion or reassignment to an existing owner key.

---

## 7. Database Constraints & Indexing

- Partial unique index on `is_master = true`.
- Mandatory indexes on `parent_key_id`, `owner_key_id`, key hash lookup columns, and permission table
  join keys.
