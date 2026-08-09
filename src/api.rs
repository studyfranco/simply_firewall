//! API endpoints and business logic.

use axum::{
    extract::{Json, Query, State, Path},
    response::IntoResponse,
    Extension,
};
use chrono::Utc;
use ipnetwork::IpNetwork;
use rand::RngExt;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter,
    sea_query::OnConflict, Condition, QuerySelect, QueryOrder, ActiveModelTrait, SqlErr,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entities::{
    api_key, api_key_group_permission, audit_log, ip_group, ip_record,
    ip_record_group_membership, prelude::*, webhook_config,
};
use crate::error::AppError;
use crate::extract::StrictJson;
use crate::middleware::ClientIp;
use crate::state::{AppState, WebhookEvent};

/// The three webhook-filterable IP mutation actions, in the vocabulary shared by
/// `audit_log::Model::action` and `webhook_config::Model::events`.
const IP_EVENT_ACTIONS: [&str; 3] = ["IP_ADD", "IP_UPDATE", "IP_DELETE"];

// `MASTER_MARKER` used to live here: the string `bootstrap_master_key` wrote into
// `api_keys.master_marker` to claim the unique index. It is gone because the column is now
// `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` and no client may write it
// (`RBAC_MODEL.md` §5, `migration::m20260808_000009_derive_master_marker`). Application code holding
// a constant for a value the engine derives is the arrangement that let a writer set `is_master`
// and leave the marker NULL. There is nothing here to keep in step any more.

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

/// Generates a random 32-byte hex key for API authentication
pub fn generate_random_key() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Hashes an API key using SHA-256 for secure storage
pub fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Canonicalizes an IP address or CIDR string so the same address always has exactly one
/// string representation, regardless of how the caller wrote it. An IPv4 `/32` or IPv6 `/128` —
/// a "network" of exactly one host — is stripped down to the plain host address: without this,
/// `188.190.74.128/32` and `188.190.74.128` would be stored/matched as two different
/// `ip_records.target_address` values despite meaning the same thing. Genuine subnets (`/24`,
/// `/64`, ...) keep their CIDR notation exactly as given — `IpNetwork::ip()` returns the address
/// as parsed, not masked to the network base, so a non-aligned host-within-a-subnet like
/// `188.190.74.130/24` round-trips unchanged rather than becoming `188.190.74.0/24`.
///
/// Infallible by design: input that doesn't parse as a valid IP/CIDR at all is returned
/// unchanged. This function's job is normalization, not validation — callers that need to reject
/// malformed input (e.g. `handle_ip_upsert`) already parse and validate it themselves; callers
/// that use this for a best-effort match (e.g. `list_ips`'s substring filter, `delete_ip`'s
/// lookup) need a plain fragment like `"74.128"` to keep working exactly as before.
pub fn normalize_ip_or_cidr(input: &str) -> String {
    match input.parse::<IpNetwork>() {
        Ok(net) => {
            let is_single_host = (net.is_ipv4() && net.prefix() == 32) || (net.is_ipv6() && net.prefix() == 128);
            if is_single_host {
                net.ip().to_string()
            } else {
                net.to_string()
            }
        }
        Err(_) => input.to_owned(),
    }
}

/// Formats a target API key for a human-readable audit log `details` string, e.g.
/// `"'worker_bot' (65cf11ce...)"` — pairs the name (what an operator actually recognizes) with a
/// truncated id (for unambiguous cross-referencing against a `GET /api/keys` listing) instead of
/// a bare UUID, which was cryptic on its own.
fn format_key_reference(name: &str, id: Uuid) -> String {
    let id_str = id.to_string();
    format!("'{name}' ({}...)", &id_str[..8])
}

/// Guards any operation whose *target* is another API key, on top of the caller's `can_manage_keys`
/// scope.
///
/// `can_manage_keys` delegates key administration; it does not delegate authority over the keys that
/// grant it. Without this check the scope was transitively equivalent to `is_master`, because every
/// destructive or re-keying operation accepted a master key as its target:
///
/// - `POST /keys/{id}/rotate` on a master key returns the **new plaintext key and signing secret**
///   in its response body — a complete, immediate takeover of the master credential.
/// - `POST /keys/{id}/rotate-secret` likewise hands back a working signing secret for that key.
/// - `PUT /keys/{id}` can rewrite a master key's `bound_ips`, relocating it to the attacker's own
///   network.
/// - `DELETE /keys/{id}` can remove the master keys that would otherwise contain the incident.
///
/// Returns `403` rather than `404`: the caller legitimately holds `can_manage_keys` and can already
/// see the key in `GET /api/keys`, so hiding its existence here would buy nothing and make a
/// legitimate operator's failure inscrutable.
/// The caller's own permission row for one group, or `None` when it has no access to it.
///
/// Master keys have no rows in `api_key_group_permissions` at all — their access is implicit — so
/// callers of this helper must special-case `is_master` *before* calling it, not after.
async fn caller_group_permission(
    db: &sea_orm::DatabaseConnection,
    key_id: Uuid,
    group_id: Uuid,
) -> Result<Option<api_key_group_permission::Model>, AppError> {
    api_key_group_permission::Entity::find()
        .filter(
            Condition::all()
                .add(api_key_group_permission::Column::ApiKeyId.eq(key_id))
                .add(api_key_group_permission::Column::GroupId.eq(group_id)),
        )
        .one(db)
        .await
        .map_err(AppError::DbError)
}

/// The `owner_key_id` to record when `creator` creates a resource.
///
/// `None` for a master, matching what `create_ip_group` already did for permission rows: a master is
/// not a tenant, it is the system, and pinning its id into `owner_key_id` would make an
/// administrative action look like a claim of ownership. A master-created resource is unowned until
/// someone is deliberately assigned, and [`guard_resource_lifecycle`] reads unowned as "Master only",
/// which is exactly the authority a master already had.
fn resource_owner(creator: &api_key::Model) -> Option<Uuid> {
    (!creator.is_master).then_some(creator.id)
}

/// **§3 — lifecycle authority.** Deleting or renaming a resource is restricted to the Master and the
/// designated `owner_key_id`, and to nobody else.
///
/// `RBAC_MODEL.md` §3: "Resource lifecycle actions — deleting or renaming the entity itself — are
/// restricted exclusively to Master and the designated `owner_key_id`. Holding manage rights or any
/// operational verb confers no lifecycle authority: a parent that merely uses a resource must not be
/// able to delete it."
///
/// That last clause is the whole point, and it is why this is a separate guard rather than another
/// branch inside [`guard_group_manage`]. `can_manage` is authority over a resource's **permission
/// rows** — who may read and write its contents. Lifecycle authority is over the resource's
/// **existence**. Conflating them means the key you trusted to hand out read access can also delete
/// the thing everyone was reading, and no combination of operational verbs adds up to that.
///
/// # An unowned resource is Master-only
///
/// `owner_key_id` is `NULL` on every row that predates the column, and on everything a master
/// creates. There is no owner to admit, so only the master passes — which withholds authority rather
/// than inventing it, and is recoverable in one call to the owner-reassignment endpoint.
fn guard_resource_lifecycle(
    caller: &api_key::Model,
    owner_key_id: Option<Uuid>,
    resource: &str,
    action: &str,
) -> Result<(), AppError> {
    if caller.is_master || owner_key_id.is_some_and(|owner| owner == caller.id) {
        return Ok(());
    }

    Err(AppError::Forbidden(format!(
        "Permission denied: only the master key or this {resource}'s owner may {action} it. \
         Managing its permissions or holding read/write/delete on its contents confers no authority \
         over the {resource} itself."
    )))
}

/// Validates an `owner_key_id` a caller asked to assign, and returns it ready to store.
///
/// No database-level foreign key backs these columns (SQLite has no `ALTER TABLE … ADD CONSTRAINT`;
/// see the migration), so the reference is checked here instead — this is the only path by which one
/// can be introduced. A master key is refused as an owner for the same reason
/// [`resource_owner`] never records one: ownership is a tenancy relationship, and the master is not a
/// tenant. `None` clears ownership, returning the resource to Master-only.
async fn resolve_owner_assignment(
    db: &sea_orm::DatabaseConnection,
    requested: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    let Some(owner_id) = requested else {
        return Ok(None);
    };

    let owner = ApiKey::find_by_id(owner_id)
        .one(db)
        .await?
        .ok_or_else(|| AppError::InvalidInput("No such key to assign ownership to".to_owned()))?;

    if owner.is_master {
        return Err(AppError::InvalidInput(
            "The master key cannot be a resource owner; leave owner_key_id null instead, which \
             already means master-only"
                .to_owned(),
        ));
    }

    Ok(Some(owner_id))
}

/// **R2 — management of a resource is a conjunction.** The single authority test for touching *any*
/// key's permissions on one group, in either direction.
///
/// `RBAC_MODEL.md` R2: "Managing a specific resource requires holding both global `can_manage_keys`
/// AND a `can_manage = true` row for that specific resource. Neither alone is sufficient.
/// `can_manage_keys` is never a global bypass of per-resource RBAC."
///
/// Each half answers a different question, and each is useless without the other:
///
/// - `can_manage_keys` is authority over **credentials**. It says the caller may administer keys at
///   all; it says nothing about *which* groups it may reach. On its own it made per-group RBAC
///   advisory — a key scoped to one group could rewrite every other key's access to every group in
///   the installation.
/// - `can_manage` is authority over **one resource**. It says which group. On its own it admitted a
///   key holding no global scope whatsoever to rewriting other keys' credentials, which is exactly
///   the tier boundary §1 draws: a Daughter key "may never" manage resources.
///
/// `action` names the operation (`"grant"` / `"revoke"`) and appears verbatim in the client-facing
/// message, which is otherwise identical between the two paths so a caller probing them cannot tell
/// which one refused it. The message states the *rule*, never the caller's state: "you hold one half
/// but not the other" would be a usable oracle.
///
/// # What this replaced, and why the previous split was wrong
///
/// Until now grant and revoke were gated differently on purpose: revocation accepted `can_manage`
/// alone, on the reasoning that removing a verb cannot raise anyone's authority and so needs no
/// anti-escalation proof. That reasoning is sound as far as it goes, and it is not what R2 governs.
/// Revocation is an **integrity** operation — stripping the credential another tenant's `fail2ban`
/// writes with stops that tenant's blocking, and the symptom sits several audit-log pages from the
/// cause — and R2's answer is that authority over *anyone's* credentials, in either direction, starts
/// at `can_manage_keys`. The resource-scoped half then bounds it to one group. R6 still holds and is
/// unchanged: the revoker need not hold the verb being removed, and may revoke its own permissions.
fn guard_group_manage(
    caller: &api_key::Model,
    caller_perm: Option<&api_key_group_permission::Model>,
    group_name: &str,
    action: &str,
) -> Result<(), AppError> {
    if caller.is_master {
        return Ok(());
    }

    if caller.can_manage_keys && caller_perm.is_some_and(|p| p.can_manage) {
        return Ok(());
    }

    Err(AppError::Forbidden(format!(
        "Permission denied: you cannot {action} permissions on group '{group_name}'. Managing a \
         group's permissions requires both the global can_manage_keys scope and can_manage = true \
         on your own grant for that group; neither alone is sufficient."
    )))
}

/// Whether the caller holds a `can_manage` row on **any** group.
///
/// A cheap pre-gate, run before any group is resolved so that a caller with no administrative
/// standing at all is refused without learning whether a group or a grant exists. It is deliberately
/// the *weaker* half of [`guard_group_manage`] — "does this caller administer anything?" — because a
/// pre-gate that consulted the target group would make the `403` depend on what exists. The precise
/// test runs later, once the group is known.
async fn holds_any_group_manage(
    db: &sea_orm::DatabaseConnection,
    key_id: Uuid,
) -> Result<bool, AppError> {
    api_key_group_permission::Entity::find()
        .filter(
            Condition::all()
                .add(api_key_group_permission::Column::ApiKeyId.eq(key_id))
                .add(api_key_group_permission::Column::CanManage.eq(true)),
        )
        .one(db)
        .await
        .map(|found| found.is_some())
        .map_err(AppError::DbError)
}

/// The pre-gate both permission-administration endpoints run before touching any group.
///
/// Both halves of R2 are checked here in their group-independent form — `can_manage_keys` costs
/// nothing, and the `can_manage`-anywhere lookup is one indexed query issued only for callers that
/// already passed the first half. A caller failing this is refused without a single lookup against
/// the group or the target key, which is what keeps the `403` from confirming that either exists.
async fn guard_may_administer_any_group(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
) -> Result<(), AppError> {
    if caller.is_master {
        return Ok(());
    }

    if caller.can_manage_keys && holds_any_group_manage(db, caller.id).await? {
        return Ok(());
    }

    Err(AppError::Forbidden("Permission denied".to_owned()))
}

/// Whether `requested` would give the target any verb it does not already hold.
///
/// This is the question that decides **which gate applies** to an update, and it is deliberately
/// asked against the *target's* current row rather than the caller's: "does this raise anyone's
/// authority?" is a different question from "does this exceed the caller's own?" (the latter is
/// [`guard_delegated_group_grant`]'s anti-escalation check, which still applies to grants).
///
/// A row that does not exist yet counts as a grant regardless of its contents, matching `AGENT.MD`
/// §2 — creating a permission row is an act of conferral even when the verbs start empty, and a
/// resource-scoped `can_manage` must not be able to mint rows.
fn widens_permissions(
    requested: &GroupPermInput,
    target_perm: Option<&api_key_group_permission::Model>,
) -> bool {
    let Some(held) = target_perm else {
        return true;
    };
    (requested.can_read && !held.can_read)
        || (requested.can_write && !held.can_write)
        || (requested.can_delete && !held.can_delete)
        || (requested.can_manage && !held.can_manage)
}

/// **R1 + R7 — granting is bounded by non-amplification on top of the R2 conjunction.**
///
/// Layered on [`guard_group_manage`]: R2 is necessary to touch a group's grants at all, and
/// *additionally* each verb being conferred is checked independently against the caller's own row —
/// holding `can_read` on a group does not confer the right to grant `can_write` on it. R7 states
/// exactly this composition: "Granting is bounded by R1 and R2 together, simultaneously and without
/// exception."
///
/// # Only the granting direction is checked per verb
///
/// `over_grants` tests `requested && !held`, so a verb being set to **false** is never examined.
/// Reducing a permission therefore needs no proof of authority over the verb removed, which is R6:
/// "the revoker need not hold the verb being removed". That asymmetry with granting is the whole
/// point — conferring a verb can raise someone's authority above the caller's own, and removing one
/// cannot raise anyone's at all. The dedicated revoke route applies the same rule, so "revoke the
/// row" and "update the row to a lower value" are governed identically rather than by two rules that
/// happen to disagree (R6, final sentence).
fn guard_delegated_group_grant(
    caller: &api_key::Model,
    caller_perm: Option<&api_key_group_permission::Model>,
    group_name: &str,
    action: &str,
    requested: &GroupPermInput,
) -> Result<(), AppError> {
    guard_group_manage(caller, caller_perm, group_name, action)?;

    if caller.is_master {
        return Ok(());
    }

    // Guaranteed `Some` by the R2 gate above, which refuses a non-master holding no `can_manage` row.
    // Fails **closed** rather than returning `Ok`: this branch is unreachable today, and the one way
    // it becomes reachable is a future edit that loosens the gate — at which point "unreachable" and
    // "grants everything unchecked" would be one refactor apart.
    let Some(held) = caller_perm else {
        return Err(AppError::Forbidden(format!(
            "Permission denied: you cannot {action} permissions on group '{group_name}'"
        )));
    };

    let over_grants = (requested.can_read && !held.can_read)
        || (requested.can_write && !held.can_write)
        || (requested.can_delete && !held.can_delete)
        // `can_manage` is a verb like any other here: a caller may only confer the administrative
        // right over a group if it holds that right itself. Redundant against the R2 gate as written
        // — a non-master reaching this line necessarily holds `can_manage` — and kept because R1
        // states the rule per verb, and a verb list that quietly omits one is how the next verb added
        // to this table gets forgotten. It is also what implements R5: manage may propagate sideways
        // between parents, bounded by R1 and R2, and never upward to a daughter (which the
        // conjunction blocks, since the recipient still needs `can_manage_keys`).
        || (requested.can_manage && !held.can_manage);

    if over_grants {
        tracing::warn!(
            "Blocked privilege delegation: key {} attempted to {} permissions on group '{}' \
             exceeding its own (read={} write={} delete={})",
            caller.prefix,
            action,
            group_name,
            held.can_read,
            held.can_write,
            held.can_delete
        );
        return Err(AppError::Forbidden(format!(
            "Permission denied: you cannot {action} permissions on group '{group_name}' beyond your own"
        )));
    }

    Ok(())
}

/// **R4 — only Master creates parents.** Every global scope, and only a master key may hand any of
/// them out.
///
/// `RBAC_MODEL.md` R4: "Only the Master key may grant `can_manage_keys` or resource-creation rights.
/// A parent key can never mint another parent key." §1 puts resource-creation rights "at the same
/// tier as `can_manage_keys`", granted strictly by Master and "never implied by `can_manage_keys`" —
/// managing keys and being able to point a dispatch target at an arbitrary URL are separate powers.
///
/// `is_master` is **not** on this list, because it is no longer grantable by anyone: §5 makes master
/// status a bootstrap-only property, and neither key payload can express the field at all — the
/// structs omit it and deny unknown fields, so serde refuses the request before any scope is
/// considered. A scope nobody can request does not need a rule about who may request it.
///
/// Each entry is a *path back to* master authority rather than a leaf capability:
///
/// - `can_manage_keys` is the scope that reaches every other key — granting it creates a second
///   administrator, so a non-master able to grant it could multiply itself without limit and, in
///   combination with any future gap in [`guard_master_target`], reach a master key.
/// - `can_create_groups` mints managed resources whose creator is auto-granted full read/write/delete
///   (`AGENT.MD` §2), which is the one way to obtain group access without a master signing off.
/// - `can_manage_webhooks` mints dispatch targets. This service's spelling of the specification's
///   `can_create_webhooks`, and the last of the three to be locked down: it was previously delegable
///   on the reasoning that it "confers no authority over keys or groups". That reasoning was too
///   narrow. A webhook is a standing export of everything that happens in a group to a URL its
///   creator chooses, and the scope was freely amplifiable — a parent that did **not** hold it could
///   hand it out (R1's plainest violation, since a caller may only grant rights it holds itself).
///
/// Because every global scope is now master-only, R1's "may only grant rights it currently holds"
/// is satisfied for globals by the strictly stronger R4: a non-master grants none of them at all.
const MASTER_ONLY_SCOPES: [&str; 3] =
    ["can_manage_keys", "can_create_groups", "can_manage_webhooks"];

/// Rejects any attempt by a non-master to grant one of [`MASTER_ONLY_SCOPES`].
///
/// `held` describes the target's current values, so this permits a no-op re-submission of a scope
/// the target already has (an idempotent `PUT` from a dashboard that posts every field) while still
/// refusing an actual elevation. Revoking is always allowed — removing authority is not escalation.
fn guard_scope_elevation(
    caller: &api_key::Model,
    requested: [Option<bool>; 3],
    held: [bool; 3],
) -> Result<(), AppError> {
    if caller.is_master {
        return Ok(());
    }

    for ((request, current), name) in
        requested.iter().zip(held.iter()).zip(MASTER_ONLY_SCOPES.iter())
    {
        if *request == Some(true) && !*current {
            tracing::warn!(
                "Blocked privilege escalation: key {} attempted to grant {}",
                caller.prefix,
                name
            );
            return Err(AppError::Forbidden(format!(
                "Only a master key can grant '{name}'"
            )));
        }
    }
    Ok(())
}

fn guard_master_target(caller: &api_key::Model, target: &api_key::Model) -> Result<(), AppError> {
    if target.is_master && !caller.is_master {
        tracing::warn!(
            "Blocked privilege escalation: key {} (master=false) attempted to operate on master key {}",
            caller.prefix,
            target.prefix
        );
        return Err(AppError::Forbidden(
            "Only a master key can modify, rotate, or delete another master key".to_owned(),
        ));
    }
    Ok(())
}

/// The refusal `RBAC_MODEL.md` §5 requires for every API operation on the Master key that is not an
/// edit of its own `bound_ips`.
///
/// "The Master key is immutable through the API **except for its own `bound_ips`** […] No other
/// field, permission, or rotation is reachable through the API," and "The Master key cannot be
/// deleted through the API." That covers deletion, both rotation endpoints, and every field of the
/// generic update except one — so the operations are named in the message rather than the caller
/// being left to guess which of several checks refused it.
///
/// This is strictly stronger than [`guard_master_target`], which only ever blocked *non*-masters and
/// therefore left the Master free to rotate, rename and re-scope itself. Uniqueness (§5, enforced by
/// the unique index over the engine-derived `master_marker`) means "the Master key" is unambiguous:
/// there is no second master for this to be relative to.
///
/// The dependency runs one way only. §5 requires that the Master's undeletability "must not rest on
/// the uniqueness constraint holding", and it does not: this guard refuses on the target row's own
/// `is_master`, so it would refuse each of two masters independently if a database ever held two.
///
/// # Why rotation is refused too, when it looks like routine hygiene
///
/// It reads like a regression — the one credential most worth rotating is the one that now cannot
/// be. But `POST /keys/{id}/rotate` returns the new plaintext in its response body, so an API-reachable
/// master rotation is an API-reachable way to *mint a working master credential* from any session
/// that already has one. The specification's answer is to take the operation out of the API surface
/// entirely: delete the row directly in the database and the service re-mints at next boot
/// (`bootstrap_master_key`). That is a deliberate trade of convenience for a smaller blast radius,
/// and it requires database access, which an HTTP-only compromise does not have.
fn guard_master_immutable(target: &api_key::Model, operation: &str) -> Result<(), AppError> {
    if !target.is_master {
        return Ok(());
    }

    tracing::warn!(
        "Blocked master mutation: attempt to {} master key {}",
        operation,
        target.prefix
    );
    Err(AppError::Forbidden(format!(
        "The master key is immutable through the API and cannot be {operation}. Only its own \
         bound_ips may be edited, by itself. To re-mint it, delete the row directly in the database \
         and restart the service."
    )))
}

// `guard_no_master_flag` used to live here. It took `payload.is_master: Option<bool>` and returned
// `400` whenever the field was present in either direction, satisfying `RBAC_MODEL.md` §5's
// "`is_master` must not be settable or clearable through any API endpoint".
//
// It is gone because §5 now says the field must be removed from the payload *type*, and "rejecting it
// at the handler is not sufficient, since a later handler can reintroduce the path". The guard was
// exactly that: correct, and one deleted line away from not existing. `CreateApiKeyPayload` and
// `UpdateApiKeyPayload` now omit the field and carry `#[serde(deny_unknown_fields)]`, so the request
// never reaches a handler at all — serde refuses it, and `StrictJson` renders that as the same `400`
// with serde's own field-level message.
//
// Do not reintroduce a handler-side check for this. A guard would be unreachable, and an unreachable
// guard reads like the control, which is how the next person deletes `deny_unknown_fields` believing
// something else still holds the line.

/// Helper to insert an audit log entry. `key` denormalizes the acting key's name/prefix into the
/// row so the audit trail stays legible even after that key is later deleted (its `api_key_id` FK
/// is `ON DELETE SET NULL`, per `SCHEMA.MD`, but the name/prefix survive as a point-in-time
/// snapshot rather than a live join). `client_ip` is the resolved caller address from
/// [`crate::middleware::ClientIp`].
async fn create_audit_log(
    db: &sea_orm::DatabaseConnection,
    key: Option<&api_key::Model>,
    client_ip: Option<std::net::IpAddr>,
    action: &str,
    target_address: Option<String>,
    group_names: Option<String>,
    details: Option<String>,
) -> Result<(), AppError> {
    let log = audit_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key.map(|k| k.id)),
        api_key_name: Set(key.map(|k| k.name.clone())),
        api_key_prefix: Set(key.map(|k| k.prefix.clone())),
        client_ip: Set(client_ip.map(|ip| ip.to_string())),
        action: Set(action.to_owned()),
        target_address: Set(target_address),
        group_names: Set(group_names),
        details: Set(details),
        timestamp: Set(Utc::now().naive_utc()),
    };
    audit_log::Entity::insert(log).exec(db).await?;
    Ok(())
}

/// Fetches an `IpGroup` by name, creating it with `default_group_type` if it doesn't exist yet.
///
/// Concurrency-safe: naively doing a `find` followed by a plain `insert` races when two requests
/// both observe the group as missing and both try to create it — `ip_groups.name` is unique, so
/// the loser gets a raw constraint-violation `500` instead of just using the winner's row. This
/// uses `on_conflict(...).do_nothing()` for the insert and always re-reads by name afterwards, so
/// either outcome (we created it, or a concurrent request beat us to it) converges on the same
/// canonical row.
///
/// `owner` becomes the group's `owner_key_id` when this call is the one that creates it, per §3.
/// When a concurrent request wins the race the existing row's owner is left alone — ownership belongs
/// to whoever actually created the resource, and the loser of a race did not.
async fn get_or_create_group(
    db: &sea_orm::DatabaseConnection,
    name: &str,
    default_group_type: &str,
    owner: Option<Uuid>,
) -> Result<ip_group::Model, AppError> {
    let new_group = ip_group::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(name.to_owned()),
        group_type: Set(default_group_type.to_owned()),
        description: Set(None),
        owner_key_id: Set(owner),
        created_at: Set(Utc::now().naive_utc()),
    };
    ip_group::Entity::insert(new_group)
        .on_conflict(OnConflict::column(ip_group::Column::Name).do_nothing().to_owned())
        .exec_without_returning(db)
        .await?;

    ip_group::Entity::find()
        .filter(ip_group::Column::Name.eq(name))
        .one(db)
        .await?
        .ok_or(AppError::Internal)
}

/// Resolves a group given an optional `group_id` and/or `group_name`; exactly one must be
/// supplied. Returns `Ok(None)` if the identifier doesn't match any existing group — the caller
/// decides whether that means "404" (for `group_id`, which is never client-inventable) or
/// "auto-create it" (for `group_name`, the only identifier a client can pick with permission).
async fn resolve_group_ref(
    db: &sea_orm::DatabaseConnection,
    group_id: Option<Uuid>,
    group_name: Option<&str>,
) -> Result<Option<ip_group::Model>, AppError> {
    match (group_id, group_name) {
        (Some(_), Some(_)) => Err(AppError::InvalidInput(
            "Provide either group_id or group_name, not both".to_owned(),
        )),
        (None, None) => Err(AppError::InvalidInput(
            "Either group_id or group_name is required".to_owned(),
        )),
        (Some(gid), None) => Ok(ip_group::Entity::find_by_id(gid).one(db).await?),
        (None, Some(name)) => Ok(ip_group::Entity::find()
            .filter(ip_group::Column::Name.eq(name))
            .one(db)
            .await?),
    }
}

/// Resolves a group from a single path segment that may be either a UUID or a literal name —
/// used for the `DELETE .../permissions/{group_identifier}` route, where REST path conventions
/// only allow one placeholder rather than separate `group_id`/`group_name` fields.
async fn resolve_group_by_identifier(
    db: &sea_orm::DatabaseConnection,
    identifier: &str,
) -> Result<Option<ip_group::Model>, AppError> {
    if let Ok(id) = Uuid::parse_str(identifier)
        && let Some(g) = ip_group::Entity::find_by_id(id).one(db).await?
    {
        return Ok(Some(g));
    }
    Ok(ip_group::Entity::find()
        .filter(ip_group::Column::Name.eq(identifier))
        .one(db)
        .await?)
}

/// Resolves a group given an optional flexible `group_id` and/or `group_name`; exactly one must
/// be supplied. Unlike [`resolve_group_ref`], `group_id` here is a plain string rather than a
/// strictly-typed UUID: a client that passes a group's name into the `group_id` field (or a UUID
/// into it, which also works) gets a correct lookup instead of Axum rejecting the request with a
/// `422` before this code ever runs. Never auto-creates via `group_id`, matching
/// [`resolve_group_by_identifier`]'s semantics — only `group_name` can create.
async fn resolve_group_ref_flexible(
    db: &sea_orm::DatabaseConnection,
    group_id: Option<&str>,
    group_name: Option<&str>,
) -> Result<Option<ip_group::Model>, AppError> {
    match (group_id, group_name) {
        (Some(_), Some(_)) => Err(AppError::InvalidInput(
            "Provide either group_id or group_name, not both".to_owned(),
        )),
        (None, None) => Err(AppError::InvalidInput(
            "Either group_id or group_name is required".to_owned(),
        )),
        (Some(identifier), None) => resolve_group_by_identifier(db, identifier).await,
        (None, Some(name)) => Ok(ip_group::Entity::find()
            .filter(ip_group::Column::Name.eq(name))
            .one(db)
            .await?),
    }
}

// ─────────────────────────────────────────────────────────────
// IP Ban / Whitelist
// ─────────────────────────────────────────────────────────────

/// Payload for banning or whitelisting an IP address
#[derive(Deserialize)]
pub struct BanWhitePayload {
    /// The target IP address or CIDR range
    pub target_address: String,
    /// The group to associate the IP with, by ID. Provide this or `group_name`, not both.
    pub group_id: Option<Uuid>,
    /// The group to associate the IP with, by name. Provide this or `group_id`, not both. Unlike
    /// `group_id`, a name that doesn't exist yet may be auto-created (permission allowing).
    pub group_name: Option<String>,
    /// The reason for the ban or whitelist
    pub cause: Option<String>,
}

/// Handles POST /api/v1/ban to add an IP to a banlist group
pub async fn handle_ban(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Json(payload): Json<BanWhitePayload>,
) -> Result<impl IntoResponse, AppError> {
    handle_ip_upsert(state, key, client_ip.0, payload, false).await
}

/// Handles POST /api/v1/white to add an IP to a whitelist group
pub async fn handle_white(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Json(payload): Json<BanWhitePayload>,
) -> Result<impl IntoResponse, AppError> {
    handle_ip_upsert(state, key, client_ip.0, payload, true).await
}

async fn handle_ip_upsert(
    state: AppState,
    key: api_key::Model,
    client_ip: std::net::IpAddr,
    payload: BanWhitePayload,
    is_whitelist: bool,
) -> Result<impl IntoResponse, AppError> {
    let network: IpNetwork = payload.target_address.parse()
        .map_err(|_| AppError::InvalidInput("Invalid IP or CIDR format".to_owned()))?;
    // Canonicalized once, up front, and used for every lookup/storage/event below instead of the
    // raw client-submitted string — otherwise "X/32" and "X" would be treated as different
    // addresses (two ip_records rows, a "not found" on delete, etc.) despite meaning the same
    // thing.
    let normalized_address = normalize_ip_or_cidr(&payload.target_address);

    if !is_whitelist {
        let ip = network.network();
        if ip.is_loopback() || ip.is_unspecified() {
             return Err(AppError::InvalidInput("Cannot ban loopback or unspecified addresses".to_owned()));
        }
        match ip {
            std::net::IpAddr::V4(v4) => {
                if v4.is_private() || v4.is_link_local() {
                     return Err(AppError::InvalidInput("Cannot ban private or link-local IPv4 addresses".to_owned()));
                }
            }
            std::net::IpAddr::V6(v6) => {
                let is_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
                let is_unique_local = (v6.segments()[0] & 0xfe00) == 0xfc00;
                if is_link_local || is_unique_local {
                     return Err(AppError::InvalidInput("Cannot ban link-local or unique-local IPv6 addresses".to_owned()));
                }
            }
        }
    }

    let target_group_id: Uuid;
    let resolved_group_name: String;

    let existing_group = resolve_group_ref(&state.db, payload.group_id, payload.group_name.as_deref()).await?;

    if let Some(g) = existing_group {
        target_group_id = g.id;
        resolved_group_name = g.name;

        if !key.is_master {
            let perm = api_key_group_permission::Entity::find()
                .filter(
                    Condition::all()
                        .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                        .add(api_key_group_permission::Column::GroupId.eq(target_group_id))
                )
                .one(&state.db)
                .await?;

            if let Some(p) = perm {
                if !p.can_write {
                    return Err(AppError::Forbidden("Permission denied: You do not have write access to this group".to_owned()));
                }
            } else {
                return Err(AppError::Forbidden("Permission denied: You have no access strictly mapped to this group".to_owned()));
            }
        }

        // Group-type validation runs strictly AFTER the RBAC check above (and unconditionally,
        // even for master keys, which bypass that check but not this one): a caller with no
        // access to the group must learn nothing about it — including its type — via a 400
        // instead of the 403 they should actually get.
        if is_whitelist && g.group_type == "banlist" {
            return Err(AppError::InvalidInput(format!(
                "Cannot whitelist IP into group '{resolved_group_name}': group type is 'banlist'. Use /api/ban or target a whitelist group."
            )));
        }
        if !is_whitelist && g.group_type == "whitelist" {
            return Err(AppError::InvalidInput(format!(
                "Cannot ban IP into group '{resolved_group_name}': group type is 'whitelist'. Use /api/white or target a banlist group."
            )));
        }
    } else if let Some(group_name) = &payload.group_name {
        // group_id (if given) is never auto-creatable — only reachable here when group_name was
        // supplied instead, since resolve_group_ref requires exactly one of the two.
        if !key.is_master && !key.can_create_groups {
            return Err(AppError::Forbidden("Permission denied: Target group does not exist and you cannot create groups".to_owned()));
        }

        let default_type = if is_whitelist { "whitelist" } else { "banlist" };
        let group = get_or_create_group(&state.db, group_name, default_type, resource_owner(&key)).await?;
        target_group_id = group.id;
        resolved_group_name = group.name;

        if !key.is_master {
            let now = Utc::now().naive_utc();
            let perm = api_key_group_permission::ActiveModel {
                id: Set(Uuid::new_v4()),
                api_key_id: Set(key.id),
                group_id: Set(target_group_id),
                can_read: Set(true),
                can_write: Set(true),
                can_delete: Set(true),
                // Auto-provisioning confers read/write/delete and nothing more, per `AGENT.MD` §2.
                // `can_manage` is administrative authority over other keys' rows, so it stays an
                // explicit grant from someone who already holds it rather than something a key
                // awards itself as a side effect of creating a group.
                can_manage: Set(false),
                created_at: Set(now),
            };
            // on_conflict do_nothing: a concurrent burst from this same key racing to create the
            // same new group would otherwise hit the (api_key_id, group_id) unique index here too.
            api_key_group_permission::Entity::insert(perm)
                .on_conflict(
                    OnConflict::columns([api_key_group_permission::Column::ApiKeyId, api_key_group_permission::Column::GroupId])
                        .do_nothing()
                        .to_owned()
                )
                .exec_without_returning(&state.db)
                .await?;
        }
    } else {
        // group_id was supplied but doesn't match any existing group. Unlike group_name, an ID
        // is never something a client can legitimately invent, so there's nothing to create.
        return Err(AppError::NotFound);
    }

    let now = Utc::now().naive_utc();
    let record_id: Uuid;

    // find-then-insert races under true concurrency: two requests can both see no existing
    // record and both attempt to insert the same (unique) target_address. Rather than trying to
    // cram the is_locked check and "only overwrite cause if provided" semantics into a single
    // atomic ON CONFLICT DO UPDATE, retry as a normal update on the one specific, portably
    // detectable failure mode that means "a concurrent request just won this race": a unique
    // constraint violation on the insert. At most one retry is possible — by the time it fires,
    // the winning request's row is already committed (SeaORM/sqlx pool this DB to a single
    // connection for SQLite, so operations are fully serialized).
    loop {
        let existing_record = ip_record::Entity::find()
            .filter(ip_record::Column::TargetAddress.eq(normalized_address.clone()))
            .one(&state.db)
            .await?;

        if let Some(record) = existing_record {
            if record.is_locked {
                return Err(AppError::Forbidden("This IP is protected and cannot be modified".to_owned()));
            }

            // Re-registering a soft-deleted address resurrects it. The alternative — refusing, or
            // silently re-adding a row that stays hidden — would make `target_address`'s unique
            // constraint into a denial: an address someone deleted last week could never be banned
            // again until a master emptied the trash. The deletion metadata is cleared so the
            // record is indistinguishable from one that was never deleted, and its 92-day
            // retention clock does not keep running against a now-live record.
            let was_deleted = record.is_deleted;

            let mut active_rec: ip_record::ActiveModel = record.into();
            active_rec.last_seen_at = Set(now);
            active_rec.updated_at = Set(now);
            if was_deleted {
                active_rec.is_deleted = Set(false);
                active_rec.deleted_at = Set(None);
                active_rec.deleted_by = Set(None);
            }
            if let Some(c) = &payload.cause {
                active_rec.cause = Set(Some(c.clone()));
            }
            let updated = active_rec.update(&state.db).await?;
            record_id = updated.id;
            if was_deleted {
                tracing::info!(
                    address = %normalized_address,
                    "Re-registration restored a soft-deleted IP record"
                );
            }
            break;
        }

        let new_id = Uuid::new_v4();
        let model = ip_record::ActiveModel {
            id: Set(new_id),
            target_address: Set(normalized_address.clone()),
            cause: Set(payload.cause.clone()),
            is_locked: Set(false),
            created_at: Set(now),
            updated_at: Set(now),
            last_seen_at: Set(now),
            is_deleted: Set(false),
            deleted_at: Set(None),
            deleted_by: Set(None),
        };
        match ip_record::Entity::insert(model).exec(&state.db).await {
            Ok(_) => {
                record_id = new_id;
                break;
            }
            Err(err) if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
                continue;
            }
            Err(err) => return Err(err.into()),
        }
    }

    let mem = ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record_id),
        group_id: Set(target_group_id),
    };
    // `exec_without_returning` is required here (not `exec`): when `DO NOTHING` actually
    // suppresses the insert because the membership already exists, there is no row to return,
    // and SeaORM's `exec` treats that as `DbErr::RecordNotInserted` ("None of the records are
    // inserted") instead of the no-op success it actually is. For a single-row `Insert`, it
    // returns the affected-row count directly as a `u64`, which doubles as the add-vs-update
    // signal below: 1 means this (address, group) pairing is genuinely new, 0 means `DO NOTHING`
    // suppressed it because the address was already a member of this exact group.
    let mem_result = ip_record_group_membership::Entity::insert(mem)
        .on_conflict(
            OnConflict::columns([ip_record_group_membership::Column::IpRecordId, ip_record_group_membership::Column::GroupId])
                .do_nothing()
                .to_owned()
        )
        .exec_without_returning(&state.db)
        .await?;

    // Deliberately keyed off the *membership* being new, not the underlying `ip_record` row: an
    // address already banned in Group A that now also gets added to Group B is an `IP_ADD` from
    // Group B's perspective (and Group B's webhooks) even though the `ip_record` row itself
    // already existed — only a re-registration into a group it's *already* a member of is a true
    // `IP_UPDATE`.
    let action = if mem_result > 0 { "IP_ADD" } else { "IP_UPDATE" };

    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip),
        action,
        Some(normalized_address.clone()),
        Some(resolved_group_name),
        Some(format!("Added IP to group. Whitelist: {}", is_whitelist))
    ).await?;

    let event = WebhookEvent {
        action: action.to_owned(),
        address: normalized_address,
        is_whitelist,
        group_id: Some(target_group_id),
        cause: payload.cause,
    };
    let _ = state.webhook_tx.send(event).await;

    Ok(axum::http::StatusCode::OK)
}

// ─────────────────────────────────────────────────────────────
// IP Record Listing & Deletion
// ─────────────────────────────────────────────────────────────

/// Query parameters for IP listing
#[derive(Deserialize)]
pub struct QueryFilters {
    /// Filter by groups (comma-separated group names)
    pub groups: Option<String>,
    /// Filter by a single group name (in addition to `groups`)
    pub group_name: Option<String>,
    /// Filter by a single group ID (in addition to `groups`/`group_name`)
    pub group_id: Option<Uuid>,
    /// Filter by a substring of the target address
    pub ip: Option<String>,
    /// Filter by a substring of the cause
    pub cause: Option<String>,
    /// Filter by group type: `ban`/`banlist` or `white`/`whitelist`
    pub status: Option<String>,
    /// Maximum age in seconds, based on `last_seen_at`
    pub max_age: Option<i64>,
    /// Only return records last seen at or after this Unix timestamp (seconds)
    pub since: Option<i64>,
    /// Pagination limit
    pub limit: Option<u64>,
    /// Pagination offset
    pub offset: Option<u64>,
    /// When set to `"iplist"` (accepted under either query key), returns a lightweight
    /// `{"ip_list": [...]}` payload of just the matched addresses instead of full records.
    pub format: Option<String>,
    /// Synonym for `format` — `format=iplist` and `mode=iplist` are both accepted.
    pub mode: Option<String>,
    /// Master-only: also return soft-deleted records (the "trash" view).
    ///
    /// Ignored for non-master callers rather than rejected — a scoped key asking for the trash is
    /// asking for something it has no concept of, and answering `403` would tell it the flag
    /// exists. It simply gets the normal, live-only listing.
    pub include_deleted: Option<bool>,
}

/// Response payload for a single IP record
#[derive(Serialize)]
pub struct IpRecordResponse {
    /// IP Record ID
    pub id: Uuid,
    /// Target address
    pub target_address: String,
    /// Associated group name
    pub group_name: String,
    /// Associated group type (`banlist` or `whitelist`)
    pub group_type: String,
    /// Cause for addition
    pub cause: Option<String>,
    /// Lock status
    pub is_locked: bool,
    /// Created at
    pub created_at: chrono::NaiveDateTime,
    /// Updated at
    pub updated_at: chrono::NaiveDateTime,
    /// Last seen at
    pub last_seen_at: chrono::NaiveDateTime,
    /// Whether the record is soft-deleted. Always `false` in a normal listing; only ever `true`
    /// in a master's `include_deleted=true` view.
    pub is_deleted: bool,
    /// When it was soft-deleted, if it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<chrono::NaiveDateTime>,
    /// Which API key soft-deleted it, if it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_by: Option<String>,
}

/// Handles GET /api/v1/ips to list IP records
pub async fn list_ips(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Query(filters): Query<QueryFilters>,
) -> Result<impl IntoResponse, AppError> {

    // Manual join fetching because of M:N
    let mut query = ip_record_group_membership::Entity::find()
        .find_also_related(ip_record::Entity);

    // Soft-deleted records are invisible unless a master explicitly asks for the trash. Applied
    // here, before every other filter, so no later branch can accidentally reintroduce them —
    // including the `iplist` export format, which shares this query.
    let include_deleted = key.is_master && filters.include_deleted.unwrap_or(false);
    if !include_deleted {
        query = query.filter(ip_record::Column::IsDeleted.eq(false));
    }

    if !key.is_master {
        let accessible_groups: Vec<Uuid> = api_key_group_permission::Entity::find()
            .filter(
                Condition::all()
                    .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                    .add(api_key_group_permission::Column::CanRead.eq(true))
            )
            .all(&state.db)
            .await?
            .into_iter()
            .map(|p| p.group_id)
            .collect();

        if accessible_groups.is_empty() {
            return Ok(Json(Vec::<IpRecordResponse>::new()).into_response());
        }

        query = query.filter(ip_record_group_membership::Column::GroupId.is_in(accessible_groups));
    }

    // `groups` (comma-separated) and `group_name` (single) both narrow by group name.
    let mut group_names: Vec<String> = Vec::new();
    if let Some(groups) = &filters.groups
        && !groups.is_empty()
    {
        group_names.extend(groups.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()));
    }
    if let Some(name) = &filters.group_name {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            group_names.push(trimmed.to_owned());
        }
    }
    // `group_id` narrows the same way, just by ID instead of by name; combined with any
    // name-based matches above using OR semantics (both are just ways to pick "these groups").
    let mut gids: Vec<Uuid> = Vec::new();
    let mut group_filter_requested = false;
    if !group_names.is_empty() {
        group_filter_requested = true;
        gids.extend(
            ip_group::Entity::find()
                .filter(ip_group::Column::Name.is_in(group_names))
                .all(&state.db)
                .await?
                .into_iter()
                .map(|g| g.id),
        );
    }
    if let Some(gid) = filters.group_id {
        group_filter_requested = true;
        gids.push(gid);
    }
    if group_filter_requested {
        query = query.filter(ip_record_group_membership::Column::GroupId.is_in(gids));
    }

    if let Some(status) = &filters.status
        && !status.is_empty()
    {
        let group_type = match status.as_str() {
            "ban" | "banlist" => "banlist",
            "white" | "whitelist" => "whitelist",
            other => return Err(AppError::InvalidInput(format!("Invalid status filter: {other}"))),
        };
        let gids: Vec<Uuid> = ip_group::Entity::find()
            .filter(ip_group::Column::GroupType.eq(group_type))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|g| g.id)
            .collect();
        query = query.filter(ip_record_group_membership::Column::GroupId.is_in(gids));
    }

    if let Some(ip) = &filters.ip
        && !ip.is_empty()
    {
        // Best-effort: if the filter value happens to be a full, parseable address/CIDR (e.g. a
        // caller pastes "188.190.74.128/32" to look up a record stored as the bare host form),
        // normalize it so the substring match still finds it. A genuine partial fragment like
        // "74.128" doesn't parse and passes through unchanged, preserving substring search.
        query = query.filter(ip_record::Column::TargetAddress.contains(normalize_ip_or_cidr(ip.trim())));
    }

    if let Some(cause) = &filters.cause
        && !cause.is_empty()
    {
        query = query.filter(ip_record::Column::Cause.contains(cause.trim()));
    }

    if let Some(age) = filters.max_age {
        let threshold = Utc::now().naive_utc() - chrono::Duration::seconds(age);
        query = query.filter(ip_record::Column::LastSeenAt.gte(threshold));
    }

    if let Some(since) = filters.since {
        let threshold = chrono::DateTime::from_timestamp(since, 0)
            .ok_or_else(|| AppError::InvalidInput("Invalid `since` timestamp".to_owned()))?
            .naive_utc();
        query = query.filter(ip_record::Column::LastSeenAt.gte(threshold));
    }

    let limit = filters.limit.unwrap_or(50);
    let offset = filters.offset.unwrap_or(0);

    // Latest activity first: whichever record was most recently added or re-registered (a ban
    // "renewed" by a fresh match) sorts to the top, matching AGENT.MD's ordering requirement.
    let memberships = query
        .order_by_desc(ip_record::Column::UpdatedAt)
        .limit(limit)
        .offset(offset)
        .all(&state.db)
        .await?;

    let format_iplist = matches!(filters.format.as_deref(), Some("iplist"))
        || matches!(filters.mode.as_deref(), Some("iplist"));
    if format_iplist {
        // Lightweight path: skip the per-row group lookup below entirely (not needed for a flat
        // address list), and de-duplicate — an address matched via multiple group memberships in
        // the same query would otherwise appear once per membership.
        let mut ip_list: Vec<String> = memberships
            .into_iter()
            .filter_map(|(_, record_opt)| record_opt.map(|r| r.target_address))
            .collect();
        ip_list.sort();
        ip_list.dedup();
        return Ok(Json(serde_json::json!({ "ip_list": ip_list })).into_response());
    }

    let mut items = Vec::with_capacity(memberships.len());
    for (mem, record_opt) in memberships {
        let Some(record) = record_opt else { continue };
        let Some(group) = ip_group::Entity::find_by_id(mem.group_id).one(&state.db).await? else {
            continue;
        };

        items.push(IpRecordResponse {
            id: record.id,
            target_address: record.target_address,
            group_name: group.name,
            group_type: group.group_type,
            cause: record.cause,
            is_locked: record.is_locked,
            created_at: record.created_at,
            updated_at: record.updated_at,
            last_seen_at: record.last_seen_at,
            is_deleted: record.is_deleted,
            deleted_at: record.deleted_at,
            deleted_by: record.deleted_by,
        });
    }

    Ok(Json(items).into_response())
}

/// Whether the caller may act on a record, given its group memberships.
///
/// A record can belong to several groups; the caller needs `can_delete` on **at least one** of
/// them, which is the same rule the group-scoped `DELETE /api/ips` applies. Master keys short-
/// circuit. A record with no memberships at all (orphaned by a group deletion) is master-only,
/// since there is no group left to derive authority from.
async fn caller_may_delete_record(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    record_id: Uuid,
) -> Result<bool, AppError> {
    if key.is_master {
        return Ok(true);
    }

    let group_ids: Vec<Uuid> = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IpRecordId.eq(record_id))
        .all(db)
        .await?
        .into_iter()
        .map(|m| m.group_id)
        .collect();

    if group_ids.is_empty() {
        return Ok(false);
    }

    let deletable = api_key_group_permission::Entity::find()
        .filter(
            Condition::all()
                .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                .add(api_key_group_permission::Column::GroupId.is_in(group_ids))
                .add(api_key_group_permission::Column::CanDelete.eq(true)),
        )
        .one(db)
        .await?;

    Ok(deletable.is_some())
}

/// Query parameters for [`delete_ip_record`].
#[derive(Deserialize, Default)]
pub struct DeleteRecordQuery {
    /// Master-only: drop the row outright instead of soft-deleting it.
    pub hard: Option<bool>,
}

/// Handles `DELETE /api/ips/{id}` — soft-deletes an IP record, or hard-deletes it for a master.
///
/// **Soft delete is the default and the only option for a non-master.** The row stays, marked
/// `is_deleted` with `deleted_at`/`deleted_by` set, and disappears from every read (see
/// [`list_ips`]) until a master restores it or [`crate::retention`] purges it after 92 days.
///
/// The reason a delegated key never gets a hard delete: `can_delete` on a group is a routine,
/// widely-handed-out scope, and the blast radius of it being misused — or of the key being stolen —
/// should be a recoverable mistake rather than permanent data loss. Making destruction master-only
/// costs a legitimate operator one extra step and costs an attacker the ability to cover their
/// tracks.
///
/// Distinct from `DELETE /api/ips` (query/body form), which removes a record's membership in **one
/// group** and leaves the record itself alone. This route acts on the record as a whole.
pub async fn delete_ip_record(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
    Query(params): Query<DeleteRecordQuery>,
) -> Result<impl IntoResponse, AppError> {
    let record = ip_record::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if !caller_may_delete_record(&state.db, &key, id).await? {
        return Err(AppError::Forbidden(
            "Permission denied: you have no delete access to any group holding this record".to_owned(),
        ));
    }

    if record.is_locked {
        return Err(AppError::Forbidden("Protected records cannot be deleted".to_owned()));
    }

    let hard = params.hard.unwrap_or(false);
    if hard && !key.is_master {
        return Err(AppError::Forbidden(
            "Only a master key can permanently delete an IP record".to_owned(),
        ));
    }

    let address = record.target_address.clone();

    if hard {
        ip_record::Entity::delete_by_id(id).exec(&state.db).await?;
        create_audit_log(
            &state.db,
            Some(&key),
            Some(client_ip.0),
            "IP_HARD_DELETE",
            Some(address.clone()),
            None,
            Some("Permanently deleted".to_owned()),
        )
        .await?;

        return Ok(Json(serde_json::json!({
            "id": id,
            "target_address": address,
            "deleted": "permanent",
        })));
    }

    // Already in the trash: report success without moving `deleted_at`, so a repeated call cannot
    // silently extend the retention window and keep a record out of the purge indefinitely.
    if record.is_deleted {
        return Ok(Json(serde_json::json!({
            "id": id,
            "target_address": address,
            "deleted": "soft",
            "already_deleted": true,
        })));
    }

    let now = Utc::now().naive_utc();
    let mut active: ip_record::ActiveModel = record.into();
    active.is_deleted = Set(true);
    active.deleted_at = Set(Some(now));
    active.deleted_by = Set(Some(key.id.to_string()));
    active.updated_at = Set(now);
    active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip.0),
        "IP_SOFT_DELETE",
        Some(address.clone()),
        None,
        Some(format!("Soft-deleted by key {}", format_key_reference(&key.name, key.id))),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "id": id,
        "target_address": address,
        "deleted": "soft",
        "already_deleted": false,
    })))
}

/// Handles `POST /api/ips/{id}/restore` — brings a soft-deleted record back. Master only.
///
/// Restoration is master-only even though a delegated key could have caused the deletion: the whole
/// point of the trash is that recovering from a compromised or careless key does not depend on that
/// same key's authority.
pub async fn restore_ip_record(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only a master key can restore a deleted IP record".to_owned(),
        ));
    }

    let record = ip_record::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if !record.is_deleted {
        return Err(AppError::InvalidInput(
            "This IP record is not deleted; nothing to restore".to_owned(),
        ));
    }

    let address = record.target_address.clone();
    let now = Utc::now().naive_utc();

    // The deletion metadata is cleared, not just the flag: leaving a stale `deleted_at` behind
    // would leave the record one flag-flip away from being purged as if it had been in the trash
    // all along.
    let mut active: ip_record::ActiveModel = record.into();
    active.is_deleted = Set(false);
    active.deleted_at = Set(None);
    active.deleted_by = Set(None);
    active.updated_at = Set(now);
    let restored = active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip.0),
        "IP_RESTORE",
        Some(address.clone()),
        None,
        Some("Restored from soft delete".to_owned()),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "id": restored.id,
        "target_address": address,
        "is_deleted": false,
        "restored": true,
    })))
}

/// Body for [`purge_ip_records`]. Optional; an empty body uses the configured retention window.
#[derive(Deserialize, Default)]
pub struct PurgeIpsPayload {
    /// Override the retention window for this sweep only, in days.
    ///
    /// `0` is rejected rather than treated as "purge everything": the difference between "empty the
    /// trash" and "empty the trash older than zero days" is one character, and the destructive
    /// reading should never be the one a typo selects.
    pub older_than_days: Option<i64>,
}

/// Handles `POST /api/system/purge-ips` — permanently drops soft-deleted records past retention.
///
/// Master only, and irreversible. Runs the same sweep as the background worker
/// ([`crate::retention::purge_expired_ip_records`]), exposed as an endpoint so an operator can
/// reclaim space or honour a deletion request without waiting for the next tick.
pub async fn purge_ip_records(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only a master key can purge deleted IP records".to_owned(),
        ));
    }

    let payload: PurgeIpsPayload = if body.is_empty() {
        PurgeIpsPayload::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| AppError::InvalidInput(format!("Invalid JSON body: {e}")))?
    };

    let retention_days = match payload.older_than_days {
        None => crate::retention::retention_days_from_env(),
        Some(days) if days > 0 => days,
        Some(days) => {
            return Err(AppError::InvalidInput(format!(
                "older_than_days must be a positive number of days, got {days}"
            )));
        }
    };

    let purged = crate::retention::purge_expired_ip_records(&state.db, retention_days).await?;

    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip.0),
        "IP_PURGE",
        None,
        None,
        Some(format!("Purged {purged} record(s) soft-deleted over {retention_days} days ago")),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "purged": purged,
        "retention_days": retention_days,
    })))
}

/// Parameters for deleting an IP record from a group. Every field is optional here because this
/// same shape is used to parse both the URL query string and an optional JSON body — the handler
/// merges the two and only then checks that the required combination was actually supplied.
#[derive(Deserialize, Default)]
pub struct DeleteIpQuery {
    /// IP to delete
    pub target_address: Option<String>,
    /// Group to delete from, by ID. Provide this or `group_name`, not both.
    pub group_id: Option<Uuid>,
    /// Group to delete from, by name. Provide this or `group_id`, not both.
    pub group_name: Option<String>,
}

impl DeleteIpQuery {
    /// Fills in any field left `None` by `self` with the corresponding field from `other`.
    fn merge(self, other: DeleteIpQuery) -> DeleteIpQuery {
        DeleteIpQuery {
            target_address: self.target_address.or(other.target_address),
            group_id: self.group_id.or(other.group_id),
            group_name: self.group_name.or(other.group_name),
        }
    }
}

/// Handles DELETE /api/v1/ips. Accepts `target_address` and `group_id`/`group_name` from the URL
/// query string, a JSON request body, or a mix of both (query values win on overlap) — some HTTP
/// clients refuse to attach a body to `DELETE`, others prefer a body over query-string params, so
/// this endpoint accommodates either without producing a deserialization error for either shape.
pub async fn delete_ip(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Query(query_params): Query<DeleteIpQuery>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let body_params: DeleteIpQuery = if body.is_empty() {
        DeleteIpQuery::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| AppError::InvalidInput(format!("Invalid JSON body: {e}")))?
    };
    let params = query_params.merge(body_params);

    let target_address = params
        .target_address
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::InvalidInput("target_address is required (query or JSON body)".to_owned()))?;
    // Canonicalize before the lookup below: a record banned as "X/32" must still be found (and
    // deletable) by a caller passing plain "X", and vice versa.
    let target_address = normalize_ip_or_cidr(&target_address);

    let group = resolve_group_ref(&state.db, params.group_id, params.group_name.as_deref())
        .await?
        .ok_or(AppError::NotFound)?;

    if !key.is_master {
        let perm = api_key_group_permission::Entity::find()
            .filter(
                Condition::all()
                    .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                    .add(api_key_group_permission::Column::GroupId.eq(group.id))
            )
            .one(&state.db)
            .await?;

        if let Some(p) = perm {
            if !p.can_delete {
                return Err(AppError::Forbidden("Permission denied: You do not have delete permissions over this group".to_owned()));
            }
        } else {
            return Err(AppError::Forbidden("Permission denied".to_owned()));
        }
    }

    let record = ip_record::Entity::find()
        .filter(ip_record::Column::TargetAddress.eq(&target_address))
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if record.is_locked {
        return Err(AppError::Forbidden("Protected records cannot be deleted".to_owned()));
    }

    let mem_result = ip_record_group_membership::Entity::delete_by_id((record.id, group.id))
        .exec(&state.db)
        .await?;

    if mem_result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip.0),
        "IP_DELETE",
        Some(target_address),
        Some(group.name.clone()),
        None
    ).await?;

    let event = WebhookEvent {
        action: "IP_DELETE".to_owned(),
        address: record.target_address.clone(),
        is_whitelist: group.group_type == "whitelist",
        group_id: Some(group.id),
        cause: Some("Deleted via API".to_owned()),
    };
    let _ = state.webhook_tx.send(event).await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// Auth Handlers
// ─────────────────────────────────────────────────────────────

/// Permission payload for a group
#[derive(Serialize)]
pub struct MePermission {
    /// Group ID
    pub group_id: Uuid,
    /// Group Name
    pub group_name: String,
    /// Can read
    pub can_read: bool,
    /// Can write
    pub can_write: bool,
    /// Can delete
    pub can_delete: bool,
    /// May administer this group's permission rows (revoke-only authority; see `AGENT.MD` §2)
    pub can_manage: bool,
}

/// Identity and permission payload returned to the client
#[derive(Serialize)]
pub struct MeResponse {
    /// API Key ID
    pub id: Uuid,
    /// Key Name
    pub name: String,
    /// Bound CIDRs
    pub bound_ips: Option<String>,
    /// Master status
    pub is_master: bool,
    /// Global key management
    pub can_manage_keys: bool,
    /// Global webhook management
    pub can_manage_webhooks: bool,
    /// Global group creation
    pub can_create_groups: bool,
    /// Granular permissions
    pub group_permissions: Vec<MePermission>,
}

/// Handles GET /api/v1/auth/me
pub async fn get_me(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {

    let perms = api_key_group_permission::Entity::find()
        .filter(api_key_group_permission::Column::ApiKeyId.eq(key.id))
        .find_also_related(ip_group::Entity)
        .all(&state.db)
        .await?;

    let mut group_permissions = Vec::new();
    for (p, g) in perms {
        if let Some(group) = g {
            group_permissions.push(MePermission {
                group_id: p.group_id,
                group_name: group.name,
                can_read: p.can_read,
                can_write: p.can_write,
                can_delete: p.can_delete,
                can_manage: p.can_manage,
            });
        }
    }

    Ok(Json(MeResponse {
        id: key.id,
        name: key.name,
        bound_ips: key.bound_ips,
        is_master: key.is_master,
        can_manage_keys: key.can_manage_keys,
        can_manage_webhooks: key.can_manage_webhooks,
        can_create_groups: key.can_create_groups,
        group_permissions,
    }))
}

// ─────────────────────────────────────────────────────────────
// Admin CRUD — API Keys
// ─────────────────────────────────────────────────────────────

/// Input to update group permissions
#[derive(Deserialize)]
pub struct GroupPermInput {
    /// Target group, by ID *or* by name (a plain string, not a strictly-typed UUID, so passing a
    /// name here doesn't trip Axum's deserialization). Provide this or `group_name`, not both.
    pub group_id: Option<String>,
    /// Target group, by name. Equivalent to putting a name into `group_id`; kept as a separate
    /// field for backward compatibility. Provide this or `group_id`, not both. A name that
    /// doesn't exist yet may be auto-created (permission allowing); an unresolvable `group_id`
    /// (whether UUID- or name-shaped) is a `404` instead — an identifier is never auto-created.
    pub group_name: Option<String>,
    /// Can read
    pub can_read: bool,
    /// Can write. Requires `can_read` (AGENT.MD least-privilege rule).
    pub can_write: bool,
    /// Can delete. Requires `can_read` (AGENT.MD least-privilege rule).
    pub can_delete: bool,
    /// May administer this group's permission rows — the resource-scoped revoke authority.
    ///
    /// Defaulted rather than required, so every client written before the column existed keeps
    /// working and its payloads mean exactly what they meant before: no administrative right.
    #[serde(default)]
    pub can_manage: bool,
}

/// Payload for creating an API Key.
///
/// `deny_unknown_fields` is a §5 control, not tidiness: it is what makes the *absence* of `is_master`
/// a refusal rather than a silent discard. Serde ignores unknown fields by default, so without it a
/// struct that simply lacks the field would accept `{"is_master": true}`, drop it, and report
/// success — the one outcome worse than either accepting or rejecting it. Paired with
/// [`crate::extract::StrictJson`], which renders the rejection as `400`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKeyPayload {
    /// Name
    pub name: String,
    /// Bound CIDRs
    pub bound_ips: Option<String>,
    // No `is_master`, and `deny_unknown_fields` above is what makes that absence mean something.
    // §5: "Removing the field from the payload type is required; rejecting it at the handler is not
    // sufficient, since a later handler can reintroduce the path." It briefly lived here as an
    // `Option<bool>` that a guard rejected — which worked, and put the only thing standing between a
    // payload and master status inside a function call any refactor could drop. Now the type cannot
    // carry it and serde refuses the request outright.
    /// Manage keys flag
    pub can_manage_keys: Option<bool>,
    /// Manage webhooks flag
    pub can_manage_webhooks: Option<bool>,
    /// Create groups flag
    pub can_create_groups: Option<bool>,
}

/// Response after creating API key
#[derive(Serialize)]
pub struct CreateApiKeyResponse {
    /// ID
    pub id: Uuid,
    /// Raw key string
    pub plaintext_key: String,
    /// The key's HMAC signing secret, for computing `X-Signature-256`. Returned **only** here, at
    /// creation: the stored copy is encrypted at rest (when `VAULT_ENCRYPTION_KEY` is set) and is
    /// never echoed by any read endpoint, so a caller that loses it must rotate the key.
    pub signing_secret: String,
    /// Name
    pub name: String,
    /// Bound ips
    pub bound_ips: Option<String>,
}

/// Handles POST /api/v1/keys
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // Nobody mints a master any more, master included. There is no check for it here because there is
    // nothing left to check: `CreateApiKeyPayload` cannot carry `is_master`, the request is refused
    // before this function runs, and the unique index over the engine-derived `master_marker` would
    // refuse a second row even if it were not (`RBAC_MODEL.md` §5).

    // Only a master key may mint a key carrying master-only scopes. Without this,
    // `can_manage_keys` was transitively equivalent to `is_master`: a key manager could create a
    // key with `can_manage_keys`, chain it, and reach every credential in the system.
    //
    // A brand-new key holds none of these, so `held` is all-false: every `true` here is a grant.
    guard_scope_elevation(
        &key,
        [payload.can_manage_keys, payload.can_create_groups, payload.can_manage_webhooks],
        [false, false, false],
    )?;

    if let Some(bips) = &payload.bound_ips {
        for cidr in bips.split(',') {
            let _ : IpNetwork = cidr.trim().parse()
                .map_err(|_| AppError::InvalidInput(format!("Invalid CIDR: {}", cidr)))?;
        }
    }

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let prefix = plaintext_key.chars().take(8).collect::<String>();
    // The signing secret is independent of the API key: leaking one must not compromise the other.
    let signing_secret = crate::crypto::generate_signing_secret();
    let stored_signing_secret = state.cipher.seal(&signing_secret)?;
    let id = Uuid::new_v4();
    let now = Utc::now().naive_utc();

    let model = api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(key_hash),
        signing_secret: Set(Some(stored_signing_secret)),
        name: Set(payload.name.clone()),
        prefix: Set(prefix),
        bound_ips: Set(payload.bound_ips.clone()),
        // Hardcoded, not derived from the payload: the field that once fed this is now rejected
        // above. The engine derives `master_marker` from this `false`, so the row leaves the marker
        // NULL and does not contend for the unique index — no application write is involved.
        is_master: Set(false),
        // R3: recorded for cascade deletion and visibility scoping, and read by no permission guard.
        // A daughter of the Master is an ordinary daughter key.
        parent_key_id: Set(Some(key.id)),
        can_manage_keys: Set(payload.can_manage_keys.unwrap_or(false)),
        can_manage_webhooks: Set(payload.can_manage_webhooks.unwrap_or(false)),
        can_create_groups: Set(payload.can_create_groups.unwrap_or(false)),
        created_at: Set(now),
        updated_at: Set(now),
    };

    api_key::Entity::insert(model).exec(&state.db).await?;
    
    create_audit_log(&state.db, Some(&key), Some(client_ip.0), "KEY_CREATE", None, None, Some(payload.name.clone())).await?;

    Ok(Json(CreateApiKeyResponse {
        id,
        plaintext_key,
        signing_secret,
        name: payload.name,
        bound_ips: payload.bound_ips,
    }))
}

/// Public-safe summary of an API key, in one of the two shapes `RBAC_MODEL.md` §4 allows a
/// non-master caller to see.
///
/// [`Self::view`] says which, and it is not decoration — the two shapes carry genuinely different
/// information, and a client that treats an absent field as `false` rather than as *withheld* will
/// draw a key as unprivileged when it may not be.
///
/// - **`"full"`** — a key inside the caller's own subtree. §4: "a parent sees its own key subtree in
///   full, minus raw secrets — its daughters, their granted rights, and their bound IPs." Everything
///   below is populated. `key_hash` and `signing_secret` are absent from this struct entirely and
///   always have been: the hash of a live credential has no reason to leave the server.
/// - **`"minimal"`** — a key visible *only* because it holds a permission row on a resource the
///   caller manages. §4: "a parent sees, in minimal form only, any key holding a permission row on a
///   resource it manages: id, name, and that key's rights on that resource alone. Global flags, bound
///   IPs, and unrelated resource memberships remain hidden. A single shared resource must never become
///   a keyhole into another parent's whole configuration." Only `id`, `name` and the rights **on the
///   shared groups themselves** are present.
///
/// A master sees every key in the `"full"` shape.
///
/// One wart, stated rather than hidden: `bound_ips` is `None` both when it is withheld (minimal view)
/// and when the key genuinely has no CIDR restriction (full view). [`Self::view`] disambiguates, and
/// that is what it is for.
#[derive(Serialize)]
pub struct ApiKeySummary {
    /// Key ID
    pub id: Uuid,
    /// Key name
    pub name: String,
    /// Which §4 visibility scope produced this entry: `"full"` or `"minimal"`.
    pub view: &'static str,
    /// First 8 characters of the plaintext key, for display/identification only. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Bound CIDRs. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_ips: Option<String>,
    /// Master flag. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_master: Option<bool>,
    /// Global key management scope. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_manage_keys: Option<bool>,
    /// Global webhook management scope. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_manage_webhooks: Option<bool>,
    /// Global group creation scope. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_create_groups: Option<bool>,
    /// The key that created this one. Full view only, and carries no authority (R3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_key_id: Option<Uuid>,
    /// Key creation timestamp. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::NaiveDateTime>,
    /// Per-group permissions. **All** of them in the full view; in the minimal view, only the rows on
    /// groups the caller itself manages.
    pub group_permissions: Vec<MePermission>,
}

/// The `"full"` view: everything about a key except its secrets.
async fn full_api_key_summary(
    db: &sea_orm::DatabaseConnection,
    k: api_key::Model,
) -> Result<ApiKeySummary, AppError> {
    let group_permissions = key_group_permissions(db, k.id, None).await?;

    Ok(ApiKeySummary {
        id: k.id,
        name: k.name,
        view: "full",
        prefix: Some(k.prefix),
        bound_ips: k.bound_ips,
        is_master: Some(k.is_master),
        can_manage_keys: Some(k.can_manage_keys),
        can_manage_webhooks: Some(k.can_manage_webhooks),
        can_create_groups: Some(k.can_create_groups),
        parent_key_id: k.parent_key_id,
        created_at: Some(k.created_at),
        group_permissions,
    })
}

/// The `"minimal"` view: id, name, and this key's rights on `visible_groups` and nothing else.
async fn minimal_api_key_summary(
    db: &sea_orm::DatabaseConnection,
    k: api_key::Model,
    visible_groups: &[Uuid],
) -> Result<ApiKeySummary, AppError> {
    let group_permissions = key_group_permissions(db, k.id, Some(visible_groups)).await?;

    Ok(ApiKeySummary {
        id: k.id,
        name: k.name,
        view: "minimal",
        prefix: None,
        bound_ips: None,
        is_master: None,
        can_manage_keys: None,
        can_manage_webhooks: None,
        can_create_groups: None,
        parent_key_id: None,
        created_at: None,
        group_permissions,
    })
}

/// One key's permission rows, optionally narrowed to a set of groups.
///
/// `Some(&[])` is a meaningful argument and returns nothing — a caller that manages no groups sees no
/// shared rows, which is different from `None` ("no filter, return everything").
async fn key_group_permissions(
    db: &sea_orm::DatabaseConnection,
    key_id: Uuid,
    only_groups: Option<&[Uuid]>,
) -> Result<Vec<MePermission>, AppError> {
    let mut condition =
        Condition::all().add(api_key_group_permission::Column::ApiKeyId.eq(key_id));
    if let Some(groups) = only_groups {
        condition = condition.add(api_key_group_permission::Column::GroupId.is_in(groups.to_vec()));
    }

    let perms = api_key_group_permission::Entity::find()
        .filter(condition)
        .find_also_related(ip_group::Entity)
        .all(db)
        .await?;

    Ok(perms
        .into_iter()
        .filter_map(|(p, g)| {
            g.map(|group| MePermission {
                group_id: p.group_id,
                group_name: group.name,
                can_read: p.can_read,
                can_write: p.can_write,
                can_delete: p.can_delete,
                can_manage: p.can_manage,
            })
        })
        .collect())
}

/// Every key at or below `root` in the `parent_key_id` tree, `root` included.
///
/// Iterative breadth-first rather than recursive, with a `visited` set: `parent_key_id` has no
/// database-level foreign key and nothing in the schema prevents a cycle, so a hand-edited row could
/// otherwise put this in an infinite loop — inside a request handler, holding a connection. The
/// visited set makes a cycle terminate at the cost of one extra pass instead of taking the process
/// down.
///
/// One query per level, not one per key: the level's ids go into a single `IN` clause against the
/// `idx-api_keys-parent_key_id` index added in §7's migration.
async fn collect_key_subtree(
    db: &sea_orm::DatabaseConnection,
    root: Uuid,
) -> Result<std::collections::HashSet<Uuid>, AppError> {
    let mut visited = std::collections::HashSet::from([root]);
    let mut frontier = vec![root];

    while !frontier.is_empty() {
        let children: Vec<Uuid> = api_key::Entity::find()
            .filter(api_key::Column::ParentKeyId.is_in(frontier.clone()))
            .all(db)
            .await?
            .into_iter()
            .map(|k| k.id)
            .collect();

        frontier = children.into_iter().filter(|id| visited.insert(*id)).collect();
    }

    Ok(visited)
}

/// The groups a caller *manages* in R2's sense — the ones whose shared keys it may see in minimal
/// form.
///
/// Deliberately the same test the write path uses (`can_manage_keys` globally **and** `can_manage` on
/// the row), so §4's "a resource it manages" and R2's "manage" cannot drift into meaning two
/// different things. A master manages everything and never reaches this.
async fn groups_the_caller_manages(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
) -> Result<Vec<Uuid>, AppError> {
    if !caller.can_manage_keys {
        return Ok(Vec::new());
    }

    Ok(api_key_group_permission::Entity::find()
        .filter(
            Condition::all()
                .add(api_key_group_permission::Column::ApiKeyId.eq(caller.id))
                .add(api_key_group_permission::Column::CanManage.eq(true)),
        )
        .all(db)
        .await?
        .into_iter()
        .map(|p| p.group_id)
        .collect())
}

/// Whether `target` is inside the caller's **own subtree** — the scope §4 grants full visibility over,
/// and the scope every credential-level operation on another key is bounded by.
///
/// Distinct from the shared-resource scope on purpose. §4 lets a parent see, in minimal form, a key
/// that merely shares a resource it manages; it does not follow that the parent may rotate that key's
/// credential or rewrite its bound IPs. Seeing a name is not administering a credential, so
/// `update`/`delete`/`rotate`/`rotate-secret` use this and nothing wider.
async fn caller_can_administer_key(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
    target: Uuid,
) -> Result<bool, AppError> {
    if caller.is_master {
        return Ok(true);
    }
    Ok(collect_key_subtree(db, caller.id).await?.contains(&target))
}

/// Resolves a key-targeted request to its row, or to the `404` §4's oracle discipline requires.
///
/// §4: "Any key, resource, or dispatch target outside the caller's visibility scope must return the
/// identical status and body the service would return if that id did not exist."
///
/// This replaced a `403` that used to come from `guard_master_target`, whose stated reasoning was that
/// "the caller legitimately holds `can_manage_keys` and can already see the key in `GET /api/keys`".
/// That reasoning was true when key listing was unscoped and is false now: a delegated manager no
/// longer sees the master, or anything outside its subtree, so a `403` here would confirm the
/// existence of a key the caller cannot otherwise observe. The master key is the obvious case — a
/// `403` on `POST /keys/{id}/rotate` was a way to enumerate it.
///
/// **This does not touch the authenticate-then-authorize ordering.** That rule governs *unauthenticated*
/// callers probing key bindings through `401`-vs-`403` and lives in the middleware; this one governs
/// *authenticated* callers distinguishing absent from invisible. §4 is explicit that both hold and
/// neither may be satisfied by regressing the other.
async fn find_administrable_key(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
    target: Uuid,
) -> Result<api_key::Model, AppError> {
    let key = ApiKey::find_by_id(target).one(db).await?.ok_or(AppError::NotFound)?;

    if !caller_can_administer_key(db, caller, target).await? {
        return Err(AppError::NotFound);
    }

    Ok(key)
}

/// Handles GET /api/v1/keys — **§4's three visibility scopes, in one listing.**
///
/// | Caller | Sees |
/// | :--- | :--- |
/// | Master | every key, `"full"` |
/// | `can_manage_keys` holder | its own subtree `"full"`, plus every key sharing a group it manages, `"minimal"` |
/// | anyone else | `403` — this is a key-administration endpoint |
///
/// # What this replaced
///
/// Every key in the system, in full, to any `can_manage_keys` holder: global flags, `bound_ips`, and
/// every group membership of every other tenant. §4 calls the shape out by name — "A single shared
/// resource must never become a keyhole into another parent's whole configuration" — and the previous
/// behaviour did not even require a shared resource. A delegated key manager scoped to one group could
/// read the entire installation's key inventory, which is a map of what to attack next.
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    if key.is_master {
        let keys = ApiKey::find().all(&state.db).await?;
        let mut summaries = Vec::with_capacity(keys.len());
        for k in keys {
            summaries.push(full_api_key_summary(&state.db, k).await?);
        }
        return Ok(Json(summaries));
    }

    let subtree = collect_key_subtree(&state.db, key.id).await?;
    let managed_groups = groups_the_caller_manages(&state.db, &key).await?;

    // Keys sharing a managed group. Empty when the caller manages nothing, which `is_in([])` already
    // expresses — but the query is skipped rather than issued, since "manages nothing" is the common
    // case for a scoped manager and there is no reason to ask the database about it.
    let shared: Vec<Uuid> = if managed_groups.is_empty() {
        Vec::new()
    } else {
        api_key_group_permission::Entity::find()
            .filter(api_key_group_permission::Column::GroupId.is_in(managed_groups.clone()))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|p| p.api_key_id)
            .filter(|id| !subtree.contains(id))
            .collect()
    };

    let mut summaries = Vec::new();
    for id in subtree {
        // A subtree member could have been deleted between the walk and here; skipping is correct
        // rather than erroring, and the caller sees the same list it would have a moment later.
        if let Some(k) = ApiKey::find_by_id(id).one(&state.db).await? {
            summaries.push(full_api_key_summary(&state.db, k).await?);
        }
    }
    let mut seen: std::collections::HashSet<Uuid> = summaries.iter().map(|s| s.id).collect();
    for id in shared {
        if !seen.insert(id) {
            continue;
        }
        if let Some(k) = ApiKey::find_by_id(id).one(&state.db).await? {
            summaries.push(minimal_api_key_summary(&state.db, k, &managed_groups).await?);
        }
    }

    Ok(Json(summaries))
}

/// One entity owned by a key inside the subtree being deleted, as it appears in §6's pre-flight
/// inventory.
///
/// §6 requires "enough detail to decide its fate: type, id, name, and current owner". `owner_name` is
/// carried alongside `owner_key_id` because the id alone is a UUID the caller would then have to go
/// and look up — and the keys it would look it up in are the ones about to be deleted.
#[derive(Serialize)]
pub struct OwnedEntity {
    /// `"group"` or `"webhook"` — the value a resolution entry must echo back.
    pub entity_type: &'static str,
    /// The entity's id, and the key of its resolution entry.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// The key inside the doomed subtree that owns it.
    pub owner_key_id: Uuid,
    /// That key's name.
    pub owner_name: String,
}

/// What to do with one inventoried entity.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Resolution {
    /// Destroy the entity along with the keys.
    Delete,
    /// Transfer it to a surviving key.
    Reassign {
        /// The new owner. Must exist, must not be the master, and must not itself be inside the
        /// subtree being deleted.
        owner_key_id: Uuid,
    },
}

/// One entry in the resolution map.
#[derive(Deserialize)]
pub struct ResolutionEntry {
    /// Must match the inventory entry's `entity_type`.
    pub entity_type: String,
    /// Must match the inventory entry's `id`.
    pub id: Uuid,
    /// What to do with it.
    #[serde(flatten)]
    pub resolution: Resolution,
}

/// Optional body for `DELETE /api/v1/keys/:id`.
#[derive(Deserialize, Default)]
pub struct DeleteKeyPayload {
    /// One entry per inventoried entity. Partial maps are refused.
    #[serde(default)]
    pub resolutions: Vec<ResolutionEntry>,
}

/// Every group and webhook owned by any key in `subtree`, with its owner's name resolved.
///
/// §6: "Before any key deletion, the service walks the entire subtree being deleted and collects every
/// resource and dispatch target owned by any key within it." **The entire subtree**, not just the
/// target — a daughter's webhooks would otherwise vanish silently when its parent is removed, which is
/// exactly what §6's "data is never destroyed implicitly" forbids.
async fn inventory_owned_entities(
    db: &sea_orm::DatabaseConnection,
    subtree: &[Uuid],
) -> Result<Vec<OwnedEntity>, AppError> {
    let owners: std::collections::HashMap<Uuid, String> = ApiKey::find()
        .filter(api_key::Column::Id.is_in(subtree.to_vec()))
        .all(db)
        .await?
        .into_iter()
        .map(|k| (k.id, k.name))
        .collect();
    let owner_name = |id: Uuid| owners.get(&id).cloned().unwrap_or_else(|| "<deleted>".to_owned());

    let mut inventory = Vec::new();

    for group in ip_group::Entity::find()
        .filter(ip_group::Column::OwnerKeyId.is_in(subtree.to_vec()))
        .all(db)
        .await?
    {
        // `is_in` cannot match a NULL, so the owner is `Some` by construction; the fallback keeps
        // this total rather than making an inventory walk panic.
        let owner = group.owner_key_id.unwrap_or_default();
        inventory.push(OwnedEntity {
            entity_type: "group",
            id: group.id,
            name: group.name,
            owner_key_id: owner,
            owner_name: owner_name(owner),
        });
    }

    for hook in webhook_config::Entity::find()
        .filter(webhook_config::Column::OwnerKeyId.is_in(subtree.to_vec()))
        .all(db)
        .await?
    {
        let owner = hook.owner_key_id.unwrap_or_default();
        inventory.push(OwnedEntity {
            entity_type: "webhook",
            id: hook.id,
            name: hook.name,
            owner_key_id: owner,
            owner_name: owner_name(owner),
        });
    }

    Ok(inventory)
}

/// Handles DELETE /api/v1/keys/:id — **§6's cascade, gated on the pre-flight inventory.**
///
/// # The shape of the operation
///
/// 1. Walk the target's entire `parent_key_id` subtree.
/// 2. Inventory every group and webhook owned by **any** key in it.
/// 3. If the inventory is non-empty and the request carries no resolution map, **refuse** with `409`
///    and the inventory itself — type, id, name, and current owner for each entity.
/// 4. On resubmission, require an explicit resolution for **every** inventoried entity. A partial map
///    is refused; so is one naming an entity that is not in the inventory.
/// 5. Only then delete: resolutions first, then the whole subtree.
///
/// # Why a refusal and not a cascade
///
/// §6: "Data is never destroyed implicitly. IP Groups, Hooks, IP Records, Webhook Configs, and
/// Executors must never disappear as a side effect of removing a key." Deleting a key is a routine
/// act of credential hygiene; deleting the banlist that key maintained is not, and the two must not be
/// spelled the same way. The refusal is what turns "remove this key" into a decision the caller makes
/// with the inventory in front of it.
///
/// The interim `ON DELETE SET NULL` this replaces — orphaning owned resources to unowned, and
/// daughters to root-level — is gone. Orphaning is not destruction, but it silently produced
/// resources only a master could ever act on again, and §6 asks for the decision instead.
///
/// # Which keys may be deleted at all
///
/// The subtree is resolved through [`find_administrable_key`], so a caller can only ever delete inside
/// its own subtree (§4). The caller itself, and the master, are refused explicitly rather than left to
/// the subtree walk: a caller is the root of its own subtree, and the master is in nobody's.
pub async fn delete_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    if id == key.id {
        return Err(AppError::Forbidden("Cannot delete yourself".to_owned()));
    }

    // `Bytes` rather than `Json<T>`: `DELETE` has always been callable with no body at all, and every
    // existing client calls it that way. `Json` rejects an empty body outright, so an optional
    // structured payload has to be parsed by hand — an empty body means "no resolutions", which is
    // the request that gets the inventory back.
    let payload: DeleteKeyPayload = if body.is_empty() {
        DeleteKeyPayload::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| {
            AppError::InvalidInput(format!("Invalid resolution map: {e}"))
        })?
    };

    let target = find_administrable_key(&state.db, &key, id).await?;
    guard_master_target(&key, &target)?;
    guard_master_immutable(&target, "deleted")?;
    let target_ref = format_key_reference(&target.name, id);

    let subtree: Vec<Uuid> = collect_key_subtree(&state.db, id).await?.into_iter().collect();
    // A cycle in `parent_key_id` (only reachable through direct database edits — the API always sets
    // the parent to a key that already exists) could otherwise put the caller inside the subtree of a
    // key it is deleting, and take its own credential with it.
    if subtree.contains(&key.id) {
        return Err(AppError::Conflict(
            "Refusing to delete: the subtree of this key contains your own key, which indicates a              cycle in parent_key_id. Resolve it directly in the database."
                .to_owned(),
        ));
    }

    let inventory = inventory_owned_entities(&state.db, &subtree).await?;

    if !inventory.is_empty() && payload.resolutions.is_empty() {
        return Err(AppError::ConflictWithDetails {
            message: format!(
                "Refusing to delete {target_ref}: {} owned entit{} in its subtree need an explicit                  resolution. Resubmit this request with a `resolutions` array assigning each one                  either {{\"action\":\"delete\"}} or {{\"action\":\"reassign\",\"owner_key_id\":\"…\"}}.",
                inventory.len(),
                if inventory.len() == 1 { "y" } else { "ies" }
            ),
            details: serde_json::json!({
                "subtree_key_count": subtree.len(),
                "owned_entities": inventory,
            }),
        });
    }

    // Every inventoried entity, exactly once, and nothing else. Checked before a single write, so a
    // rejected map leaves the installation untouched.
    let mut resolutions: std::collections::HashMap<(String, Uuid), &Resolution> =
        std::collections::HashMap::new();
    for entry in &payload.resolutions {
        if resolutions
            .insert((entry.entity_type.clone(), entry.id), &entry.resolution)
            .is_some()
        {
            return Err(AppError::InvalidInput(format!(
                "Duplicate resolution for {} {}",
                entry.entity_type, entry.id
            )));
        }
    }

    let missing: Vec<&OwnedEntity> = inventory
        .iter()
        .filter(|e| !resolutions.contains_key(&(e.entity_type.to_owned(), e.id)))
        .collect();
    if !missing.is_empty() {
        return Err(AppError::ConflictWithDetails {
            message: format!(
                "Refusing to delete {target_ref}: the resolution map is incomplete — {} entit{}                  unresolved. Partial maps are not applied.",
                missing.len(),
                if missing.len() == 1 { "y is" } else { "ies are" }
            ),
            details: serde_json::json!({ "unresolved": missing }),
        });
    }

    let inventoried: std::collections::HashSet<(String, Uuid)> =
        inventory.iter().map(|e| (e.entity_type.to_owned(), e.id)).collect();
    if let Some(extra) = resolutions.keys().find(|k| !inventoried.contains(*k)) {
        return Err(AppError::InvalidInput(format!(
            "Resolution names {} {}, which is not owned by any key in this subtree",
            extra.0, extra.1
        )));
    }

    // Validate every reassignment target before applying any of them. Reassigning to a key inside the
    // doomed subtree is refused specifically: it looks like a rescue and is a delayed deletion.
    let doomed: std::collections::HashSet<Uuid> = subtree.iter().copied().collect();
    for resolution in resolutions.values() {
        if let Resolution::Reassign { owner_key_id } = resolution {
            resolve_owner_assignment(&state.db, Some(*owner_key_id)).await?;
            if doomed.contains(owner_key_id) {
                return Err(AppError::InvalidInput(format!(
                    "Cannot reassign to key {owner_key_id}: it is itself inside the subtree being                      deleted, so the entity would be orphaned the moment this request completes"
                )));
            }
        }
    }

    // Everything below this line writes. Every validation is above it.
    let mut deleted_entities = 0usize;
    let mut reassigned_entities = 0usize;
    for entity in &inventory {
        let resolution = resolutions[&(entity.entity_type.to_owned(), entity.id)];
        match (entity.entity_type, resolution) {
            ("group", Resolution::Delete) => {
                IpGroup::delete_by_id(entity.id).exec(&state.db).await?;
                deleted_entities += 1;
            }
            ("webhook", Resolution::Delete) => {
                WebhookConfig::delete_by_id(entity.id).exec(&state.db).await?;
                deleted_entities += 1;
            }
            ("group", Resolution::Reassign { owner_key_id }) => {
                ip_group::Entity::update_many()
                    .col_expr(
                        ip_group::Column::OwnerKeyId,
                        sea_orm::sea_query::Expr::value(Some(*owner_key_id)),
                    )
                    .filter(ip_group::Column::Id.eq(entity.id))
                    .exec(&state.db)
                    .await?;
                reassigned_entities += 1;
            }
            ("webhook", Resolution::Reassign { owner_key_id }) => {
                webhook_config::Entity::update_many()
                    .col_expr(
                        webhook_config::Column::OwnerKeyId,
                        sea_orm::sea_query::Expr::value(Some(*owner_key_id)),
                    )
                    .filter(webhook_config::Column::Id.eq(entity.id))
                    .exec(&state.db)
                    .await?;
                reassigned_entities += 1;
            }
            // `entity_type` is set by `inventory_owned_entities` from a closed set of two literals.
            (other, _) => {
                tracing::error!("Unhandled inventory entity type {other:?}");
                return Err(AppError::Internal);
            }
        }
    }

    // The cascade itself. `api_key_group_permissions` rows follow by foreign key; nothing else does,
    // which is the point.
    let result = ApiKey::delete_many()
        .filter(api_key::Column::Id.is_in(subtree.clone()))
        .exec(&state.db)
        .await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip.0),
        "KEY_DELETE",
        None,
        None,
        Some(format!(
            "Deleted key {target_ref} and {} descendant key(s); {deleted_entities} owned \
             entit(y/ies) deleted, {reassigned_entities} reassigned",
            subtree.len().saturating_sub(1)
        )),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Payload for updating an existing API key's name, `bound_ips`, and global scope flags.
///
/// Carries no `is_master`, and denies unknown fields so that saying so is enforceable — the same §5
/// arrangement as [`CreateApiKeyPayload`], for the same reason. This struct has now held the field in
/// all three possible ways: absent and silently discarded, present and rejected by a guard, and
/// absent and rejected by the type. Only the last one cannot be undone by editing a handler.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateApiKeyPayload {
    /// New name, if changing it
    pub name: Option<String>,
    /// New bound CIDRs, if changing them
    pub bound_ips: Option<String>,
    /// New value for the "manage keys" global scope, if changing it
    pub can_manage_keys: Option<bool>,
    /// New value for the "manage webhooks" global scope, if changing it
    pub can_manage_webhooks: Option<bool>,
    /// New value for the "create groups" global scope, if changing it
    pub can_create_groups: Option<bool>,
}

/// Handles PUT /api/v1/keys/:id — updates name, `bound_ips`, and global scope flags in place.
pub async fn update_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
    StrictJson(payload): StrictJson<UpdateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = find_administrable_key(&state.db, &key, id).await?;
    guard_master_target(&key, &target)?;

    // §5's one exception: the Master may edit its own `bound_ips`, and nothing else about it is
    // reachable. Every other field is refused here rather than silently dropped, so an operator who
    // tried to rename the master learns that it did not happen.
    //
    // `key.id == target.id` is the "its own" half. With uniqueness enforced there is no other master
    // to be the caller, so in practice this only ever refuses the master editing itself in a way §5
    // forbids — but stating it explicitly means the rule does not quietly depend on the constraint
    // holding.
    if target.is_master {
        let touches_other_fields = payload.name.is_some()
            || payload.can_manage_keys.is_some()
            || payload.can_manage_webhooks.is_some()
            || payload.can_create_groups.is_some();
        if touches_other_fields {
            guard_master_immutable(&target, "renamed or re-scoped")?;
        }
        if key.id != target.id {
            return Err(AppError::Forbidden(
                "Only the master key itself may edit its bound_ips".to_owned(),
            ));
        }
    }

    // The master-only scopes cannot be granted to *anyone* by a non-master, self or otherwise.
    // `target`'s current values are the baseline, so re-submitting a scope the key already holds
    // is a no-op rather than a rejection.
    guard_scope_elevation(
        &key,
        [payload.can_manage_keys, payload.can_create_groups, payload.can_manage_webhooks],
        [target.can_manage_keys, target.can_create_groups, target.can_manage_webhooks],
    )?;

    // A dedicated self-escalation check for `can_manage_webhooks` stood here. It is now subsumed
    // exactly, not dropped: it fired when a non-master targeted itself with `can_manage_webhooks:
    // true` while not holding it, and in that case `target` *is* the caller, so the guard above sees
    // `requested = Some(true)` against `held = false` and refuses on R4 grounds. The scope moved onto
    // MASTER_ONLY_SCOPES, which makes the narrower rule redundant rather than merely usually-true.

    if let Some(bips) = &payload.bound_ips {
        for cidr in bips.split(',') {
            let _: IpNetwork = cidr.trim().parse()
                .map_err(|_| AppError::InvalidInput(format!("Invalid CIDR: {cidr}")))?;
        }
    }

    let mut active: api_key::ActiveModel = target.into();
    if let Some(name) = payload.name {
        active.name = Set(name);
    }
    if let Some(bips) = payload.bound_ips {
        active.bound_ips = Set(Some(bips));
    }
    if let Some(v) = payload.can_manage_keys {
        active.can_manage_keys = Set(v);
    }
    if let Some(v) = payload.can_manage_webhooks {
        active.can_manage_webhooks = Set(v);
    }
    if let Some(v) = payload.can_create_groups {
        active.can_create_groups = Set(v);
    }
    active.updated_at = Set(Utc::now().naive_utc());
    let updated = active.update(&state.db).await?;
    // Uses the post-update name (not the pre-update one) — if this call renamed the key, the
    // resulting name is what a reader will actually recognize it by later.
    let target_ref = format_key_reference(&updated.name, id);

    create_audit_log(&state.db, Some(&key), Some(client_ip.0), "KEY_UPDATE", None, None, Some(format!("Updated key {target_ref}"))).await?;

    Ok(Json(full_api_key_summary(&state.db, updated).await?))
}

/// Response after rotating an API key's secret
#[derive(Serialize)]
pub struct RotateKeyResponse {
    /// Key ID
    pub id: Uuid,
    /// The new plaintext key. Shown only once — only its hash is stored.
    pub plaintext_key: String,
    /// The new HMAC signing secret. Shown only once, like [`Self::plaintext_key`].
    pub signing_secret: String,
}

/// Handles POST /api/v1/keys/:id/rotate — generates a new secret for an existing key, returning
/// the plaintext once while immediately invalidating the previous secret (the old `key_hash` is
/// overwritten, not kept around).
///
/// Rotation replaces **both** credentials: the API key *and* its HMAC signing secret. Leaving the
/// old signing secret in place would defeat the point of rotating after a suspected compromise, and
/// it doubles as the recovery path for keys created before `signing_secret` existed (which carry
/// `NULL` and cannot authenticate until rotated).
pub async fn rotate_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = find_administrable_key(&state.db, &key, id).await?;
    guard_master_target(&key, &target)?;
    guard_master_immutable(&target, "rotated")?;
    let target_ref = format_key_reference(&target.name, id);

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let prefix = plaintext_key.chars().take(8).collect::<String>();
    let signing_secret = crate::crypto::generate_signing_secret();
    let stored_signing_secret = state.cipher.seal(&signing_secret)?;

    let mut active: api_key::ActiveModel = target.into();
    active.key_hash = Set(key_hash);
    active.prefix = Set(prefix);
    active.signing_secret = Set(Some(stored_signing_secret));
    active.updated_at = Set(Utc::now().naive_utc());
    active.update(&state.db).await?;

    create_audit_log(&state.db, Some(&key), Some(client_ip.0), "KEY_ROTATE", None, None, Some(format!("Rotated secret for key {target_ref}"))).await?;

    Ok(Json(RotateKeyResponse { id, plaintext_key, signing_secret }))
}

/// Response after rotating only an API key's HMAC signing secret.
#[derive(Serialize)]
pub struct RotateSigningSecretResponse {
    /// Key ID — unchanged by this operation.
    pub id: Uuid,
    /// Key name — unchanged by this operation, echoed back so the caller can confirm which key it
    /// just re-keyed without a second lookup.
    pub name: String,
    /// The new signing secret, in plaintext. Returned **only** here: the stored copy is encrypted at
    /// rest when `VAULT_ENCRYPTION_KEY` is set, and no read endpoint ever echoes it.
    pub signing_secret: String,
}

/// Handles `POST /api/keys/{id}/rotate-secret` — replaces a key's HMAC signing secret in place.
///
/// Distinct from [`rotate_api_key`] (`POST /api/keys/{id}/rotate`), which replaces *both*
/// credentials. This narrower operation exists because the two secrets have very different blast
/// radii: rotating `X-API-Key` forces every client to be reconfigured with a new identity, whereas
/// rotating only the signing secret re-keys the HMAC while the key's id, name, `bound_ips`, global
/// scopes, and every per-group permission grant stay exactly as they were. That makes it the right
/// tool for routine credential hygiene, and for recovering a key whose `signing_secret` is `NULL`
/// because it predates HMAC authentication.
///
/// The previous signing secret stops working the instant this returns — the column is overwritten,
/// not versioned — so callers must be updated in lockstep.
pub async fn rotate_signing_secret(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = find_administrable_key(&state.db, &key, id).await?;
    guard_master_target(&key, &target)?;
    guard_master_immutable(&target, "re-keyed")?;
    let target_name = target.name.clone();
    let target_ref = format_key_reference(&target_name, id);

    let signing_secret = crate::crypto::generate_signing_secret();
    let stored_signing_secret = state.cipher.seal(&signing_secret)?;

    // Only `signing_secret` (and the bookkeeping `updated_at`) is touched: `key_hash`, `prefix`,
    // `name`, `bound_ips` and every global scope are left untouched by construction, and the
    // separate `api_key_group_permissions` rows are never referenced at all.
    let mut active: api_key::ActiveModel = target.into();
    active.signing_secret = Set(Some(stored_signing_secret));
    active.updated_at = Set(Utc::now().naive_utc());
    active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip.0),
        "KEY_SECRET_ROTATE",
        None,
        None,
        Some(format!("Rotated signing secret for key {target_ref}")),
    )
    .await?;

    Ok(Json(RotateSigningSecretResponse { id, name: target_name, signing_secret }))
}

/// Handles POST /api/v1/keys/:id/groups
pub async fn update_key_group_permissions(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
    Json(payload): Json<GroupPermInput>,
) -> Result<impl IntoResponse, AppError> {

    // R2 in its group-independent form, run before any lookup so a caller with no administrative
    // standing anywhere cannot probe what exists. The precise per-group test runs below, once the
    // group is resolved.
    guard_may_administer_any_group(&state.db, &key).await?;

    let target_key = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    if target_key.is_master {
        return Err(AppError::InvalidInput("Cannot configure M:N permissions on a master key".to_owned()));
    }

    // Self-targeting is permitted, and is bounded rather than blocked. `guard_delegated_group_grant`
    // below compares the request against the caller's *own* row — which, when the caller is the
    // target, is the very row being written — so the result can never exceed what was already held.
    // A self-directed call is therefore always a reduction or a no-op, which is the same authority
    // the dedicated revoke path grants, reached through the other endpoint.
    //
    // An earlier revision refused this outright to prevent a ratchet: grant yourself what you
    // already hold, then widen from the fresh row. The ratchet was never reachable — widening is
    // exactly what the per-verb check refuses — so the block only stopped a manager from dropping
    // its own access, which is the one self-directed change nobody needs protecting from.

    if (payload.can_write || payload.can_delete) && !payload.can_read {
        return Err(AppError::InvalidInput(
            "can_write or can_delete require can_read to be true".to_owned(),
        ));
    }

    let target_group_id: Uuid;
    let resolved_group_name: String;
    let existing_group = resolve_group_ref_flexible(&state.db, payload.group_id.as_deref(), payload.group_name.as_deref()).await?;

    if let Some(g) = existing_group {
        target_group_id = g.id;
        resolved_group_name = g.name;
    } else if let Some(group_name) = &payload.group_name {
        if !key.is_master && !key.can_create_groups {
            return Err(AppError::Forbidden("Permission denied: Target group does not exist and you cannot create groups".to_owned()));
        }

        let group = get_or_create_group(&state.db, group_name, "banlist", resource_owner(&key)).await?;
        target_group_id = group.id;
        resolved_group_name = group.name;
    } else {
        return Err(AppError::NotFound);
    }

    // Checked after the group is resolved (so the name in the error is the real one) but before any
    // write.
    //
    // The `group_name` auto-create path above creates the group but provisions **no** permission row
    // for the creator, so a non-master arriving that way holds no `can_manage` on it and the R2 gate
    // below refuses. That is the specification's answer, not an oversight: R2 requires a
    // `can_manage = true` row and creating a resource does not mint one. Only a master can open a
    // brand-new group up for delegation.
    let caller_perm = caller_group_permission(&state.db, key.id, target_group_id).await?;
    let target_perm = caller_group_permission(&state.db, id, target_group_id).await?;

    // **Endpoint parity (R6, final sentence).** Which rule applies is a property of the *request*,
    // not of the route it arrived on. Both directions now share the same R2 admission test; the
    // classification decides whether the per-verb R1 ceiling applies on top.
    //
    // A payload that adds any verb the target lacks — or creates the row at all — is a grant, and
    // gets R2 + R1. A payload that only lowers an existing row is a **revocation reached through the
    // general update endpoint**, which R6 says must be classified as revocation "regardless of which
    // endpoint it arrives at", and gets R2 alone: no proof of authority over the verb being removed,
    // and self-targeting permitted. Splitting on the request rather than the route is what keeps
    // "revoke the row" and "update the row to a lower value" from drifting apart.
    if widens_permissions(&payload, target_perm.as_ref()) {
        guard_delegated_group_grant(&key, caller_perm.as_ref(), &resolved_group_name, "grant", &payload)?;
    } else {
        guard_group_manage(&key, caller_perm.as_ref(), &resolved_group_name, "revoke")?;
    }

    let now = Utc::now().naive_utc();
    let perm_model = api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(id),
        group_id: Set(target_group_id),
        can_read: Set(payload.can_read),
        can_write: Set(payload.can_write),
        can_delete: Set(payload.can_delete),
        can_manage: Set(payload.can_manage),
        created_at: Set(now),
    };

    api_key_group_permission::Entity::insert(perm_model)
        .on_conflict(
            OnConflict::columns([api_key_group_permission::Column::ApiKeyId, api_key_group_permission::Column::GroupId])
                .update_columns([
                    api_key_group_permission::Column::CanRead,
                    api_key_group_permission::Column::CanWrite,
                    api_key_group_permission::Column::CanDelete,
                    api_key_group_permission::Column::CanManage,
                ])
                .to_owned()
        )
        .exec(&state.db)
        .await?;

    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip.0),
        "KEY_PERM_UPDATE",
        None,
        Some(resolved_group_name),
        Some(format!("Updated permissions for key {}", format_key_reference(&target_key.name, id)))
    ).await?;

    Ok(axum::http::StatusCode::OK)
}

/// Handles DELETE /api/v1/keys/:id/permissions/:group_identifier — removes a key's permission
/// mapping for a specific group. `group_identifier` may be either the group's UUID or its name.
///
/// # Managing the group is the whole authority test
///
/// Admission is [`guard_group_manage`] — R2's conjunction, the same test the grant path starts from:
/// **Master**, or **global `can_manage_keys` together with `can_manage = true` on the caller's own
/// row for this group**. Neither half alone.
///
/// What revocation does *not* require is anything about the verbs themselves. R6: "Removing a
/// permission requires manage rights on the resource only; the revoker need not hold the verb being
/// removed, and may revoke its own permissions." Both are load-bearing:
///
/// **Per-verb revocation** would conflate two controls. Guarding a *grant* per verb is an
/// anti-escalation control: conferring `can_write` when you hold only `can_read` manufactures
/// authority that did not exist. Removing `can_write` manufactures nothing — no key anywhere ends up
/// with more access than before, the caller included. What removal genuinely threatens is
/// **integrity**: this service keeps `fail2ban`-style automation writing to shared banlists, so
/// stripping the key that maintains another tenant's list stops that tenant's blocking, and the
/// symptom ("bans stopped landing") sits several audit-log pages from the cause. R2's conjunction is
/// what bounds that threat — it confines every revocation to a group the caller was explicitly given
/// `can_manage` on, *and* to a caller trusted with credentials at all. A per-verb test on top would
/// buy no further containment while producing a genuinely strange shape: a grant you were trusted to
/// create could be one you were forbidden to undo.
///
/// **Self-targeting** is permitted for a related reason. It was once refused to prevent a ratchet —
/// grant yourself what you already hold, then widen from the fresh row — but the ratchet does not
/// exist: [`guard_delegated_group_grant`] compares a self-directed request against the caller's *own*
/// row, which is the very row being written, so the result can never exceed what was already held.
/// With escalation impossible, the block only forbade a manager from dropping its own access, making
/// the least-privilege action require a master.
///
/// The counterpart safeguard is that a master's view never depends on a permission row existing, so
/// a group whose last manager revokes itself stays visible and re-grantable rather than becoming
/// invisible. See [`list_ip_groups`].
pub async fn revoke_key_group_permission(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path((id, group_identifier)): Path<(Uuid, String)>,
) -> Result<impl IntoResponse, AppError> {
    // R2 in its group-independent form, kept ahead of the group lookup so a caller with no
    // administrative standing anywhere is refused without learning whether the group exists. *Which*
    // group it manages is checked precisely below.
    guard_may_administer_any_group(&state.db, &key).await?;

    let group = resolve_group_by_identifier(&state.db, &group_identifier)
        .await?
        .ok_or(AppError::NotFound)?;

    // A missing grant is the `404` this endpoint has always returned, and it is established before
    // the authority check below so a caller learns "no such grant" before it learns anything about
    // its own standing — and so a nonexistent grant cannot become a `403` that confirms the group
    // exists to someone with no access to it.
    if caller_group_permission(&state.db, id, group.id).await?.is_none() {
        return Err(AppError::NotFound);
    }

    let caller_perm = caller_group_permission(&state.db, key.id, group.id).await?;
    guard_group_manage(&key, caller_perm.as_ref(), &group.name, "revoke")?;

    let result = api_key_group_permission::Entity::delete_many()
        .filter(
            Condition::all()
                .add(api_key_group_permission::Column::ApiKeyId.eq(id))
                .add(api_key_group_permission::Column::GroupId.eq(group.id))
        )
        .exec(&state.db)
        .await?;

    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    let target = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip.0),
        "KEY_PERM_REVOKE",
        None,
        Some(group.name),
        Some(format!("Revoked permissions for key {}", format_key_reference(&target.name, id)))
    ).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// Admin CRUD — IP Groups
// ─────────────────────────────────────────────────────────────

/// Payload for creating an IP group
#[derive(Deserialize)]
pub struct CreateIpGroupPayload {
    /// Group Name
    pub name: String,
    /// Group type: `"banlist"` or `"whitelist"`. Defaults to `"banlist"` if omitted or set to
    /// anything else — this endpoint deliberately never rejects the request over this field.
    pub group_type: Option<String>,
}

/// Handles POST /api/v1/groups
pub async fn create_ip_group(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Json(payload): Json<CreateIpGroupPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_create_groups {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let group_type = match payload.group_type.as_deref() {
        Some("whitelist") => "whitelist",
        _ => "banlist",
    };

    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    let model = ip_group::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
        group_type: Set(group_type.to_owned()),
        description: Set(None),
        owner_key_id: Set(resource_owner(&key)),
        created_at: Set(now),
    };
    if let Err(err) = ip_group::Entity::insert(model).exec(&state.db).await {
        if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
            return Err(AppError::Conflict(format!(
                "A group named '{}' already exists",
                payload.name
            )));
        }
        return Err(err.into());
    }

    if !key.is_master {
        let perm = api_key_group_permission::ActiveModel {
            id: Set(Uuid::new_v4()),
            api_key_id: Set(key.id),
            group_id: Set(id),
            can_read: Set(true),
            can_write: Set(true),
            can_delete: Set(true),
            // See the auto-provisioning note in `upsert_ip`: creating a group does not confer
            // authority over other keys' rows on it.
            can_manage: Set(false),
            created_at: Set(now),
        };
        api_key_group_permission::Entity::insert(perm).exec(&state.db).await?;
    }
    
    create_audit_log(&state.db, Some(&key), Some(client_ip.0), "GROUP_CREATE", None, Some(payload.name.clone()), None).await?;

    Ok(Json(serde_json::json!({ "id": id, "name": payload.name, "group_type": group_type })))
}

/// Handles GET /api/v1/groups
pub async fn list_ip_groups(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    
    let mut query = IpGroup::find();
    if !key.is_master {
        let accessible_groups: Vec<Uuid> = api_key_group_permission::Entity::find()
            .filter(
                Condition::all()
                    .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                    .add(api_key_group_permission::Column::CanRead.eq(true))
            )
            .all(&state.db)
            .await?
            .into_iter()
            .map(|p| p.group_id)
            .collect();
        
        query = query.filter(ip_group::Column::Id.is_in(accessible_groups));
    }

    let groups = query.all(&state.db).await?;
    Ok(Json(groups))
}

/// Handles DELETE /api/v1/groups/:id — a **lifecycle** action, restricted by §3 to the Master and the
/// group's `owner_key_id`.
///
/// Previously master-only, which satisfied "not just anyone" without expressing why. §3 names the
/// owner as the second holder of this authority, and names what does *not* confer it: neither
/// `can_manage` on the group's permission rows nor any read/write/delete verb over its contents. A
/// group with no owner recorded — every pre-migration row, and everything a master creates — stays
/// master-only, which is exactly the authority that existed before.
pub async fn delete_ip_group(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let group = IpGroup::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    guard_resource_lifecycle(&key, group.owner_key_id, "group", "delete")?;

    let result = IpGroup::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    
    create_audit_log(&state.db, Some(&key), Some(client_ip.0), "GROUP_DELETE", None, None, Some(id.to_string())).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Payload for reassigning a resource's owner. `owner_key_id: null` clears ownership, returning the
/// resource to Master-only lifecycle authority.
#[derive(Deserialize)]
pub struct ReassignOwnerPayload {
    /// The key to make the new owner, or `null` to leave the resource unowned.
    pub owner_key_id: Option<Uuid>,
}

/// Handles PUT /api/v1/groups/:id/owner — **§3: "Master may reassign `owner_key_id` on any resource
/// or dispatch target at any time."**
///
/// Master-only, and deliberately not delegable even to the current owner. Ownership is the authority
/// to destroy the resource, so a transferable owner flag would let a tenant hand that authority
/// onward without the master who granted it ever seeing the transfer — the same amplification R1
/// forbids for permission verbs, one level up. It is also the sole recovery path for the `NULL`
/// backfill: every pre-migration resource arrives here to be assigned an owner.
pub async fn reassign_group_owner(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
    Json(payload): Json<ReassignOwnerPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only the master key can reassign resource ownership".to_owned(),
        ));
    }

    let group = IpGroup::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let owner = resolve_owner_assignment(&state.db, payload.owner_key_id).await?;

    let group_name = group.name.clone();
    let mut active: ip_group::ActiveModel = group.into();
    active.owner_key_id = Set(owner);
    active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip.0),
        "GROUP_OWNER_REASSIGN",
        None,
        Some(group_name),
        Some(match owner {
            Some(owner_id) => format!("Owner set to {owner_id}"),
            None => "Owner cleared (master-only)".to_owned(),
        }),
    )
    .await?;

    Ok(Json(serde_json::json!({ "id": id, "owner_key_id": owner })))
}

/// Handles PUT /api/v1/webhooks/:id/owner — the dispatch-target counterpart to
/// [`reassign_group_owner`], and the only way a pre-migration webhook becomes visible to anyone but
/// the master again.
pub async fn reassign_webhook_owner(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
    Json(payload): Json<ReassignOwnerPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only the master key can reassign resource ownership".to_owned(),
        ));
    }

    let webhook = WebhookConfig::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let owner = resolve_owner_assignment(&state.db, payload.owner_key_id).await?;

    let webhook_name = webhook.name.clone();
    let mut active: webhook_config::ActiveModel = webhook.into();
    active.owner_key_id = Set(owner);
    active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip.0),
        "WEBHOOK_OWNER_REASSIGN",
        None,
        None,
        Some(match owner {
            Some(owner_id) => format!("Owner of '{webhook_name}' set to {owner_id}"),
            None => format!("Owner of '{webhook_name}' cleared (master-only)"),
        }),
    )
    .await?;

    Ok(Json(serde_json::json!({ "id": id, "owner_key_id": owner })))
}

// ─────────────────────────────────────────────────────────────
// Admin CRUD — Webhooks
// ─────────────────────────────────────────────────────────────

/// Payload for webhook creation
#[derive(Deserialize)]
pub struct CreateWebhookPayload {
    /// Webhook name
    pub name: String,
    /// Target URL
    pub target_url: String,
    /// Shared secret keying the HMAC. Required by `CANONICAL_V1` and `BODY_ONLY`; may be omitted
    /// (and is stored as an empty string) by the modes that compute no signature.
    pub secret_token: Option<String>,
    /// Custom headers
    pub headers_json: Option<String>,
    /// Payload Template
    pub payload_template: String,
    /// Target IP Group
    pub group_id: Uuid,
    /// Is Active
    pub is_active: Option<bool>,
    /// Comma-separated subset of `IP_ADD`/`IP_UPDATE`/`IP_DELETE` to trigger on. `None` (the
    /// default if omitted) means all events — the historical, pre-filtering behavior.
    pub events: Option<String>,
    /// How dispatches authenticate: `"CANONICAL_V1"` (default), `"BODY_ONLY"`, `"API_KEY_ONLY"`, or
    /// `"NONE"`.
    pub auth_mode: Option<String>,
    /// Deprecated alias for [`Self::auth_mode`], accepted so callers written against the
    /// short-lived `signature_mode` field keep working. Ignored when `auth_mode` is also present.
    pub signature_mode: Option<String>,
    /// Value to send as `X-API-Key` on each dispatch. Required by `API_KEY_ONLY`; optional for
    /// `CANONICAL_V1`; ignored by the other modes.
    pub api_key: Option<String>,
    /// Canonical string template for `CANONICAL_V1`, with `{method}`/`{path}`/`{timestamp}`/`{body}`
    /// placeholders. Omitted or empty means the default `{method}\n{path}\n{timestamp}\n{body}`.
    pub hmac_template: Option<String>,
}

/// Handles POST /api/v1/webhooks
pub async fn create_webhook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Json(payload): Json<CreateWebhookPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // A webhook is a standing export of everything that happens in its group, to a URL the creator
    // chooses. `can_manage_webhooks` alone therefore was not sufficient authority: it let a key
    // scoped to one group subscribe to the events of *every* group — including ones it cannot read
    // through any other endpoint — and stream them to a server it controls. Requiring `can_read` on
    // the target group keeps a webhook's reach bounded by the creator's own reach.
    if !key.is_master {
        let perm = caller_group_permission(&state.db, key.id, payload.group_id).await?;
        if !perm.is_some_and(|p| p.can_read) {
            return Err(AppError::Forbidden(
                "Permission denied: you have no read access to the target group".to_owned(),
            ));
        }
    }

    let parsed_url = reqwest::Url::parse(&payload.target_url)
        .map_err(|_| AppError::InvalidInput("Invalid target_url: must be a well-formed URL".to_owned()))?;
    if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
        return Err(AppError::InvalidInput("Invalid target_url: scheme must be http or https".to_owned()));
    }
    if parsed_url.host_str().is_none() {
        return Err(AppError::InvalidInput("Invalid target_url: missing host".to_owned()));
    }

    if let Some(events) = &payload.events {
        for token in events.split(',').map(|s| s.trim()) {
            if !IP_EVENT_ACTIONS.contains(&token) {
                return Err(AppError::InvalidInput(format!(
                    "Invalid events entry '{token}': must be one of {}",
                    IP_EVENT_ACTIONS.join(", ")
                )));
            }
        }
    }

    // Rejected rather than silently defaulted: a caller who asks for an auth mode and gets a
    // different one would ship a receiver that rejects every dispatch, with nothing to point at.
    let requested_mode = payload.auth_mode.as_deref().or(payload.signature_mode.as_deref());
    let auth_mode = match requested_mode {
        None => webhook_config::AuthMode::CanonicalV1,
        Some(raw) => webhook_config::AuthMode::parse(raw).ok_or_else(|| {
            AppError::InvalidInput(format!(
                "Invalid auth_mode '{raw}': must be one of {}",
                webhook_config::AuthMode::ALL.join(", ")
            ))
        })?,
    };

    // Empty strings are normalized to `None` up front, so "field present but blank" (what an
    // untouched HTML input posts) and "field absent" mean the same thing everywhere downstream.
    let api_key = payload.api_key.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(str::to_owned);
    let hmac_template = payload.hmac_template.as_deref().filter(|v| !v.is_empty()).map(str::to_owned);
    let secret_token = payload.secret_token.clone().unwrap_or_default();

    // Each mode's own preconditions. Catching these here turns a webhook that would have failed
    // silently on every future dispatch — in a background worker, where the operator sees only a
    // log line — into an error on the request that configured it.
    if auth_mode.requires_secret() && secret_token.is_empty() {
        return Err(AppError::InvalidInput(format!(
            "auth_mode '{}' computes an HMAC and requires a non-empty secret_token",
            auth_mode.as_str()
        )));
    }
    if auth_mode == webhook_config::AuthMode::ApiKeyOnly && api_key.is_none() {
        return Err(AppError::InvalidInput(
            "auth_mode 'API_KEY_ONLY' requires a non-empty api_key".to_owned(),
        ));
    }
    if let Some(template) = &hmac_template
        && !template.contains("{body}")
    {
        return Err(AppError::InvalidInput(
            "hmac_template must contain {body}: a signature that does not cover the payload authenticates nothing".to_owned(),
        ));
    }

    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    let model = webhook_config::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
        target_url: Set(payload.target_url.clone()),
        secret_token: Set(secret_token),
        auth_mode: Set(auth_mode.as_str().to_owned()),
        api_key: Set(api_key),
        hmac_template: Set(hmac_template),
        headers_json: Set(payload.headers_json.clone()),
        payload_template: Set(payload.payload_template.clone()),
        group_id: Set(payload.group_id),
        // §4 makes a webhook creator-private. This column is the "creator" half; without it the only
        // scoping available was the group's, which is the shared-resource rule §4 forbids here.
        owner_key_id: Set(resource_owner(&key)),
        is_active: Set(payload.is_active.unwrap_or(true)),
        events: Set(payload.events.clone()),
        created_at: Set(now),
    };
    webhook_config::Entity::insert(model).exec(&state.db).await?;

    create_audit_log(&state.db, Some(&key), Some(client_ip.0), "WEBHOOK_CREATE", None, None, Some(payload.target_url.clone())).await?;

    Ok(Json(serde_json::json!({
        "id": id,
        "target_url": payload.target_url,
        "auth_mode": auth_mode.as_str(),
    })))
}

/// Public-safe summary of a webhook configuration. Deliberately omits `secret_token` **and**
/// `api_key`: unlike `api_keys.key_hash` (a hash of a high-entropy generated value), both are
/// caller-supplied plaintext credentials for a remote system — leaking `secret_token` would let any
/// reader with `can_manage_webhooks` forge valid `X-Signature-256` signatures, and leaking `api_key`
/// would hand them a working credential on the receiving system outright.
#[derive(Serialize)]
pub struct WebhookSummary {
    /// Webhook ID
    pub id: Uuid,
    /// Webhook name
    pub name: String,
    /// Target URL
    pub target_url: String,
    /// Custom headers (JSON-encoded)
    pub headers_json: Option<String>,
    /// Payload template
    pub payload_template: String,
    /// Target IP group
    pub group_id: Uuid,
    /// Whether dispatching is currently enabled
    pub is_active: bool,
    /// Comma-separated subset of `IP_ADD`/`IP_UPDATE`/`IP_DELETE` this webhook fires for; `None`
    /// means all events.
    pub events: Option<String>,
    /// How dispatches authenticate: `"CANONICAL_V1"`, `"BODY_ONLY"`, `"API_KEY_ONLY"` or `"NONE"`.
    /// Safe to expose — it describes the *scheme*, not the `secret_token` or `api_key` behind it.
    pub auth_mode: String,
    /// The canonical string template used in `CANONICAL_V1` mode, resolved to the effective value
    /// (the default when the column is unset) so the dashboard shows what is actually signed.
    /// Contains only placeholders and literal structure, never secret material.
    pub hmac_template: String,
    /// Whether an `X-API-Key` is configured, without disclosing it. The dashboard needs to render
    /// the field as populated; nothing needs its value back.
    pub has_api_key: bool,
    /// Creation timestamp
    pub created_at: chrono::NaiveDateTime,
}

impl From<webhook_config::Model> for WebhookSummary {
    fn from(w: webhook_config::Model) -> Self {
        // Normalized through the enum so a hand-edited or legacy row is reported as the mode it
        // will actually be dispatched with, rather than as whatever string happens to be stored.
        let auth_mode = webhook_config::AuthMode::from_stored(&w.auth_mode);
        WebhookSummary {
            id: w.id,
            name: w.name,
            target_url: w.target_url,
            headers_json: w.headers_json,
            payload_template: w.payload_template,
            group_id: w.group_id,
            is_active: w.is_active,
            events: w.events,
            auth_mode: auth_mode.as_str().to_owned(),
            hmac_template: w
                .hmac_template
                .unwrap_or_else(|| webhook_config::DEFAULT_HMAC_TEMPLATE.to_owned()),
            has_api_key: w.api_key.is_some_and(|k| !k.is_empty()),
            created_at: w.created_at,
        }
    }
}

/// Payload for updating an existing webhook. Every field is optional; omitted fields are left as
/// they are.
///
/// `secret_token` is deliberately **not** settable to an empty string here — see
/// [`update_webhook`] for why a repointed webhook must always end up with a fresh secret.
#[derive(Deserialize)]
pub struct UpdateWebhookPayload {
    /// New human-readable name.
    pub name: Option<String>,
    /// New target endpoint. Changing this forces the `secret_token` to be regenerated.
    pub target_url: Option<String>,
    /// New canonical-string template. Changing this also forces regeneration, since the template
    /// decides what the signature actually attests to.
    pub hmac_template: Option<String>,
    /// Explicit replacement secret. When omitted and a rotation is required, one is generated and
    /// returned in the response.
    pub secret_token: Option<String>,
    /// New custom headers, JSON-encoded.
    pub headers_json: Option<String>,
    /// New payload template.
    pub payload_template: Option<String>,
    /// New event filter.
    pub events: Option<String>,
    /// Enable or disable dispatching.
    pub is_active: Option<bool>,
}

/// Response from [`update_webhook`]. Carries the new `secret_token` **only** when the update forced
/// a rotation, and only on this one response — no read endpoint ever echoes it again.
#[derive(Serialize)]
pub struct UpdateWebhookResponse {
    /// The updated webhook, in the same public-safe shape as the listing.
    #[serde(flatten)]
    pub webhook: WebhookSummary,
    /// Whether this update rotated the signing secret.
    pub secret_rotated: bool,
    /// The freshly generated secret, present only when `secret_rotated` is true *and* the caller
    /// did not supply its own replacement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_token: Option<String>,
}

/// Handles `PUT /api/v1/webhooks/{id}` — edits a webhook in place.
///
/// **Repointing a webhook invalidates its secret.** If `target_url` or `hmac_template` changes, the
/// `secret_token` is replaced — with the caller's own value if it supplied one, otherwise with a
/// freshly generated secret returned once in this response.
///
/// This is the anti-hijack property. `secret_token` is write-only: no endpoint returns it, so a
/// caller who can edit a webhook cannot read the secret it currently signs with. Without forced
/// rotation, that caller could instead point the webhook at a server it controls and simply *wait*
/// — the next dispatch would arrive at the attacker's endpoint carrying a valid
/// `X-Signature-256` over an attacker-chosen payload, handing over a working forgery oracle for the
/// receiver's shared secret. Rotating on repoint means the secret a webhook holds is only ever
/// usable against the destination it was configured for.
///
/// Changing `hmac_template` is treated identically: the template decides which bytes the signature
/// covers, so a caller who can rewrite it (e.g. to a constant that ignores `{body}`) can make the
/// existing secret vouch for content it never saw.
pub async fn update_webhook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateWebhookPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = WebhookConfig::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    // Same scoping as create/delete, and for the same §4 reason: a dispatch target is visible to its
    // creator and Master and to nobody else, so a webhook the caller does not own is one it cannot
    // edit. `404` keeps "not yours" and "does not exist" indistinguishable from outside.
    //
    // This endpoint renames webhooks, which §3 names as a lifecycle action — but the ownership test
    // is the same test either way, so it is applied once here rather than split into "you may repoint
    // it but not rename it", which would be a distinction with no holder.
    if !key.is_master && target.owner_key_id != Some(key.id) {
        return Err(AppError::NotFound);
    }

    if let Some(url) = &payload.target_url {
        let parsed = reqwest::Url::parse(url).map_err(|_| {
            AppError::InvalidInput("Invalid target_url: must be a well-formed URL".to_owned())
        })?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(AppError::InvalidInput(
                "Invalid target_url: scheme must be http or https".to_owned(),
            ));
        }
        if parsed.host_str().is_none() {
            return Err(AppError::InvalidInput("Invalid target_url: missing host".to_owned()));
        }
    }

    if let Some(events) = &payload.events {
        for token in events.split(',').map(|s| s.trim()) {
            if !IP_EVENT_ACTIONS.contains(&token) {
                return Err(AppError::InvalidInput(format!(
                    "Invalid events entry '{token}': must be one of {}",
                    IP_EVENT_ACTIONS.join(", ")
                )));
            }
        }
    }

    if let Some(template) = &payload.hmac_template
        && !template.contains("{body}")
    {
        return Err(AppError::InvalidInput(
            "hmac_template must contain {body}: a signature that does not cover the payload authenticates nothing".to_owned(),
        ));
    }

    // Compared against the *effective* current values so that setting a field to what it already
    // holds is not treated as a repoint — an idempotent PUT from a dashboard that submits every
    // field on every save must not churn the secret on each click.
    let effective_template =
        target.hmac_template.as_deref().unwrap_or(webhook_config::DEFAULT_HMAC_TEMPLATE);
    let url_changed = payload.target_url.as_deref().is_some_and(|u| u != target.target_url);
    let template_changed = payload
        .hmac_template
        .as_deref()
        .filter(|t| !t.is_empty())
        .is_some_and(|t| t != effective_template);

    let mode = webhook_config::AuthMode::from_stored(&target.auth_mode);

    // A *privileged* webhook carries a credential the receiver recognizes as an identity — an
    // `api_key`, which is how instance chaining works (`AGENT.MD` §4): its dispatches authenticate
    // as a real API caller on the receiving system. Repointing one aims a working credential at a
    // destination of the editor's choosing, which forced rotation alone does not undo, because the
    // `api_key` is not rotated and cannot be (it belongs to the remote system, not this one).
    //
    // So for these, changing the destination or what the signature attests to is master-only. Every
    // other property — name, payload template, event filter, enabled/disabled — stays editable by
    // any `can_manage_webhooks` holder, and non-privileged webhooks are unaffected.
    if (url_changed || template_changed)
        && target.api_key.as_deref().is_some_and(|k| !k.is_empty())
        && !key.is_master
    {
        tracing::warn!(
            "Blocked webhook repointing: key {} attempted to alter target_url/hmac_template on \
             privileged webhook '{}' (carries an api_key)",
            key.prefix,
            target.name
        );
        return Err(AppError::Forbidden(
            "This webhook sends an api_key credential; only a master key may change its \
             target_url or hmac_template"
                .to_owned(),
        ));
    }
    // Only the signing modes have a secret worth protecting; forcing a rotation on API_KEY_ONLY or
    // NONE would mint a secret that is never used and cannot be verified against anything.
    let must_rotate = (url_changed || template_changed) && mode.requires_secret();

    let supplied_secret = payload.secret_token.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let mut generated_secret = None;

    let new_secret = match (must_rotate, supplied_secret) {
        // Caller brought its own replacement: honour it, and do not echo it back.
        (_, Some(supplied)) => Some(supplied.to_owned()),
        // Repointed with no replacement offered: generate one and hand it over exactly once.
        (true, None) => {
            let secret = crate::crypto::generate_signing_secret();
            generated_secret = Some(secret.clone());
            Some(secret)
        }
        (false, None) => None,
    };

    let mut active: webhook_config::ActiveModel = target.clone().into();
    if let Some(name) = payload.name {
        active.name = Set(name);
    }
    if let Some(url) = payload.target_url {
        active.target_url = Set(url);
    }
    if let Some(template) = payload.hmac_template {
        active.hmac_template = Set(Some(template).filter(|t| !t.is_empty()));
    }
    if let Some(headers) = payload.headers_json {
        active.headers_json = Set(Some(headers));
    }
    if let Some(template) = payload.payload_template {
        active.payload_template = Set(template);
    }
    if let Some(events) = payload.events {
        active.events = Set(Some(events));
    }
    if let Some(is_active) = payload.is_active {
        active.is_active = Set(is_active);
    }
    if let Some(secret) = new_secret {
        active.secret_token = Set(secret);
    }

    let updated = active.update(&state.db).await?;

    let detail = if must_rotate {
        format!(
            "Updated webhook '{}' (repointed — secret_token rotated)",
            updated.name
        )
    } else {
        format!("Updated webhook '{}'", updated.name)
    };
    create_audit_log(
        &state.db,
        Some(&key),
        Some(client_ip.0),
        "WEBHOOK_UPDATE",
        None,
        None,
        Some(detail),
    )
    .await?;

    Ok(Json(UpdateWebhookResponse {
        webhook: WebhookSummary::from(updated),
        secret_rotated: must_rotate,
        secret_token: generated_secret,
    }))
}

/// Handles GET /api/v1/webhooks
pub async fn list_webhooks(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // §4: "Dispatch targets: visible exclusively to their creator and Master. They are never exposed
    // by the shared-resource rule above."
    //
    // This was scoped by *group readability*, which is that shared-resource rule — so every
    // `can_manage_webhooks` holder with `can_read` on a group saw every other tenant's integrations in
    // it, target URL and configured headers included. A webhook row is a description of where a
    // tenant sends its data and what it puts in the request; a shared banlist is not a reason to hand
    // that over.
    //
    // Pre-migration rows carry `owner_key_id = NULL` and so appear to nobody but the master until
    // reassigned — the deliberate consequence of the null backfill, recorded in AGENT_NOTES.MD.
    let mut query = WebhookConfig::find();
    if !key.is_master {
        query = query.filter(webhook_config::Column::OwnerKeyId.eq(key.id));
    }

    let webhooks = query.all(&state.db).await?;
    let summaries: Vec<WebhookSummary> = webhooks.into_iter().map(WebhookSummary::from).collect();
    Ok(Json(summaries))
}

/// Handles DELETE /api/v1/webhooks/:id
pub async fn delete_webhook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // A webhook is a **dispatch target**: creator-private, and never reachable through the group it
    // watches. Scoping deletion by group readability — what this did before — is the shared-resource
    // rule §4 explicitly forbids applying to a dispatch target, and it meant any `can_manage_webhooks`
    // holder with `can_read` on a group could delete another tenant's integration.
    //
    // `404` rather than `403` for a webhook the caller does not own: it never appeared in that
    // caller's `GET /api/webhooks`, so its existence is not something to confirm. That is §4's oracle
    // discipline, which Phase 3 extends to the rest of the surface.
    let target = WebhookConfig::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !key.is_master && target.owner_key_id != Some(key.id) {
        return Err(AppError::NotFound);
    }

    let result = WebhookConfig::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(&state.db, Some(&key), Some(client_ip.0), "WEBHOOK_DELETE", None, None, Some(id.to_string())).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// Audit Logs
// ─────────────────────────────────────────────────────────────

/// Query parameters for audit log listing
#[derive(Deserialize)]
pub struct AuditLogQuery {
    /// Filter by exact action type (e.g. `IP_ADD`)
    pub action: Option<String>,
    /// Pagination limit
    pub limit: Option<u64>,
    /// Pagination offset
    pub offset: Option<u64>,
}

/// Handles GET /api/v1/audit-logs. Restricted to master keys: audit entries span every key and
/// group in the system, so a scoped key seeing them would be an RBAC leak regardless of its
/// per-group grants.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Query(query): Query<AuditLogQuery>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only master keys can view audit logs".to_owned()));
    }

    let mut q = audit_log::Entity::find().order_by_desc(audit_log::Column::Timestamp);
    if let Some(action) = &query.action
        && !action.is_empty()
    {
        q = q.filter(audit_log::Column::Action.eq(action));
    }

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    let logs = q.limit(limit).offset(offset).all(&state.db).await?;

    Ok(Json(logs))
}
