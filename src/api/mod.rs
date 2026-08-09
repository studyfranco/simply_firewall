//! API endpoints and business logic.

use chrono::Utc;
use ipnetwork::IpNetwork;
use rand::RngExt;
use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, sea_query::OnConflict};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entities::{api_key, audit_log, ip_group};
use crate::error::AppError;

// ─────────────────────────────────────────────────────────────
// Sub-modules
// ─────────────────────────────────────────────────────────────
//
// Split by *domain*, and re-exported flat. `api::create_api_key` still resolves exactly as it
// did when this was one file, so `lib.rs`'s router, every integration test, and `scripts/`
// needed no changes — which is what makes this refactor reviewable as a move rather than a
// rewrite. The paths are the API; the files are an implementation detail.
//
// What stays *here* rather than in a domain module is the set of helpers more than one domain
// needs: key hashing, address normalisation, audit-log writing, and group resolution. Pushing
// them into a domain would make every other domain depend on that one.

mod guards;
mod records;
mod keys;
mod groups;
mod webhooks;
mod audit;

// `pub(crate)` rather than `pub`: every item in `guards` is internal, so a `pub` glob would
// re-export nothing and clippy says so. The guards are deliberately not part of the crate's public
// surface — they are the enforcement, not the API.
pub(crate) use guards::*;
pub use records::*;
pub use keys::*;
pub use groups::*;
pub use webhooks::*;
pub use audit::*;


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


/// Payload for reassigning a resource's owner. `owner_key_id: null` clears ownership, returning the
/// resource to Master-only lifecycle authority.
#[derive(Deserialize)]
pub struct ReassignOwnerPayload {
    /// The key to make the new owner, or `null` to leave the resource unowned.
    pub owner_key_id: Option<Uuid>,
}
