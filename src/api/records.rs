//! IP record endpoints: ban/white, listing, soft delete, restore, and purge.
//!
//! The specification's *resource data* — records live inside IP Groups and inherit their
//! authorization from the group's permission row rather than carrying one of their own.

use axum::{Extension, extract::{Json, Path, Query, State}, response::IntoResponse};
use chrono::Utc;
use ipnetwork::IpNetwork;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, sea_query::OnConflict, SqlErr,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    api_key, api_key_group_permission, ip_group, ip_record, ip_record_group_membership,
};
use crate::error::AppError;
use crate::middleware::ClientIp;
use crate::state::{AppState, WebhookEvent};

use super::{
    create_audit_log, format_key_reference, get_or_create_group, normalize_ip_or_cidr,
    resolve_group_ref, resource_owner,
};

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


pub(crate) async fn handle_ip_upsert(
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
pub(crate) async fn caller_may_delete_record(
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
