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
use crate::state::{AppState, WebhookEvent};

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

/// Helper to insert an audit log entry
async fn create_audit_log(
    db: &sea_orm::DatabaseConnection,
    api_key_id: Option<Uuid>,
    action: &str,
    target_address: Option<String>,
    group_names: Option<String>,
    details: Option<String>,
) -> Result<(), AppError> {
    let log = audit_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(api_key_id),
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
async fn get_or_create_group(
    db: &sea_orm::DatabaseConnection,
    name: &str,
    default_group_type: &str,
) -> Result<ip_group::Model, AppError> {
    let new_group = ip_group::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(name.to_owned()),
        group_type: Set(default_group_type.to_owned()),
        description: Set(None),
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
    Json(payload): Json<BanWhitePayload>,
) -> Result<impl IntoResponse, AppError> {
    handle_ip_upsert(state, key, payload, false).await
}

/// Handles POST /api/v1/white to add an IP to a whitelist group
pub async fn handle_white(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Json(payload): Json<BanWhitePayload>,
) -> Result<impl IntoResponse, AppError> {
    handle_ip_upsert(state, key, payload, true).await
}

async fn handle_ip_upsert(
    state: AppState,
    key: api_key::Model,
    payload: BanWhitePayload,
    is_whitelist: bool,
) -> Result<impl IntoResponse, AppError> {
    let network: IpNetwork = payload.target_address.parse()
        .map_err(|_| AppError::InvalidInput("Invalid IP or CIDR format".to_owned()))?;

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
    } else if let Some(group_name) = &payload.group_name {
        // group_id (if given) is never auto-creatable — only reachable here when group_name was
        // supplied instead, since resolve_group_ref requires exactly one of the two.
        if !key.is_master && !key.can_create_groups {
            return Err(AppError::Forbidden("Permission denied: Target group does not exist and you cannot create groups".to_owned()));
        }

        let default_type = if is_whitelist { "whitelist" } else { "banlist" };
        let group = get_or_create_group(&state.db, group_name, default_type).await?;
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
            .filter(ip_record::Column::TargetAddress.eq(payload.target_address.clone()))
            .one(&state.db)
            .await?;

        if let Some(record) = existing_record {
            if record.is_locked {
                return Err(AppError::Forbidden("This IP is protected and cannot be modified".to_owned()));
            }

            let mut active_rec: ip_record::ActiveModel = record.into();
            active_rec.last_seen_at = Set(now);
            active_rec.updated_at = Set(now);
            if let Some(c) = &payload.cause {
                active_rec.cause = Set(Some(c.clone()));
            }
            let updated = active_rec.update(&state.db).await?;
            record_id = updated.id;
            break;
        }

        let new_id = Uuid::new_v4();
        let model = ip_record::ActiveModel {
            id: Set(new_id),
            target_address: Set(payload.target_address.clone()),
            cause: Set(payload.cause.clone()),
            is_locked: Set(false),
            created_at: Set(now),
            updated_at: Set(now),
            last_seen_at: Set(now),
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
    // inserted") instead of the no-op success it actually is.
    ip_record_group_membership::Entity::insert(mem)
        .on_conflict(
            OnConflict::columns([ip_record_group_membership::Column::IpRecordId, ip_record_group_membership::Column::GroupId])
                .do_nothing()
                .to_owned()
        )
        .exec_without_returning(&state.db)
        .await?;

    create_audit_log(
        &state.db,
        Some(key.id),
        "IP_ADD",
        Some(payload.target_address.clone()),
        Some(resolved_group_name),
        Some(format!("Added IP to group. Whitelist: {}", is_whitelist))
    ).await?;

    let event = WebhookEvent {
        event_type: if is_whitelist { "white".to_owned() } else { "ban".to_owned() },
        address: payload.target_address.clone(),
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
            return Ok(Json(Vec::<IpRecordResponse>::new()));
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
        query = query.filter(ip_record::Column::TargetAddress.contains(ip.trim()));
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

    let memberships = query
        .limit(limit)
        .offset(offset)
        .all(&state.db)
        .await?;

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
        });
    }

    Ok(Json(items))
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
        Some(key.id),
        "IP_DELETE",
        Some(target_address),
        Some(group.name.clone()),
        None
    ).await?;

    let event = WebhookEvent {
        event_type: "delete".to_owned(),
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
    /// Target group, by ID. Provide this or `group_name`, not both.
    pub group_id: Option<Uuid>,
    /// Target group, by name. Provide this or `group_id`, not both. A name that doesn't exist
    /// yet may be auto-created (permission allowing); an unknown `group_id` is a `404` instead.
    pub group_name: Option<String>,
    /// Can read
    pub can_read: bool,
    /// Can write
    pub can_write: bool,
    /// Can delete
    pub can_delete: bool,
}

/// Payload for creating an API Key
#[derive(Deserialize)]
pub struct CreateApiKeyPayload {
    /// Name
    pub name: String,
    /// Bound CIDRs
    pub bound_ips: Option<String>,
    /// Master flag
    pub is_master: Option<bool>,
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
    /// Name
    pub name: String,
    /// Bound ips
    pub bound_ips: Option<String>,
}

/// Handles POST /api/v1/keys
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Json(payload): Json<CreateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    if let Some(bips) = &payload.bound_ips {
        for cidr in bips.split(',') {
            let _ : IpNetwork = cidr.trim().parse()
                .map_err(|_| AppError::InvalidInput(format!("Invalid CIDR: {}", cidr)))?;
        }
    }

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let prefix = plaintext_key.chars().take(8).collect::<String>();
    let id = Uuid::new_v4();
    let now = Utc::now().naive_utc();

    let model = api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(key_hash),
        name: Set(payload.name.clone()),
        prefix: Set(prefix),
        bound_ips: Set(payload.bound_ips.clone()),
        is_master: Set(payload.is_master.unwrap_or(false)),
        can_manage_keys: Set(payload.can_manage_keys.unwrap_or(false)),
        can_manage_webhooks: Set(payload.can_manage_webhooks.unwrap_or(false)),
        can_create_groups: Set(payload.can_create_groups.unwrap_or(false)),
        created_at: Set(now),
        updated_at: Set(now),
    };

    api_key::Entity::insert(model).exec(&state.db).await?;
    
    create_audit_log(&state.db, Some(key.id), "KEY_CREATE", None, None, Some(payload.name.clone())).await?;

    Ok(Json(CreateApiKeyResponse {
        id,
        plaintext_key,
        name: payload.name,
        bound_ips: payload.bound_ips,
    }))
}

/// Public-safe summary of an API key for admin listings. Deliberately omits `key_hash`: the
/// hash of the live secret has no reason to ever leave the server, even to trusted admin UIs.
#[derive(Serialize)]
pub struct ApiKeySummary {
    /// Key ID
    pub id: Uuid,
    /// Key name
    pub name: String,
    /// First 8 characters of the plaintext key, for display/identification only
    pub prefix: String,
    /// Bound CIDRs
    pub bound_ips: Option<String>,
    /// Master flag
    pub is_master: bool,
    /// Global key management scope
    pub can_manage_keys: bool,
    /// Global webhook management scope
    pub can_manage_webhooks: bool,
    /// Global group creation scope
    pub can_create_groups: bool,
    /// Key creation timestamp
    pub created_at: chrono::NaiveDateTime,
    /// Per-group permissions granted to this key
    pub group_permissions: Vec<MePermission>,
}

/// Builds the public-safe summary (including per-group permissions) for a single key. Shared by
/// every endpoint that returns key details, so the shape stays consistent everywhere.
async fn build_api_key_summary(
    db: &sea_orm::DatabaseConnection,
    k: api_key::Model,
) -> Result<ApiKeySummary, AppError> {
    let perms = api_key_group_permission::Entity::find()
        .filter(api_key_group_permission::Column::ApiKeyId.eq(k.id))
        .find_also_related(ip_group::Entity)
        .all(db)
        .await?;

    let group_permissions = perms
        .into_iter()
        .filter_map(|(p, g)| {
            g.map(|group| MePermission {
                group_id: p.group_id,
                group_name: group.name,
                can_read: p.can_read,
                can_write: p.can_write,
                can_delete: p.can_delete,
            })
        })
        .collect();

    Ok(ApiKeySummary {
        id: k.id,
        name: k.name,
        prefix: k.prefix,
        bound_ips: k.bound_ips,
        is_master: k.is_master,
        can_manage_keys: k.can_manage_keys,
        can_manage_webhooks: k.can_manage_webhooks,
        can_create_groups: k.can_create_groups,
        created_at: k.created_at,
        group_permissions,
    })
}

/// Handles GET /api/v1/keys
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let keys = ApiKey::find().all(&state.db).await?;
    let mut summaries = Vec::with_capacity(keys.len());
    for k in keys {
        summaries.push(build_api_key_summary(&state.db, k).await?);
    }

    Ok(Json(summaries))
}

/// Handles DELETE /api/v1/keys/:id
pub async fn delete_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    if id == key.id {
        return Err(AppError::Forbidden("Cannot delete yourself".to_owned()));
    }

    let result = ApiKey::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    
    create_audit_log(&state.db, Some(key.id), "KEY_DELETE", None, None, Some(id.to_string())).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Payload for updating an existing API key's name, `bound_ips`, and global scope flags. Does not
/// include `is_master`: promoting/demoting master status is deliberately not exposed through this
/// generic update endpoint.
#[derive(Deserialize)]
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
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

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

    create_audit_log(&state.db, Some(key.id), "KEY_UPDATE", None, None, Some(id.to_string())).await?;

    Ok(Json(build_api_key_summary(&state.db, updated).await?))
}

/// Response after rotating an API key's secret
#[derive(Serialize)]
pub struct RotateKeyResponse {
    /// Key ID
    pub id: Uuid,
    /// The new plaintext key. Shown only once — only its hash is stored.
    pub plaintext_key: String,
}

/// Handles POST /api/v1/keys/:id/rotate — generates a new secret for an existing key, returning
/// the plaintext once while immediately invalidating the previous secret (the old `key_hash` is
/// overwritten, not kept around).
pub async fn rotate_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let prefix = plaintext_key.chars().take(8).collect::<String>();

    let mut active: api_key::ActiveModel = target.into();
    active.key_hash = Set(key_hash);
    active.prefix = Set(prefix);
    active.updated_at = Set(Utc::now().naive_utc());
    active.update(&state.db).await?;

    create_audit_log(&state.db, Some(key.id), "KEY_ROTATE", None, None, Some(id.to_string())).await?;

    Ok(Json(RotateKeyResponse { id, plaintext_key }))
}

/// Handles POST /api/v1/keys/:id/groups
pub async fn update_key_group_permissions(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Path(id): Path<Uuid>,
    Json(payload): Json<GroupPermInput>,
) -> Result<impl IntoResponse, AppError> {

    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target_key = ApiKey::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    
    if target_key.is_master {
        return Err(AppError::InvalidInput("Cannot configure M:N permissions on a master key".to_owned()));
    }

    let target_group_id: Uuid;
    let resolved_group_name: String;
    let existing_group = resolve_group_ref(&state.db, payload.group_id, payload.group_name.as_deref()).await?;

    if let Some(g) = existing_group {
        target_group_id = g.id;
        resolved_group_name = g.name;
    } else if let Some(group_name) = &payload.group_name {
        if !key.is_master && !key.can_create_groups {
            return Err(AppError::Forbidden("Permission denied: Target group does not exist and you cannot create groups".to_owned()));
        }

        let group = get_or_create_group(&state.db, group_name, "banlist").await?;
        target_group_id = group.id;
        resolved_group_name = group.name;
    } else {
        return Err(AppError::NotFound);
    }

    let now = Utc::now().naive_utc();
    let perm_model = api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(id),
        group_id: Set(target_group_id),
        can_read: Set(payload.can_read),
        can_write: Set(payload.can_write),
        can_delete: Set(payload.can_delete),
        created_at: Set(now),
    };

    api_key_group_permission::Entity::insert(perm_model)
        .on_conflict(
            OnConflict::columns([api_key_group_permission::Column::ApiKeyId, api_key_group_permission::Column::GroupId])
                .update_columns([
                    api_key_group_permission::Column::CanRead,
                    api_key_group_permission::Column::CanWrite,
                    api_key_group_permission::Column::CanDelete,
                ])
                .to_owned()
        )
        .exec(&state.db)
        .await?;

    create_audit_log(&state.db, Some(key.id), "KEY_PERM_UPDATE", None, Some(resolved_group_name), Some(id.to_string())).await?;

    Ok(axum::http::StatusCode::OK)
}

/// Handles DELETE /api/v1/keys/:id/permissions/:group_identifier — removes a key's permission
/// mapping for a specific group. `group_identifier` may be either the group's UUID or its name.
pub async fn revoke_key_group_permission(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Path((id, group_identifier)): Path<(Uuid, String)>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let group = resolve_group_by_identifier(&state.db, &group_identifier)
        .await?
        .ok_or(AppError::NotFound)?;

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

    create_audit_log(&state.db, Some(key.id), "KEY_PERM_REVOKE", None, Some(group.name), Some(id.to_string())).await?;

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
}

/// Handles POST /api/v1/groups
pub async fn create_ip_group(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Json(payload): Json<CreateIpGroupPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_create_groups {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    let model = ip_group::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        created_at: Set(now),
    };
    ip_group::Entity::insert(model).exec(&state.db).await?;

    if !key.is_master {
        let perm = api_key_group_permission::ActiveModel {
            id: Set(Uuid::new_v4()),
            api_key_id: Set(key.id),
            group_id: Set(id),
            can_read: Set(true),
            can_write: Set(true),
            can_delete: Set(true),
            created_at: Set(now),
        };
        api_key_group_permission::Entity::insert(perm).exec(&state.db).await?;
    }
    
    create_audit_log(&state.db, Some(key.id), "GROUP_CREATE", None, Some(payload.name.clone()), None).await?;

    Ok(Json(serde_json::json!({ "id": id, "name": payload.name })))
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

/// Handles DELETE /api/v1/groups/:id
pub async fn delete_ip_group(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only the master key can strictly drop entire groups".to_owned()));
    }

    let result = IpGroup::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    
    create_audit_log(&state.db, Some(key.id), "GROUP_DELETE", None, None, Some(id.to_string())).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
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
    /// Shared secret
    pub secret_token: String,
    /// Custom headers
    pub headers_json: Option<String>,
    /// Payload Template
    pub payload_template: String,
    /// Target IP Group
    pub group_id: Uuid,
    /// Is Active
    pub is_active: Option<bool>,
}

/// Handles POST /api/v1/webhooks
pub async fn create_webhook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Json(payload): Json<CreateWebhookPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let parsed_url = reqwest::Url::parse(&payload.target_url)
        .map_err(|_| AppError::InvalidInput("Invalid target_url: must be a well-formed URL".to_owned()))?;
    if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
        return Err(AppError::InvalidInput("Invalid target_url: scheme must be http or https".to_owned()));
    }
    if parsed_url.host_str().is_none() {
        return Err(AppError::InvalidInput("Invalid target_url: missing host".to_owned()));
    }

    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    let model = webhook_config::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
        target_url: Set(payload.target_url.clone()),
        secret_token: Set(payload.secret_token.clone()),
        headers_json: Set(payload.headers_json.clone()),
        payload_template: Set(payload.payload_template.clone()),
        group_id: Set(payload.group_id),
        is_active: Set(payload.is_active.unwrap_or(true)),
        created_at: Set(now),
    };
    webhook_config::Entity::insert(model).exec(&state.db).await?;
    
    create_audit_log(&state.db, Some(key.id), "WEBHOOK_CREATE", None, None, Some(payload.target_url.clone())).await?;

    Ok(Json(serde_json::json!({ "id": id, "target_url": payload.target_url })))
}

/// Public-safe summary of a webhook configuration. Deliberately omits `secret_token`: unlike
/// `api_key.key_hash` (a hash of a high-entropy generated value), a webhook's `secret_token` is a
/// caller-supplied plaintext HMAC key — leaking it would let any reader with `can_manage_webhooks`
/// forge valid `X-Signature-256` signatures for that webhook.
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
    /// Creation timestamp
    pub created_at: chrono::NaiveDateTime,
}

impl From<webhook_config::Model> for WebhookSummary {
    fn from(w: webhook_config::Model) -> Self {
        WebhookSummary {
            id: w.id,
            name: w.name,
            target_url: w.target_url,
            headers_json: w.headers_json,
            payload_template: w.payload_template,
            group_id: w.group_id,
            is_active: w.is_active,
            created_at: w.created_at,
        }
    }
}

/// Handles GET /api/v1/webhooks
pub async fn list_webhooks(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let webhooks = WebhookConfig::find().all(&state.db).await?;
    let summaries: Vec<WebhookSummary> = webhooks.into_iter().map(WebhookSummary::from).collect();
    Ok(Json(summaries))
}

/// Handles DELETE /api/v1/webhooks/:id
pub async fn delete_webhook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let result = WebhookConfig::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    
    create_audit_log(&state.db, Some(key.id), "WEBHOOK_DELETE", None, None, Some(id.to_string())).await?;

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
