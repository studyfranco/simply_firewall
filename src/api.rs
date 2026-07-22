//! API endpoints and business logic.

use axum::{
    extract::{Json, Query, State, Path},
    response::IntoResponse,
    Extension,
};
use chrono::Utc;
use ipnetwork::IpNetwork;
use rand::Rng;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter,
    sea_query::OnConflict, Condition, QuerySelect, ActiveModelTrait,
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

// ─────────────────────────────────────────────────────────────
// IP Ban / Whitelist
// ─────────────────────────────────────────────────────────────

/// Payload for banning or whitelisting an IP address
#[derive(Deserialize)]
pub struct BanWhitePayload {
    /// The target IP address or CIDR range
    pub target_address: String,
    /// The group name to associate the IP with
    pub group_name: String,
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
    
    let existing_group = ip_group::Entity::find()
        .filter(ip_group::Column::Name.eq(&payload.group_name))
        .one(&state.db)
        .await?;

    if let Some(g) = existing_group {
        target_group_id = g.id;
        
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
    } else {
        if !key.is_master && !key.can_create_groups {
            return Err(AppError::Forbidden("Permission denied: Target group does not exist and you cannot create groups".to_owned()));
        }

        let new_id = Uuid::new_v4();
        let now = chrono::Utc::now().naive_utc();
        let new_group = ip_group::ActiveModel {
            id: Set(new_id),
            name: Set(payload.group_name.clone()),
            group_type: Set(if is_whitelist { "whitelist".to_owned() } else { "banlist".to_owned() }),
            description: Set(None),
            created_at: Set(now),
        };
        ip_group::Entity::insert(new_group).exec(&state.db).await?;
        target_group_id = new_id;

        if !key.is_master {
            let perm = api_key_group_permission::ActiveModel {
                id: Set(Uuid::new_v4()),
                api_key_id: Set(key.id),
                group_id: Set(target_group_id),
                can_read: Set(true),
                can_write: Set(true),
                can_delete: Set(true),
                created_at: Set(now),
            };
            api_key_group_permission::Entity::insert(perm).exec(&state.db).await?;
        }
    }

    let existing_record = ip_record::Entity::find()
        .filter(ip_record::Column::TargetAddress.eq(payload.target_address.clone()))
        .one(&state.db)
        .await?;

    let now = Utc::now().naive_utc();
    let record_id: Uuid;

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
    } else {
        record_id = Uuid::new_v4();
        let model = ip_record::ActiveModel {
            id: Set(record_id),
            target_address: Set(payload.target_address.clone()),
            cause: Set(payload.cause.clone()),
            is_locked: Set(false),
            created_at: Set(now),
            updated_at: Set(now),
            last_seen_at: Set(now),
        };
        ip_record::Entity::insert(model).exec(&state.db).await?;
    }

    let mem = ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record_id),
        group_id: Set(target_group_id),
    };
    ip_record_group_membership::Entity::insert(mem)
        .on_conflict(
            OnConflict::columns([ip_record_group_membership::Column::IpRecordId, ip_record_group_membership::Column::GroupId])
                .do_nothing()
                .to_owned()
        )
        .exec(&state.db)
        .await?;

    create_audit_log(
        &state.db, 
        Some(key.id), 
        "IP_ADD", 
        Some(payload.target_address.clone()), 
        Some(payload.group_name.clone()), 
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
    /// Filter by groups (comma-separated)
    pub groups: Option<String>,
    /// Maximum age in seconds
    pub max_age: Option<i64>,
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

    if let Some(groups) = &filters.groups
        && !groups.is_empty()
    {
        let group_names: Vec<&str> = groups.split(',').map(|s| s.trim()).collect();
        let gids: Vec<Uuid> = ip_group::Entity::find()
            .filter(ip_group::Column::Name.is_in(group_names))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|g| g.id)
            .collect();
        query = query.filter(ip_record_group_membership::Column::GroupId.is_in(gids));
    }

    let limit = filters.limit.unwrap_or(50);
    let offset = filters.offset.unwrap_or(0);

    let memberships = query
        .limit(limit)
        .offset(offset)
        .all(&state.db)
        .await?;
    
    let mut items = Vec::new();
    for (mem, record_opt) in memberships {
        if let Some(record) = record_opt {
            if let Some(age) = filters.max_age {
                let threshold = Utc::now().naive_utc() - chrono::Duration::seconds(age);
                if record.last_seen_at < threshold {
                    continue;
                }
            }

            let group = ip_group::Entity::find_by_id(mem.group_id).one(&state.db).await?.unwrap();

            items.push(IpRecordResponse {
                id: record.id,
                target_address: record.target_address,
                group_name: group.name,
                cause: record.cause,
                is_locked: record.is_locked,
                created_at: record.created_at,
                updated_at: record.updated_at,
                last_seen_at: record.last_seen_at,
            });
        }
    }
    
    Ok(Json(items))
}

/// Parameters for deleting an IP record from a group
#[derive(Deserialize)]
pub struct DeleteIpQuery {
    /// IP to delete
    pub target_address: String,
    /// Group to delete from
    pub group_name: String,
}

/// Handles DELETE /api/v1/ips?target_address=...&group_name=...
pub async fn delete_ip(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Query(query): Query<DeleteIpQuery>,
) -> Result<impl IntoResponse, AppError> {

    let group = ip_group::Entity::find()
        .filter(ip_group::Column::Name.eq(&query.group_name))
        .one(&state.db)
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
        .filter(ip_record::Column::TargetAddress.eq(&query.target_address))
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
        Some(query.target_address.clone()), 
        Some(query.group_name.clone()), 
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
    /// Target group
    pub group_name: String,
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

/// Handles GET /api/v1/keys
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let keys = ApiKey::find().all(&state.db).await?;
    Ok(Json(keys))
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
    let existing_group = ip_group::Entity::find()
        .filter(ip_group::Column::Name.eq(&payload.group_name))
        .one(&state.db)
        .await?;

    if let Some(g) = existing_group {
        target_group_id = g.id;
    } else {
        if !key.is_master && !key.can_create_groups {
            return Err(AppError::Forbidden("Permission denied: Target group does not exist and you cannot create groups".to_owned()));
        }

        let new_id = Uuid::new_v4();
        let now = chrono::Utc::now().naive_utc();
        let new_group = ip_group::ActiveModel {
            id: Set(new_id),
            name: Set(payload.group_name.clone()),
            group_type: Set("banlist".to_owned()),
            description: Set(None),
            created_at: Set(now),
        };
        ip_group::Entity::insert(new_group).exec(&state.db).await?;
        target_group_id = new_id;
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
        
    create_audit_log(&state.db, Some(key.id), "KEY_PERM_UPDATE", None, Some(payload.group_name.clone()), Some(id.to_string())).await?;

    Ok(axum::http::StatusCode::OK)
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

/// Handles GET /api/v1/webhooks
pub async fn list_webhooks(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let webhooks = WebhookConfig::find().all(&state.db).await?;
    Ok(Json(webhooks))
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
