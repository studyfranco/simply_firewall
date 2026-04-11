use axum::{
    extract::{Json, Path, Query, State},
    response::IntoResponse,
    Extension,
};
use chrono::{Utc, NaiveDateTime};
use ipnetwork::IpNetwork;
use rand::Rng;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
    sea_query::OnConflict, Condition, QuerySelect,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entities::{api_key, api_key_group_permission, ip_group, ip_record, webhook_config, prelude::*};
use crate::error::AppError;
use crate::state::{AppState, WebhookEvent};

// ─────────────────────────────────────────────────────────────
// IP Ban / Whitelist
// ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BanWhitePayload {
    pub target_address: String,
    pub group_name: String,
    pub cause: Option<String>,
}

pub async fn handle_ban(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Json(payload): Json<BanWhitePayload>,
) -> Result<impl IntoResponse, AppError> {
    handle_ip_upsert(state, key, payload, false).await
}

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

    // Resolve or create IP Group
    let target_group_id: Uuid;
    
    let existing_group = ip_group::Entity::find()
        .filter(ip_group::Column::Name.eq(&payload.group_name))
        .one(&state.db)
        .await?;

    if let Some(g) = existing_group {
        target_group_id = g.id;
        
        // M:N RBAC verify write permissions
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
        // Auto-provision logic if doesn't exist
        if !key.is_master && !key.can_create_groups {
            return Err(AppError::Forbidden("Permission denied: Target group does not exist and you cannot create groups".to_owned()));
        }

        let new_id = Uuid::new_v4();
        let new_group = ip_group::ActiveModel {
            id: Set(new_id),
            name: Set(payload.group_name.clone()),
        };
        ip_group::Entity::insert(new_group).exec(&state.db).await?;
        target_group_id = new_id;

        // Auto insert permission for non-master
        if !key.is_master {
            let perm = api_key_group_permission::ActiveModel {
                api_key_id: Set(key.id),
                group_id: Set(target_group_id),
                can_read: Set(true),
                can_write: Set(true),
                can_delete: Set(true),
            };
            api_key_group_permission::Entity::insert(perm).exec(&state.db).await?;
        }
    }

    let existing = ip_record::Entity::find()
        .filter(ip_record::Column::Address.eq(payload.target_address.clone()))
        .one(&state.db)
        .await?;

    if let Some(record) = existing {
        if record.is_locked {
            return Err(AppError::Forbidden("This IP is protected and cannot be modified".to_owned()));
        }
    }

    let now = Utc::now().naive_utc();
    
    let model = ip_record::ActiveModel {
        id: Set(Uuid::new_v4()),
        address: Set(payload.target_address.clone()),
        is_whitelist: Set(is_whitelist),
        group_id: Set(Some(target_group_id)),
        cause: Set(payload.cause.clone()),
        is_locked: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };

    ip_record::Entity::insert(model)
        .on_conflict(
            OnConflict::column(ip_record::Column::Address)
                .update_columns([
                    ip_record::Column::IsWhitelist,
                    ip_record::Column::GroupId,
                    ip_record::Column::Cause,
                    ip_record::Column::UpdatedAt,
                ])
                .to_owned()
        )
        .exec(&state.db)
        .await?;

    // Dispatch webhook asynchronously
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
// IP Record Listing
// ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct QueryFilters {
    pub ip: Option<String>,
    pub cause: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub status: Option<String>,
    pub group_name: Option<String>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

#[derive(Serialize)]
pub struct IpRecordResponse {
    pub id: Uuid,
    pub address: String,
    pub is_whitelist: bool,
    pub group_id: Option<Uuid>,
    pub group_name: Option<String>,
    pub cause: Option<String>,
    pub is_locked: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

pub async fn list_ips(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Query(filters): Query<QueryFilters>,
) -> Result<impl IntoResponse, AppError> {
    let mut query = ip_record::Entity::find()
        .find_also_related(ip_group::Entity);

    // M:N filtering: If not master, join permissions and ensure can_read = true
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

        query = query.filter(ip_record::Column::GroupId.is_in(accessible_groups));
    }

    if let Some(ip) = &filters.ip {
        if !ip.is_empty() {
            query = query.filter(ip_record::Column::Address.contains(ip));
        }
    }

    if let Some(cause) = &filters.cause {
        if !cause.is_empty() {
            query = query.filter(ip_record::Column::Cause.contains(cause));
        }
    }

    if let Some(st) = &filters.status {
        match st.as_str() {
            "ban" => query = query.filter(ip_record::Column::IsWhitelist.eq(false)),
            "white" => query = query.filter(ip_record::Column::IsWhitelist.eq(true)),
            _ => {}
        }
    }

    if let Some(name) = &filters.group_name {
        if !name.is_empty() {
            query = query.filter(ip_group::Column::Name.eq(name));
        }
    }

    if let (Some(start), Some(end)) = (&filters.start_date, &filters.end_date) {
        if let (Ok(s), Ok(e)) = (NaiveDateTime::parse_from_str(start, "%Y-%m-%dT%H:%M:%S"), NaiveDateTime::parse_from_str(end, "%Y-%m-%dT%H:%M:%S")) {
            query = query.filter(
                Condition::all()
                    .add(ip_record::Column::CreatedAt.gte(s))
                    .add(ip_record::Column::CreatedAt.lte(e))
            );
        }
    }

    let limit = filters.limit.unwrap_or(20);
    let offset = filters.offset.unwrap_or(0);

    let results: Vec<(ip_record::Model, Option<ip_group::Model>)> = query
        .order_by_desc(ip_record::Column::UpdatedAt)
        .limit(limit)
        .offset(offset)
        .all(&state.db)
        .await?;
    
    let items: Vec<IpRecordResponse> = results.into_iter().map(|(record, group)| {
        IpRecordResponse {
            id: record.id,
            address: record.address,
            is_whitelist: record.is_whitelist,
            group_id: record.group_id,
            group_name: group.map(|g| g.name),
            cause: record.cause,
            is_locked: record.is_locked,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }).collect();
    
    Ok(Json(items))
}

pub async fn delete_ip(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {

    let record = ip_record::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if let Some(gid) = record.group_id {
        if !key.is_master {
            let perm = api_key_group_permission::Entity::find()
                .filter(
                    Condition::all()
                        .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                        .add(api_key_group_permission::Column::GroupId.eq(gid))
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
    }

    if record.is_locked {
        return Err(AppError::Forbidden("Protected records cannot be deleted".to_owned()));
    }

    ip_record::Entity::delete_by_id(id).exec(&state.db).await?;

    let event = WebhookEvent {
        event_type: "delete".to_owned(),
        address: record.address.clone(),
        is_whitelist: record.is_whitelist,
        group_id: record.group_id,
        cause: Some("Deleted via API".to_owned()),
    };
    let _ = state.webhook_tx.send(event).await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// Auth Handlers
// ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct MePermission {
    pub group_id: Uuid,
    pub group_name: String,
    pub can_read: bool,
    pub can_write: bool,
    pub can_delete: bool,
}

#[derive(Serialize)]
pub struct MeResponse {
    pub id: Uuid,
    pub name: String,
    pub bound_ips: String,
    pub is_master: bool,
    pub can_manage_keys: bool,
    pub can_manage_webhooks: bool,
    pub can_create_groups: bool,
    pub group_permissions: Vec<MePermission>,
}

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

#[derive(Deserialize)]
pub struct GroupPermInput {
    pub group_name: String,
    pub can_read: bool,
    pub can_write: bool,
    pub can_delete: bool,
}

#[derive(Deserialize)]
pub struct CreateApiKeyPayload {
    pub name: String,
    pub bound_ips: String,
    pub is_master: Option<bool>,
    pub can_manage_keys: Option<bool>,
    pub can_manage_webhooks: Option<bool>,
    pub can_create_groups: Option<bool>,
}

#[derive(Serialize)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub plaintext_key: String,
    pub name: String,
    pub bound_ips: String,
}

pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Json(payload): Json<CreateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    for cidr in payload.bound_ips.split(',') {
        let _ : IpNetwork = cidr.trim().parse()
            .map_err(|_| AppError::InvalidInput(format!("Invalid CIDR: {}", cidr)))?;
    }

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let id = Uuid::new_v4();

    let model = api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(key_hash),
        name: Set(payload.name.clone()),
        bound_ips: Set(payload.bound_ips.clone()),
        is_master: Set(payload.is_master.unwrap_or(false)),
        can_manage_keys: Set(payload.can_manage_keys.unwrap_or(false)),
        can_manage_webhooks: Set(payload.can_manage_webhooks.unwrap_or(false)),
        can_create_groups: Set(payload.can_create_groups.unwrap_or(false)),
    };

    api_key::Entity::insert(model).exec(&state.db).await?;

    Ok(Json(CreateApiKeyResponse {
        id,
        plaintext_key,
        name: payload.name,
        bound_ips: payload.bound_ips,
    }))
}

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
    Ok(axum::http::StatusCode::NO_CONTENT)
}

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
        let new_group = ip_group::ActiveModel {
            id: Set(new_id),
            name: Set(payload.group_name.clone()),
        };
        ip_group::Entity::insert(new_group).exec(&state.db).await?;
        target_group_id = new_id;
    }

    let perm_model = api_key_group_permission::ActiveModel {
        api_key_id: Set(id),
        group_id: Set(target_group_id),
        can_read: Set(payload.can_read),
        can_write: Set(payload.can_write),
        can_delete: Set(payload.can_delete),
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

    Ok(axum::http::StatusCode::OK)
}

// ─────────────────────────────────────────────────────────────
// Admin CRUD — IP Groups
// ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateIpGroupPayload {
    pub name: String,
}

pub async fn create_ip_group(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Json(payload): Json<CreateIpGroupPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_create_groups {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let id = Uuid::new_v4();
    let model = ip_group::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
    };
    ip_group::Entity::insert(model).exec(&state.db).await?;

    if !key.is_master {
        let perm = api_key_group_permission::ActiveModel {
            api_key_id: Set(key.id),
            group_id: Set(id),
            can_read: Set(true),
            can_write: Set(true),
            can_delete: Set(true),
        };
        api_key_group_permission::Entity::insert(perm).exec(&state.db).await?;
    }

    Ok(Json(serde_json::json!({ "id": id, "name": payload.name })))
}

pub async fn list_ip_groups(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    
    // Non-masters can only list groups they have read access to
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
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// Admin CRUD — Webhooks
// ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateWebhookPayload {
    pub target_url: String,
    pub trigger_events: String,
    pub auth_header_name: Option<String>,
    pub auth_token: Option<String>,
    pub payload_template: String,
    pub group_id: Option<Uuid>,
}

pub async fn create_webhook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Json(payload): Json<CreateWebhookPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let id = Uuid::new_v4();
    let model = webhook_config::ActiveModel {
        id: Set(id),
        target_url: Set(payload.target_url.clone()),
        trigger_events: Set(payload.trigger_events.clone()),
        auth_header_name: Set(payload.auth_header_name.clone()),
        auth_token: Set(payload.auth_token.clone()),
        payload_template: Set(payload.payload_template.clone()),
        group_id: Set(payload.group_id),
    };
    webhook_config::Entity::insert(model).exec(&state.db).await?;
    Ok(Json(serde_json::json!({ "id": id, "target_url": payload.target_url })))
}

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
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

pub fn generate_random_key() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

pub fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}
