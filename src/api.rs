use axum::{
    extract::{Json, Path, Query, State},
    response::IntoResponse,
};
use chrono::Utc;
use ipnetwork::IpNetwork;
use rand::Rng;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
    sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entities::{api_key, ip_group, ip_record, webhook_config, prelude::*};
use crate::error::AppError;
use crate::state::{AppState, WebhookEvent};

// ─────────────────────────────────────────────────────────────
// IP Ban / Whitelist
// ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BanWhitePayload {
    pub target_address: String,
    pub group_name: Option<String>,
    pub cause: Option<String>,
}

pub async fn handle_ban(
    State(state): State<AppState>,
    Json(payload): Json<BanWhitePayload>,
) -> Result<impl IntoResponse, AppError> {
    handle_ip_upsert(state, payload, false).await
}

pub async fn handle_white(
    State(state): State<AppState>,
    Json(payload): Json<BanWhitePayload>,
) -> Result<impl IntoResponse, AppError> {
    handle_ip_upsert(state, payload, true).await
}

async fn handle_ip_upsert(
    state: AppState,
    payload: BanWhitePayload,
    is_whitelist: bool,
) -> Result<impl IntoResponse, AppError> {
    // Strict IP Network Validation
    let network: IpNetwork = payload.target_address.parse()
        .map_err(|_| AppError::InvalidInput("Invalid IP or CIDR format".to_owned()))?;

    // Check if protected (is_locked)
    let existing = ip_record::Entity::find()
        .filter(ip_record::Column::Address.eq(payload.target_address.clone()))
        .one(&state.db)
        .await?;

    if let Some(record) = existing {
        if record.is_locked {
            return Err(AppError::Forbidden("This IP is protected and cannot be modified".to_owned()));
        }
    }

    // Rule: Don't allow banning loopback, unspecified, link-local, or private if it's a "ban" action
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
    let mut group_id = None;
    if let Some(name) = &payload.group_name {
        let existing_group = ip_group::Entity::find()
            .filter(ip_group::Column::Name.eq(name))
            .one(&state.db)
            .await?;

        if let Some(g) = existing_group {
            group_id = Some(g.id);
        } else {
            let id = Uuid::new_v4();
            let new_group = ip_group::ActiveModel {
                id: Set(id),
                name: Set(name.clone()),
            };
            ip_group::Entity::insert(new_group).exec(&state.db).await?;
            group_id = Some(id);
        }
    }

    let now = Utc::now().naive_utc();
    
    // SeaORM Upsert (On Conflict)
    let model = ip_record::ActiveModel {
        id: Set(Uuid::new_v4()),
        address: Set(payload.target_address.clone()),
        is_whitelist: Set(is_whitelist),
        group_id: Set(group_id),
        cause: Set(payload.cause.clone()),
        is_locked: Set(false), // Default to false for new entries
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
        address: payload.target_address.clone(),
        is_whitelist,
        group_id,
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
    Query(filters): Query<QueryFilters>,
) -> Result<impl IntoResponse, AppError> {
    use sea_orm::QuerySelect;

    let mut query = ip_record::Entity::find()
        .find_also_related(ip_group::Entity);

    if let Some(st) = &filters.status {
        match st.as_str() {
            "ban" => query = query.filter(ip_record::Column::IsWhitelist.eq(false)),
            "white" => query = query.filter(ip_record::Column::IsWhitelist.eq(true)),
            _ => {}
        }
    }

    if let Some(name) = &filters.group_name {
        query = query.filter(ip_group::Column::Name.eq(name));
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

// ─────────────────────────────────────────────────────────────
// Admin CRUD — API Keys
// ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateApiKeyPayload {
    pub bound_ip: String, // CIDR e.g. "0.0.0.0/0"
}

#[derive(Serialize)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub plaintext_key: String,
    pub bound_ip: String,
}

pub async fn create_api_key(
    State(state): State<AppState>,
    Json(payload): Json<CreateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    let _: IpNetwork = payload.bound_ip.parse()
        .map_err(|_| AppError::InvalidInput("Invalid bound IP CIDR".to_owned()))?;

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let id = Uuid::new_v4();

    let model = api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(key_hash),
        bound_ip: Set(payload.bound_ip.clone()),
    };

    api_key::Entity::insert(model).exec(&state.db).await?;

    Ok(Json(CreateApiKeyResponse {
        id,
        plaintext_key,
        bound_ip: payload.bound_ip,
    }))
}

pub async fn list_api_keys(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let keys = ApiKey::find().all(&state.db).await?;
    Ok(Json(keys))
}

pub async fn delete_api_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let result = ApiKey::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
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
    Json(payload): Json<CreateIpGroupPayload>,
) -> Result<impl IntoResponse, AppError> {
    let id = Uuid::new_v4();
    let model = ip_group::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
    };
    ip_group::Entity::insert(model).exec(&state.db).await?;
    Ok(Json(serde_json::json!({ "id": id, "name": payload.name })))
}

pub async fn list_ip_groups(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let groups = IpGroup::find().all(&state.db).await?;
    Ok(Json(groups))
}

pub async fn delete_ip_group(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
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
    pub group_id: Option<Uuid>,
}

pub async fn create_webhook(
    State(state): State<AppState>,
    Json(payload): Json<CreateWebhookPayload>,
) -> Result<impl IntoResponse, AppError> {
    let id = Uuid::new_v4();
    let model = webhook_config::ActiveModel {
        id: Set(id),
        target_url: Set(payload.target_url.clone()),
        group_id: Set(payload.group_id),
    };
    webhook_config::Entity::insert(model).exec(&state.db).await?;
    Ok(Json(serde_json::json!({ "id": id, "target_url": payload.target_url })))
}

pub async fn list_webhooks(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let webhooks = WebhookConfig::find().all(&state.db).await?;
    Ok(Json(webhooks))
}

pub async fn delete_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
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
