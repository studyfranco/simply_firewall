use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use ipnetwork::IpNetwork;
use rand::Rng;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
    PaginatorTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entities::{api_key, ip_group, ip_record, webhook_config, prelude::*};
use crate::state::{AppState, WebhookEvent};

// ─────────────────────────────────────────────────────────────
// IP Ban / Whitelist
// ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BanWhitePayload {
    pub address: String, // IP or CIDR
    pub group_id: Option<Uuid>,
    pub cause: Option<String>,
}

pub async fn handle_ban(
    State(state): State<AppState>,
    Json(payload): Json<BanWhitePayload>,
) -> Result<impl IntoResponse, StatusCode> {
    handle_ip_upsert(state, payload, false).await
}

pub async fn handle_white(
    State(state): State<AppState>,
    Json(payload): Json<BanWhitePayload>,
) -> Result<impl IntoResponse, StatusCode> {
    handle_ip_upsert(state, payload, true).await
}

async fn handle_ip_upsert(
    state: AppState,
    payload: BanWhitePayload,
    is_whitelist: bool,
) -> Result<impl IntoResponse, StatusCode> {
    let address = payload.address.clone();
    let network: IpNetwork = address.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    if !is_whitelist {
        let ip = network.network();
        if ip.is_loopback() || ip.is_unspecified() {
            return Err(StatusCode::BAD_REQUEST);
        }

        match ip {
            std::net::IpAddr::V4(v4) => {
                if v4.is_private() || v4.is_link_local() {
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
            std::net::IpAddr::V6(v6) => {
                let is_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
                let is_unique_local = (v6.segments()[0] & 0xfe00) == 0xfc00;
                if v6.is_loopback() || v6.is_unspecified() || is_link_local || is_unique_local {
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }
    }

    let now = Utc::now().naive_utc();
    let model = ip_record::ActiveModel {
        id: Set(Uuid::new_v4()),
        address: Set(address.clone()),
        is_whitelist: Set(is_whitelist),
        group_id: Set(payload.group_id),
        cause: Set(payload.cause.clone()),
        created_at: Set(now),
        updated_at: Set(now),
    };

    let on_conflict = sea_orm::sea_query::OnConflict::column(ip_record::Column::Address)
        .update_columns([
            ip_record::Column::UpdatedAt,
            ip_record::Column::GroupId,
            ip_record::Column::IsWhitelist,
            ip_record::Column::Cause,
        ])
        .to_owned();

    IpRecord::insert(model)
        .on_conflict(on_conflict)
        .exec(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Upsert failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let event = WebhookEvent {
        address,
        is_whitelist,
        group_id: payload.group_id,
        cause: payload.cause,
    };

    state.webhook_tx.send(event).await.ok();

    Ok(StatusCode::OK)
}

// ─────────────────────────────────────────────────────────────
// IP Record Listing
// ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct QueryFilters {
    pub status: Option<String>, // "ban" or "white"
    pub group_id: Option<Uuid>,
    pub updated_after: Option<chrono::NaiveDateTime>,
    pub limit: Option<u64>,
    pub page: Option<u64>,
}

pub async fn list_ips(
    State(state): State<AppState>,
    Query(filters): Query<QueryFilters>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut query = IpRecord::find();

    if let Some(st) = &filters.status {
        if st == "ban" {
            query = query.filter(ip_record::Column::IsWhitelist.eq(false));
        } else if st == "white" {
            query = query.filter(ip_record::Column::IsWhitelist.eq(true));
        }
    }

    if let Some(gid) = filters.group_id {
        query = query.filter(ip_record::Column::GroupId.eq(gid));
    }

    if let Some(date) = filters.updated_after {
        query = query.filter(ip_record::Column::UpdatedAt.gte(date));
    }

    let limit = filters.limit.unwrap_or(50);
    let page = filters.page.unwrap_or(0);

    let paginator = query
        .order_by_desc(ip_record::Column::UpdatedAt)
        .paginate(&state.db, limit);

    let results = paginator
        .fetch_page(page)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(results))
}

// ─────────────────────────────────────────────────────────────
// Admin CRUD — API Keys
// ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateApiKeyPayload {
    pub bound_ip: String, // CIDR string, e.g. "0.0.0.0/0"
}

#[derive(Serialize)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub plaintext_key: String,
    pub bound_ip: String,
}

#[derive(Serialize)]
pub struct ApiKeyListItem {
    pub id: Uuid,
    pub bound_ip: String,
}

pub async fn create_api_key(
    State(state): State<AppState>,
    Json(payload): Json<CreateApiKeyPayload>,
) -> Result<impl IntoResponse, StatusCode> {
    // Validate CIDR
    let _: IpNetwork = payload.bound_ip.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let id = Uuid::new_v4();

    let model = api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(key_hash),
        bound_ip: Set(payload.bound_ip.clone()),
    };

    api_key::Entity::insert(model)
        .exec(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create API key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(CreateApiKeyResponse {
        id,
        plaintext_key,
        bound_ip: payload.bound_ip,
    }))
}

pub async fn list_api_keys(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let keys = ApiKey::find()
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let items: Vec<ApiKeyListItem> = keys
        .into_iter()
        .map(|k| ApiKeyListItem {
            id: k.id,
            bound_ip: k.bound_ip,
        })
        .collect();

    Ok(Json(items))
}

pub async fn delete_api_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    let result = ApiKey::delete_by_id(id)
        .exec(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::NO_CONTENT)
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
) -> Result<impl IntoResponse, StatusCode> {
    let id = Uuid::new_v4();
    let model = ip_group::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
    };

    ip_group::Entity::insert(model)
        .exec(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create IP group: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({ "id": id, "name": payload.name })))
}

pub async fn list_ip_groups(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let groups = IpGroup::find()
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(groups))
}

pub async fn delete_ip_group(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    let result = IpGroup::delete_by_id(id)
        .exec(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────
// Admin CRUD — Webhook Configs
// ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateWebhookPayload {
    pub target_url: String,
    pub group_id: Option<Uuid>,
}

pub async fn create_webhook(
    State(state): State<AppState>,
    Json(payload): Json<CreateWebhookPayload>,
) -> Result<impl IntoResponse, StatusCode> {
    let id = Uuid::new_v4();
    let model = webhook_config::ActiveModel {
        id: Set(id),
        target_url: Set(payload.target_url.clone()),
        group_id: Set(payload.group_id),
    };

    webhook_config::Entity::insert(model)
        .exec(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create webhook config: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({
        "id": id,
        "target_url": payload.target_url,
        "group_id": payload.group_id
    })))
}

pub async fn list_webhooks(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let configs = WebhookConfig::find()
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(configs))
}

pub async fn delete_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    let result = WebhookConfig::delete_by_id(id)
        .exec(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::NO_CONTENT)
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
