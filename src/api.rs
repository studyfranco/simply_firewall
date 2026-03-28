use axum::{
    extract::{Json, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use ipnetwork::IpNetwork;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, PaginatorTrait};
use serde::Deserialize;
use uuid::Uuid;

use crate::entities::{ip_record, prelude::*};
use crate::state::{AppState, WebhookEvent};

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
        created_at: Set(now),
        updated_at: Set(now),
    };

    let on_conflict = sea_orm::sea_query::OnConflict::column(ip_record::Column::Address)
        .update_columns([
            ip_record::Column::UpdatedAt,
            ip_record::Column::GroupId,
            ip_record::Column::IsWhitelist,
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
