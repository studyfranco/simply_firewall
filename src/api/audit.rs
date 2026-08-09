//! Audit log endpoint.
//!
//! Master-only, and its own module rather than a tail on another: it is the one read surface that
//! spans every domain, so filing it under any single one would be arbitrary.

use axum::{Extension, extract::{Json, Query, State}, response::IntoResponse};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;

use crate::entities::{api_key, audit_log};
use crate::error::AppError;
use crate::state::AppState;

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
