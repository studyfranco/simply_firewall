//! IP Group endpoints: creation, listing, deletion, and owner reassignment.
//!
//! The specification's *managed resource* — shared, carrying per-key permission rows, and governed
//! by the R2 conjunction.


use axum::{
    extract::{Json, State, Path},
    response::IntoResponse,
    Extension,
};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, Condition, ActiveModelTrait, SqlErr,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::entities::{
    api_key, api_key_group_permission, ip_group,
};
use crate::error::AppError;
use crate::middleware::ClientIp;
use crate::state::AppState;
use super::*;


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
