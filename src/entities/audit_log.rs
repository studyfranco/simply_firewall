//! The `audit_logs` table: the security audit trail tracking mutating operations across the
//! application.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single audit trail entry for a mutating operation.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "audit_logs")]
pub struct Model {
    /// Unique audit log entry ID.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The API key that performed the action, if any (`None` for system/bootstrap actions, or
    /// if the key was later deleted).
    pub api_key_id: Option<Uuid>,
    /// Operation type, e.g. `IP_ADD`, `IP_DELETE`, `KEY_CREATE`, `KEY_DELETE`, `KEY_PERM_UPDATE`,
    /// `GROUP_CREATE`, `GROUP_DELETE`, `WEBHOOK_CREATE`, `WEBHOOK_DELETE` (non-exhaustive).
    pub action: String,
    /// Target IP or CIDR range affected, if applicable.
    pub target_address: Option<String>,
    /// Comma-separated list of group names involved, if applicable.
    pub group_names: Option<String>,
    /// Additional context or a raw payload overview.
    pub details: Option<String>,
    /// Log creation timestamp.
    pub timestamp: DateTime,
}

/// Relations from `audit_logs` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The API key that performed the audited action.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id",
        on_update = "NoAction",
        on_delete = "SetNull"
    )]
    ApiKey,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
