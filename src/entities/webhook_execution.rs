//! The `webhook_executions` table: one row per outbound HTTP attempt a webhook dispatch makes,
//! including retries. The delivery history behind the dashboard's "Executions" tab.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// One HTTP attempt's outcome, on the way to or from `webhook_configs`.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "webhook_executions")]
pub struct Model {
    /// Unique execution row ID.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The webhook this attempt was dispatched for. `ON DELETE CASCADE` — see the migration's
    /// module header for why this row has no useful existence once its webhook is gone.
    pub webhook_id: Uuid,
    /// `IP_ADD`, `IP_UPDATE`, `IP_DELETE` (matching `webhook_configs.events`/`audit_logs.action`'s
    /// vocabulary), or `TEST` for a live "Test Webhook" dispatch.
    pub event_type: String,
    /// The HTTP status code received, if a response was received at all. `None` for a network-level
    /// failure (timeout, connection refused, DNS failure) — [`dispatch::DispatchOutcome`]'s own
    /// `status: Option<u16>` maps onto this column exactly.
    ///
    /// [`dispatch::DispatchOutcome`]: crate::dispatch::DispatchOutcome
    pub status_code: Option<i32>,
    /// Whether the receiver answered with a `2xx` status. The column the retention sweep and the
    /// executions listing's status filter both read — `status_code` is diagnostic detail, this is
    /// the outcome.
    pub is_success: bool,
    /// Wall-clock duration of this one HTTP attempt, in milliseconds. Not cumulative across
    /// retries — each retry attempt is its own row.
    pub duration_ms: i32,
    /// The failure reason, when there was one: `DispatchOutcome::Transient`/`Permanent`'s `reason`
    /// string, or a response-body snippet. `None` on success.
    pub error_message: Option<String>,
    /// When this attempt was made.
    pub created_at: DateTime,
}

/// Relations from `webhook_executions` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The webhook this attempt was dispatched for.
    #[sea_orm(
        belongs_to = "super::webhook_config::Entity",
        from = "Column::WebhookId",
        to = "super::webhook_config::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    WebhookConfig,
}

impl Related<super::webhook_config::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::WebhookConfig.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
