//! The `webhook_configs` table: HTTP endpoints notified when IP events occur within a specific
//! IP group.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single webhook subscription: where to send events for a group, and how to sign/shape them.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "webhook_configs")]
pub struct Model {
    /// Unique webhook configuration ID.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable name for the webhook.
    pub name: String,
    /// HTTP/HTTPS target endpoint URL. Validated against SSRF (private/loopback/link-local
    /// targets are rejected at dispatch time) unless `ALLOW_PRIVATE_WEBHOOKS=true`.
    pub target_url: String,
    /// Shared secret used to generate the HMAC SHA-256 signature (`X-Signature-256`) on every
    /// dispatched request.
    pub secret_token: String,
    /// Custom JSON key-value object of HTTP headers to inject into requests.
    pub headers_json: Option<String>,
    /// Template string with dynamic variables (e.g.
    /// `{"ip":"$target_address","group":"$group_name"}`).
    pub payload_template: String,
    /// The IP group this webhook monitors.
    pub group_id: Uuid,
    /// Toggle to enable/disable webhook dispatching without deleting the configuration.
    pub is_active: bool,
    /// Creation timestamp.
    pub created_at: DateTime,
}

/// Relations from `webhook_configs` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The IP group this webhook is scoped to.
    #[sea_orm(
        belongs_to = "super::ip_group::Entity",
        from = "Column::GroupId",
        to = "super::ip_group::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    IpGroup,
}

impl Related<super::ip_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpGroup.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
