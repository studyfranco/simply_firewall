//! The `ip_groups` table: logical, named collections of IP rules (e.g. `fail2ban`, `sshd`,
//! `vpn_whitelist`), each tagged as either a `banlist` or a `whitelist`.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A named collection of IP records, tagged as a `banlist` or `whitelist`.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_groups")]
pub struct Model {
    /// Unique identifier for the group.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Group name used in API requests and the UI. Must be unique.
    #[sea_orm(unique)]
    pub name: String,
    /// The group's type: `"banlist"` or `"whitelist"`. Defaults to `"banlist"`.
    pub group_type: String,
    /// Optional detailed description of the group's purpose.
    pub description: Option<String>,
    /// Group creation timestamp.
    pub created_at: DateTime,
}

/// Relations from `ip_groups` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Webhooks that fire on changes to IPs in this group.
    #[sea_orm(has_many = "super::webhook_config::Entity")]
    WebhookConfig,
    /// API-key permission grants scoped to this group.
    #[sea_orm(has_many = "super::api_key_group_permission::Entity")]
    ApiKeyGroupPermission,
    /// IP record memberships belonging to this group.
    #[sea_orm(has_many = "super::ip_record_group_membership::Entity")]
    IpRecordGroupMembership,
}

impl Related<super::webhook_config::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::WebhookConfig.def()
    }
}

impl Related<super::api_key_group_permission::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKeyGroupPermission.def()
    }
}

impl Related<super::ip_record_group_membership::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpRecordGroupMembership.def()
    }
}

impl Related<super::ip_record::Entity> for Entity {
    fn to() -> RelationDef {
        super::ip_record_group_membership::Relation::IpRecord.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::ip_record_group_membership::Relation::IpGroup.def().rev())
    }
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        super::api_key_group_permission::Relation::ApiKey.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::api_key_group_permission::Relation::IpGroup.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
