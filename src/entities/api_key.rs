use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub key_hash: String,
    pub name: String,
    pub bound_ips: String, // Comma-separated CIDRs
    pub is_master: bool,
    pub can_manage_keys: bool,
    pub can_manage_webhooks: bool,
    pub can_create_groups: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::api_key_group_permission::Entity")]
    ApiKeyGroupPermission,
}

impl Related<super::api_key_group_permission::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKeyGroupPermission.def()
    }
}

impl Related<super::ip_group::Entity> for Entity {
    fn to() -> RelationDef {
        super::api_key_group_permission::Relation::IpGroup.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::api_key_group_permission::Relation::ApiKey.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
