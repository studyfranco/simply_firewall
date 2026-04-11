use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_groups")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::ip_record::Entity")]
    IpRecord,
    #[sea_orm(has_many = "super::webhook_config::Entity")]
    WebhookConfig,
    #[sea_orm(has_many = "super::api_key_group_permission::Entity")]
    ApiKeyGroupPermission,
}

impl Related<super::ip_record::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpRecord.def()
    }
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

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        super::api_key_group_permission::Relation::ApiKey.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::api_key_group_permission::Relation::IpGroup.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
