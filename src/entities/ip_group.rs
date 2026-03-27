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

impl ActiveModelBehavior for ActiveModel {}
