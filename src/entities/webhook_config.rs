use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "webhook_configs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub target_url: String,
    pub group_id: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::ip_group::Entity",
        from = "Column::GroupId",
        to = "super::ip_group::Column::Id",
        on_update = "NoAction",
        on_delete = "SetNull"
    )]
    IpGroup,
}

impl Related<super::ip_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpGroup.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
