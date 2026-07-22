use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_record_group_memberships")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub ip_record_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub group_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::ip_record::Entity",
        from = "Column::IpRecordId",
        to = "super::ip_record::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    IpRecord,
    #[sea_orm(
        belongs_to = "super::ip_group::Entity",
        from = "Column::GroupId",
        to = "super::ip_group::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    IpGroup,
}

impl Related<super::ip_record::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpRecord.def()
    }
}

impl Related<super::ip_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpGroup.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
