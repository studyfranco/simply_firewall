use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_records")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(unique)]
    pub target_address: String,
    pub cause: Option<String>,
    pub is_locked: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    pub last_seen_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::ip_record_group_membership::Entity")]
    IpRecordGroupMembership,
}

impl Related<super::ip_record_group_membership::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpRecordGroupMembership.def()
    }
}

impl Related<super::ip_group::Entity> for Entity {
    fn to() -> RelationDef {
        super::ip_record_group_membership::Relation::IpGroup.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::ip_record_group_membership::Relation::IpRecord.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
