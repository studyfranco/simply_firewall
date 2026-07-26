//! The `ip_record_group_memberships` M:N junction table, associating an IP record with one or
//! more IP groups.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single (IP record, IP group) membership row.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_record_group_memberships")]
pub struct Model {
    /// The IP record this membership refers to. Part of the composite primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub ip_record_id: Uuid,
    /// The IP group this membership refers to. Part of the composite primary key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub group_id: Uuid,
}

/// Relations from `ip_record_group_memberships` to the entities it joins.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The IP record side of the membership.
    #[sea_orm(
        belongs_to = "super::ip_record::Entity",
        from = "Column::IpRecordId",
        to = "super::ip_record::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    IpRecord,
    /// The IP group side of the membership.
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
