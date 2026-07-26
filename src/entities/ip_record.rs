//! The `ip_records` table: banned or whitelisted IP addresses and CIDR subnets. A record is
//! shared across every group it belongs to via [`ip_record_group_membership`](super::ip_record_group_membership).

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single IP address or CIDR range tracked by the firewall.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_records")]
pub struct Model {
    /// Unique record identifier.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Valid IPv4/IPv6 address or CIDR range (e.g. `192.168.1.50/32`, `2001:db8::/32`), stored
    /// exactly as submitted. Unique: re-registering the same address updates the existing row
    /// (`last_seen_at`) instead of creating a duplicate.
    #[sea_orm(unique)]
    pub target_address: String,
    /// Reason for adding the IP record.
    pub cause: Option<String>,
    /// When `true`, the record is protected: it cannot be updated or deleted through the API
    /// regardless of the caller's permissions. Nothing in the current API sets this to `true`;
    /// it exists as a manual/administrative safeguard for protecting critical records at the
    /// data layer.
    pub is_locked: bool,
    /// Initial insertion timestamp.
    pub created_at: DateTime,
    /// Timestamp of the last field update (cause change or re-registration).
    pub updated_at: DateTime,
    /// Timestamp of last re-registration or recorded activity.
    pub last_seen_at: DateTime,
}

/// Relations from `ip_records` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Group memberships this record participates in.
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
