//! The `ip_records` table: banned or whitelisted IP addresses and CIDR subnets. A record is
//! shared across every group it belongs to via
//! [`ip_record_group_membership`](crate::entities::ip_record_group_membership).

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
    /// Whether the record has been soft-deleted.
    ///
    /// A soft-deleted record is hidden from every normal read and from webhook dispatch, but the
    /// row survives for the retention window in [`crate::retention`] so a master key can inspect or
    /// restore it. `NOT NULL` with a `false` default: there is no "unknown" state, and a nullable
    /// flag would make every read filter spell out `IS NULL OR = false`.
    pub is_deleted: bool,
    /// When the soft delete happened; `None` while the record is live.
    ///
    /// This — not `updated_at` — is what the 92-day purge measures against, so restoring and
    /// re-deleting a record restarts its retention window rather than inheriting an old one.
    pub deleted_at: Option<DateTime>,
    /// The `api_keys.id` of whoever soft-deleted the record, as text; `None` while live.
    ///
    /// Stored as text rather than a foreign key so the attribution outlives the key that performed
    /// the deletion — a FK would either block deleting that key or null this out, and an
    /// attribution that disappears with its actor is not an attribution.
    pub deleted_by: Option<String>,
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
