//! Convenience re-exports of every entity type in [`crate::entities`].

/// The `api_keys` entity.
pub use super::api_key::Entity as ApiKey;
/// The `api_key_group_permissions` entity.
pub use super::api_key_group_permission::Entity as ApiKeyGroupPermission;
/// The `ip_groups` entity.
pub use super::ip_group::Entity as IpGroup;
/// The `ip_records` entity.
pub use super::ip_record::Entity as IpRecord;
/// The `ip_record_group_memberships` entity.
pub use super::ip_record_group_membership::Entity as IpRecordGroupMembership;
/// The `webhook_configs` entity.
pub use super::webhook_config::Entity as WebhookConfig;
/// The `audit_logs` entity.
pub use super::audit_log::Entity as AuditLog;
