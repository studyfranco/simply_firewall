//! The `api_keys` table: authentication tokens, global access rights, and CIDR network bindings.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single API key: its identity, global RBAC scopes, and network binding rule.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    /// Unique identifier for the API key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable key description.
    pub name: String,
    /// SHA-256 hash of the secret API key (the plaintext key is never stored).
    #[sea_orm(unique)]
    pub key_hash: String,
    /// The key's HMAC-SHA256 signing secret, used to verify the `X-Signature-256` request header.
    ///
    /// Unlike [`Self::key_hash`], this cannot be a one-way hash — verifying a signature requires
    /// the secret verbatim — so it is instead encrypted with AES-GCM-256 whenever
    /// `VAULT_ENCRYPTION_KEY` is configured, and stored raw otherwise (development fallback). Always
    /// read it through [`crate::crypto::open_signing_secret`] rather than using the field directly.
    ///
    /// `None` for keys created before this column existed; such keys cannot authenticate and must be
    /// rotated (`POST /api/keys/{id}/rotate`) to obtain a secret.
    ///
    /// Never serialized: `api_key::Model` derives `Serialize` and is carried in request extensions,
    /// so `skip_serializing` is a standing guard against this secret leaking into any response body
    /// that ever serializes a whole model.
    #[serde(skip_serializing)]
    #[serde(default)]
    pub signing_secret: Option<String>,
    /// First 8 characters of the plaintext key, kept for display and fast lookup.
    pub prefix: String,
    /// Comma-separated CIDR ranges allowed to use this key (e.g. `127.0.0.1/32,::/0`). An empty
    /// value means no CIDR restriction is enforced.
    pub bound_ips: Option<String>,
    /// Bypasses all group permission checks (and CIDR binding checks) when `true`.
    pub is_master: bool,
    /// Global privilege to create/edit/delete other API keys.
    pub can_manage_keys: bool,
    /// Global privilege to manage webhook configurations.
    pub can_manage_webhooks: bool,
    /// Global privilege to create new IP groups.
    pub can_create_groups: bool,
    /// Key generation timestamp.
    pub created_at: DateTime,
    /// Key last-update timestamp.
    pub updated_at: DateTime,
}

/// Relations from `api_keys` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// This key's per-group permission grants.
    #[sea_orm(has_many = "super::api_key_group_permission::Entity")]
    ApiKeyGroupPermission,
    /// Audit log entries attributed to this key.
    #[sea_orm(has_many = "super::audit_log::Entity")]
    AuditLog,
}

impl Related<super::api_key_group_permission::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKeyGroupPermission.def()
    }
}

impl Related<super::audit_log::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AuditLog.def()
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
