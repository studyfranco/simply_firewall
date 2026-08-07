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
    ///
    /// Not reachable through any API payload: `RBAC_MODEL.md` §5 makes master status a
    /// bootstrap-only property, and `create_api_key`/`update_api_key` reject a request that carries
    /// the field at all. The only writer is `bootstrap_master_key`.
    pub is_master: bool,
    /// Uniqueness marker, kept in lockstep with [`Self::is_master`]: [`MASTER_MARKER`] on the Master
    /// key, `NULL` on every other key.
    ///
    /// Carries no authority and is read by no guard — [`Self::is_master`] remains the flag every
    /// permission check consults. This column exists so a **unique index** can express "at most one
    /// Master" in the schema itself, which `RBAC_MODEL.md` §5 requires be enforced by the database
    /// rather than by application logic alone. See
    /// `migration::m20260807_000007_add_api_key_master_marker` for why a marker column rather than a
    /// partial unique index (MySQL has no partial indexes).
    ///
    /// `serde(default)` so a payload that omits it — every payload, since it is never settable —
    /// still deserializes.
    #[serde(default)]
    pub master_marker: Option<String>,
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
