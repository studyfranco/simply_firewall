//! The `webhook_configs` table: HTTP endpoints notified when IP events occur within a specific
//! IP group.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single webhook subscription: where to send events for a group, and how to sign/shape them.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "webhook_configs")]
pub struct Model {
    /// Unique webhook configuration ID.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable name for the webhook.
    pub name: String,
    /// HTTP/HTTPS target endpoint URL. Validated against SSRF (private/loopback/link-local
    /// targets are rejected at dispatch time) unless `ALLOW_PRIVATE_WEBHOOKS=true`.
    pub target_url: String,
    /// Shared secret used to generate the HMAC SHA-256 signature (`X-Signature-256`) on every
    /// dispatched request.
    pub secret_token: String,
    /// How outbound dispatches are signed — `"BODY_ONLY"` or `"CANONICAL_V1"`. See
    /// [`SignatureMode`], which is the parsed form; this column stores its string representation.
    ///
    /// Stored as a plain `String` rather than a SeaORM enum column to stay SQL-agnostic per
    /// `AGENT.MD` (a native `ENUM` type is PostgreSQL/MySQL-specific and has no SQLite equivalent).
    /// Values are validated at the API boundary, and [`SignatureMode::from_stored`] fails safe on
    /// anything unrecognized.
    pub signature_mode: String,
    /// Custom JSON key-value object of HTTP headers to inject into requests.
    pub headers_json: Option<String>,
    /// Template string with dynamic variables (e.g.
    /// `{"ip":"$target_address","group":"$group_name"}`).
    pub payload_template: String,
    /// The IP group this webhook monitors.
    pub group_id: Uuid,
    /// Toggle to enable/disable webhook dispatching without deleting the configuration.
    pub is_active: bool,
    /// Comma-separated subset of `IP_ADD`/`IP_UPDATE`/`IP_DELETE` this webhook should fire for.
    /// `None` means all events (the historical, pre-filtering behavior).
    pub events: Option<String>,
    /// Creation timestamp.
    pub created_at: DateTime,
}

/// How an outbound webhook dispatch computes its `X-Signature-256`.
///
/// Kept as a real type rather than stringly-typed comparisons scattered through the dispatcher, so
/// adding a future mode is a compiler-enforced exhaustive match instead of a hunt for `==` checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureMode {
    /// HMAC-SHA256 over the raw request body only, sent as `X-Signature-256: sha256=<hex>`.
    ///
    /// The original behaviour and the default, kept for generic third-party receivers (GitHub-style
    /// webhook consumers) that expect exactly this and would reject anything else.
    BodyOnly,
    /// HMAC-SHA256 over `POST\n<path>\n<timestamp>\n<raw_body>`, sent as bare hex alongside an
    /// `X-Timestamp` header.
    ///
    /// Byte-for-byte the same construction the inbound API middleware verifies, which is what lets
    /// one `simply_ip_vault` instance dispatch directly into another's authenticated API (and what
    /// `simply_hook_executor` expects).
    CanonicalV1,
}

impl SignatureMode {
    /// The string written to `webhook_configs.signature_mode`.
    pub const BODY_ONLY: &'static str = "BODY_ONLY";
    /// The string written to `webhook_configs.signature_mode` for canonical signing.
    pub const CANONICAL_V1: &'static str = "CANONICAL_V1";

    /// Every accepted value, for API validation and error messages.
    pub const ALL: [&'static str; 2] = [Self::BODY_ONLY, Self::CANONICAL_V1];

    /// Parses a caller-supplied value, accepting any casing. `None` if unrecognized.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            Self::BODY_ONLY => Some(Self::BodyOnly),
            Self::CANONICAL_V1 => Some(Self::CanonicalV1),
            _ => None,
        }
    }

    /// Parses a value already persisted in the database, falling back to [`Self::BodyOnly`].
    ///
    /// Fails *safe* rather than erroring: a row with an unrecognized mode (hand-edited SQL, or a
    /// downgrade after a future mode is added) still dispatches under the conservative legacy
    /// scheme instead of silently dropping the event or panicking inside the worker.
    pub fn from_stored(value: &str) -> Self {
        Self::parse(value).unwrap_or_else(|| {
            tracing::warn!(
                "Unrecognized webhook signature_mode {:?} in database; falling back to {}",
                value,
                Self::BODY_ONLY
            );
            Self::BodyOnly
        })
    }

    /// The canonical string representation, for storage and API responses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BodyOnly => Self::BODY_ONLY,
            Self::CanonicalV1 => Self::CANONICAL_V1,
        }
    }
}

/// Relations from `webhook_configs` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The IP group this webhook is scoped to.
    #[sea_orm(
        belongs_to = "super::ip_group::Entity",
        from = "Column::GroupId",
        to = "super::ip_group::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    IpGroup,
}

impl Related<super::ip_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpGroup.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
