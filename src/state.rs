//! Application State

use std::sync::Arc;

use ipnetwork::IpNetwork;
use sea_orm::DatabaseConnection;
use tokio::sync::mpsc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

/// Represents a webhook event triggered by the system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// The action that occurred: `"IP_ADD"`, `"IP_UPDATE"`, or `"IP_DELETE"` — matches
    /// `audit_log::Model::action`'s vocabulary and is what `webhook_config::Model::events`
    /// filters against in the dispatcher.
    pub action: String,
    /// Target address
    pub address: String,
    /// Is whitelist
    pub is_whitelist: bool,
    /// Associated group ID
    pub group_id: Option<Uuid>,
    /// Cause for the event
    pub cause: Option<String>,
}

/// Global application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub db: DatabaseConnection,
    /// Channel sender for webhook events
    pub webhook_tx: mpsc::Sender<WebhookEvent>,
    /// Networks whose members are allowed to set `X-Forwarded-For`/`X-Real-IP`, from
    /// [`TRUSTED_PROXIES`](crate::config::TRUSTED_PROXIES_ENV).
    ///
    /// Resolved once at startup and carried in state rather than re-read from the environment per
    /// request: this is an authorization input, and a value that can change under a running process
    /// is one that cannot be reasoned about. `Arc` keeps `AppState: Clone` cheap — axum clones it
    /// for every request.
    ///
    /// **Empty means no proxy is trusted**, so forwarding headers are ignored entirely. See
    /// [`crate::config::resolve_client_ip`].
    pub trusted_proxies: Arc<Vec<IpNetwork>>,
}

impl AppState {
    /// Builds state with the trusted-proxy list read from the environment. The normal constructor.
    pub fn new(db: DatabaseConnection, webhook_tx: mpsc::Sender<WebhookEvent>) -> Self {
        Self::with_trusted_proxies(db, webhook_tx, crate::config::trusted_proxies_from_env())
    }

    /// Builds state with an explicit trusted-proxy list, bypassing the environment.
    ///
    /// Exists for tests, which need to exercise both the trusted and untrusted paths within one
    /// process — something a process-wide environment variable cannot express.
    pub fn with_trusted_proxies(
        db: DatabaseConnection,
        webhook_tx: mpsc::Sender<WebhookEvent>,
        trusted_proxies: Vec<IpNetwork>,
    ) -> Self {
        Self { db, webhook_tx, trusted_proxies: Arc::new(trusted_proxies) }
    }
}
