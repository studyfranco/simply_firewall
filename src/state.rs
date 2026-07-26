//! Application State

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
}
