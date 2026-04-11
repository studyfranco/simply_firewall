use sea_orm::DatabaseConnection;
use tokio::sync::mpsc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub event_type: String, // "ban", "white", or "delete"
    pub address: String,
    pub is_whitelist: bool,
    pub group_id: Option<Uuid>,
    pub cause: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub webhook_tx: mpsc::Sender<WebhookEvent>,
}
