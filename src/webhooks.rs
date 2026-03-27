use crate::entities::{prelude::*, webhook_config};
use crate::state::WebhookEvent;
use reqwest::Client;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::mpsc::Receiver;
use tracing::{error, info};

pub async fn run_webhook_worker(db: DatabaseConnection, mut rx: Receiver<WebhookEvent>) {
    let client = Client::new();

    while let Some(event) = rx.recv().await {
        info!("Processing webhook event for IP: {}", event.address);

        // Fetch configs matching the group_id or global configs (group_id is null)
        let mut condition = webhook_config::Column::GroupId.is_null();
        if let Some(gid) = event.group_id {
            condition = condition.or(webhook_config::Column::GroupId.eq(gid));
        }

        let configs = match WebhookConfig::find().filter(condition).all(&db).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to fetch webhook configs: {}", e);
                continue;
            }
        };

        if configs.is_empty() {
            continue;
        }

        for config in configs {
            let client = client.clone();
            let event = event.clone();
            
            // Spawn a task for each request to not block other webhooks
            tokio::spawn(async move {
                match client.post(&config.target_url).json(&event).send().await {
                    Ok(resp) => {
                        if !resp.status().is_success() {
                            error!("Webhook request to {} failed with status: {}", config.target_url, resp.status());
                        }
                    }
                    Err(e) => {
                        error!("Failed to send webhook to {}: {}", config.target_url, e);
                    }
                }
            });
        }
    }
}
