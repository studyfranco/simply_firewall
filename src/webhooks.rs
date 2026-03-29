use std::time::Duration;
use crate::entities::{prelude::*, webhook_config};
use crate::state::WebhookEvent;
use reqwest::Client;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::{error, info};

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_INFLIGHT: usize = 64;

pub async fn run_webhook_worker(db: DatabaseConnection, mut rx: Receiver<WebhookEvent>) {
    let client = Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .user_agent("SimplyFirewall/1.0")
        .build()
        .expect("Failed to build reqwest client");

    let mut join_set = JoinSet::new();

    info!("Webhook worker started.");

    while let Some(event) = rx.recv().await {
        info!(address = %event.address, "Processing event for webhooks");

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

        for config in configs {
            // Respect max inflight tasks to prevent memory issues
            if join_set.len() >= MAX_INFLIGHT {
                // Wait for at least one to finish if we're full
                let _ = join_set.join_next().await;
            }

            let client = client.clone();
            let event = event.clone();
            let target_url = config.target_url.clone();

            join_set.spawn(async move {
                match client.post(&target_url).json(&event).send().await {
                    Ok(resp) => {
                        if !resp.status().is_success() {
                            error!(url = %target_url, status = %resp.status(), "Webhook failed");
                        } else {
                            info!(url = %target_url, "Webhook delivered");
                        }
                    }
                    Err(e) => error!(url = %target_url, "Webhook error: {}", e),
                }
            });
        }
        
        // Clean up finished tasks periodically
        while let Some(Ok(_)) = join_set.try_join_next() {}
    }

    info!("Webhook channel closed, draining pending tasks...");
    while let Some(_) = join_set.join_next().await {}
    info!("Webhook worker shut down.");
}
