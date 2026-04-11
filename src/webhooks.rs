use std::time::Duration;
use crate::entities::{prelude::*, webhook_config};
use crate::state::WebhookEvent;
use reqwest::{Client, header::{HeaderMap, HeaderName, HeaderValue}};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::{error, info};

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_INFLIGHT: usize = 64;

pub async fn run_webhook_worker(db: DatabaseConnection, mut rx: Receiver<WebhookEvent>) {
    let client = Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .user_agent("SimplyFirewall/2.0")
        .build()
        .expect("Failed to build reqwest client");

    let mut join_set = JoinSet::new();

    info!("Webhook worker started.");

    while let Some(event) = rx.recv().await {
        info!(address = %event.address, event_type = %event.event_type, "Processing event for webhooks");

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
            // Check if this config cares about this event type
            let triggers: Vec<&str> = config.trigger_events.split(',').map(|s| s.trim()).collect();
            if !triggers.contains(&event.event_type.as_str()) {
                continue;
            }

            // Respect max inflight tasks to prevent memory issues
            if join_set.len() >= MAX_INFLIGHT {
                let _ = join_set.join_next().await;
            }

            let client = client.clone();
            
            // Generate payload from template
            let mut payload = config.payload_template.clone();
            payload = payload.replace("$ip", &event.address);
            payload = payload.replace("$cause", event.cause.as_deref().unwrap_or("Unknown"));
            
            // To resolve GroupName we would typically need another DB query, but to keep worker fast
            // and avoiding locks we inject the group_id if no name was provided over events.
            let gid_str = event.group_id.map(|id| id.to_string()).unwrap_or_else(|| "Global".to_string());
            payload = payload.replace("$group_name", &gid_str);

            let mut headers = HeaderMap::new();
            if let (Some(auth_name), Some(auth_value)) = (&config.auth_header_name, &config.auth_token) {
                if !auth_name.is_empty() && !auth_value.is_empty() {
                    if let (Ok(h_name), Ok(h_val)) = (HeaderName::from_bytes(auth_name.as_bytes()), HeaderValue::from_str(auth_value)) {
                        headers.insert(h_name, h_val);
                    }
                }
            }
            
            headers.insert("Content-Type", HeaderValue::from_static("application/json"));

            let target_url = config.target_url.clone();

            join_set.spawn(async move {
                match client.post(&target_url).headers(headers).body(payload).send().await {
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
        
        while let Some(Ok(_)) = join_set.try_join_next() {}
    }

    info!("Webhook channel closed, draining pending tasks...");
    while let Some(_) = join_set.join_next().await {}
    info!("Webhook worker shut down.");
}
