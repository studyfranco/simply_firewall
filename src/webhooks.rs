use std::time::Duration;

use crate::entities::{prelude::*, webhook_config};
use crate::state::WebhookEvent;
use reqwest::Client;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

/// Timeout for individual webhook HTTP dispatches.
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of concurrent in-flight webhook dispatches.
/// Prevents unbounded memory growth if events arrive faster than
/// remote endpoints can respond.
const MAX_INFLIGHT: usize = 64;

pub async fn run_webhook_worker(db: DatabaseConnection, mut rx: Receiver<WebhookEvent>) {
    let client = Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .user_agent("SimplyFirewall/1.0")
        .build()
        .expect("Failed to build reqwest client");

    let mut join_set = JoinSet::new();

    info!("Webhook worker started, listening for events...");

    while let Some(event) = rx.recv().await {
        info!(
            address = %event.address,
            is_whitelist = event.is_whitelist,
            cause = event.cause.as_deref().unwrap_or("-"),
            "Processing webhook event"
        );

        // Reap any already-completed tasks to free memory (non-blocking)
        reap_completed(&mut join_set);

        // If we've hit the concurrency ceiling, wait for one to finish
        if join_set.len() >= MAX_INFLIGHT {
            warn!(
                inflight = join_set.len(),
                "Webhook concurrency limit reached, waiting for a slot..."
            );
            if let Some(res) = join_set.join_next().await {
                if let Err(e) = res {
                    error!("Webhook task panicked while awaiting slot: {}", e);
                }
            }
        }

        // Fetch configs matching the group_id or global configs (group_id is null)
        let mut condition = webhook_config::Column::GroupId.is_null();
        if let Some(gid) = event.group_id {
            condition = condition.or(webhook_config::Column::GroupId.eq(gid));
        }

        let configs = match WebhookConfig::find().filter(condition).all(&db).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to fetch webhook configs from DB: {}", e);
                continue;
            }
        };

        if configs.is_empty() {
            info!(address = %event.address, "No matching webhook configs, skipping dispatch.");
            continue;
        }

        info!(
            address = %event.address,
            config_count = configs.len(),
            "Dispatching webhook to {} endpoint(s)",
            configs.len()
        );

        for config in configs {
            let client = client.clone();
            let event = event.clone();
            let target_url = config.target_url.clone();

            // Spawn a task for each request to not block other webhooks
            join_set.spawn(async move {
                info!(url = %target_url, "Sending webhook request...");

                match client.post(&target_url).json(&event).send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        if status.is_success() {
                            info!(url = %target_url, status = %status, "Webhook delivered successfully.");
                        } else {
                            // Read body for error context (truncated)
                            let body = resp
                                .text()
                                .await
                                .unwrap_or_else(|_| "<unreadable>".to_string());
                            let body_preview = if body.len() > 200 {
                                format!("{}...", &body[..200])
                            } else {
                                body
                            };
                            error!(
                                url = %target_url,
                                status = %status,
                                body = %body_preview,
                                "Webhook request returned non-success status"
                            );
                        }
                    }
                    Err(e) => {
                        if e.is_timeout() {
                            error!(url = %target_url, "Webhook request timed out after {:?}", WEBHOOK_TIMEOUT);
                        } else if e.is_connect() {
                            error!(url = %target_url, "Webhook connection failed (bad URL or host unreachable): {}", e);
                        } else {
                            error!(url = %target_url, "Webhook request failed: {}", e);
                        }
                    }
                }
            });
        }
    }

    // ── Drain Phase ────────────────────────────────────────
    // The MPSC channel is now closed (all Senders have been dropped).
    // We must wait for every in-flight HTTP dispatch to complete before
    // the process can exit cleanly.
    let pending = join_set.len();
    info!(
        pending,
        "Webhook MPSC channel closed. Draining {} pending dispatch(es)...", pending
    );

    while let Some(res) = join_set.join_next().await {
        match res {
            Ok(()) => {}
            Err(e) => error!("Webhook dispatch task panicked during drain: {}", e),
        }
    }

    info!("All webhook tasks drained. Worker shutting down.");
}

/// Non-blocking reap of completed JoinSet tasks.
/// Frees memory from finished futures without waiting.
fn reap_completed<T: 'static>(join_set: &mut JoinSet<T>) {
    loop {
        match join_set.try_join_next() {
            Some(Ok(_)) => {}
            Some(Err(e)) => {
                error!("Completed webhook task had panicked: {}", e);
            }
            None => break,
        }
    }
}
