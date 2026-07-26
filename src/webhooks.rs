//! Webhook background worker

use std::time::Duration;
use std::str::FromStr;
use std::net::IpAddr;
use crate::entities::{prelude::*, webhook_config};
use crate::state::WebhookEvent;
use reqwest::{Client, header::{HeaderMap, HeaderName, HeaderValue}};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_INFLIGHT: usize = 64;

async fn is_url_safe(url_str: &str, allow_private: bool) -> bool {
    if allow_private { return true; }
    
    let url = match reqwest::Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return false,
    };
    
    let host_str = match url.host_str() {
        Some(h) => h,
        None => return false,
    };
    
    let port = url.port_or_known_default().unwrap_or(80);
    
    let addrs = match tokio::net::lookup_host((host_str, port)).await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                addr.ip()
            } else {
                return false;
            }
        },
        Err(_) => return false,
    };
    
    match addrs {
        IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                return false;
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return false;
            }
        }
    }
    
    true
}

/// Runs the background webhook worker, processing events and dispatching HTTP requests
pub async fn run_webhook_worker(db: DatabaseConnection, mut rx: Receiver<WebhookEvent>) {
    let client = match Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .user_agent("SimplyFirewall/2.0")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to build webhook HTTP client, worker will not start: {}", e);
            return;
        }
    };

    let mut join_set = JoinSet::new();
    let allow_private_webhooks = std::env::var("ALLOW_PRIVATE_WEBHOOKS").unwrap_or_else(|_| "false".to_owned()) == "true";

    info!("Webhook worker started.");

    while let Some(event) = rx.recv().await {
        info!(address = %event.address, event_type = %event.event_type, "Processing event for webhooks");

        let gid = match event.group_id {
            Some(id) => id,
            None => continue,
        };

        let configs = match WebhookConfig::find()
            .filter(webhook_config::Column::GroupId.eq(gid))
            .filter(webhook_config::Column::IsActive.eq(true))
            .all(&db).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to fetch webhook configs: {}", e);
                continue;
            }
        };

        for config in configs {
            if join_set.len() >= MAX_INFLIGHT {
                let _ = join_set.join_next().await;
            }

            let client = client.clone();
            
            let mut payload = config.payload_template.clone();
            payload = payload.replace("$target_address", &event.address);
            payload = payload.replace("$ip", &event.address);
            payload = payload.replace("$cause", event.cause.as_deref().unwrap_or("Unknown"));
            payload = payload.replace("$group_name", &gid.to_string()); 

            let mut headers = HeaderMap::new();
            headers.insert("Content-Type", HeaderValue::from_static("application/json"));
            
            if let Some(hjson) = &config.headers_json
                && let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, String>>(hjson)
            {
                for (k, v) in map {
                    if let (Ok(h_name), Ok(h_val)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                        headers.insert(h_name, h_val);
                    }
                }
            }
            
            let mac_result = Hmac::<Sha256>::new_from_slice(config.secret_token.as_bytes());
            let mut mac = match mac_result {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!("Failed to create HMAC key: {}", e);
                    continue;
                }
            };
            mac.update(payload.as_bytes());
            let result = mac.finalize();
            let hex_sig = hex::encode(result.into_bytes());
            let sig_val = format!("sha256={}", hex_sig);
            
            if let Ok(hv) = HeaderValue::from_str(&sig_val) {
                headers.insert("X-Signature-256", hv);
            }

            let target_url = config.target_url.clone();

            join_set.spawn(async move {
                if !is_url_safe(&target_url, allow_private_webhooks).await {
                    warn!(url = %target_url, "Webhook blocked by SSRF protection");
                    return;
                }
                
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
    while join_set.join_next().await.is_some() {}
    info!("Webhook worker shut down.");
}
