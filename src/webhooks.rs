//! Webhook background worker

use std::time::Duration;
use std::str::FromStr;
use std::net::IpAddr;
use crate::entities::{prelude::*, webhook_config::{self, AuthMode, DEFAULT_HMAC_TEMPLATE}};
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

/// Expands a `CANONICAL_V1` webhook's `hmac_template` into the exact bytes to be signed.
///
/// Two substitutions happen in a **single left-to-right pass**, so neither can act on the other's
/// output:
///
/// - **Escapes.** `\n`, `\r`, `\t` and `\\` become the characters they name. Every other backslash
///   sequence is emitted verbatim (`\d` stays `\d`). Templates travel through a single-line HTML
///   text input in the dashboard, where a real newline cannot be typed — yet the canonical string is
///   defined in terms of newlines, so the escape layer is what makes the field usable at all.
/// - **Placeholders.** `{method}`, `{path}`, `{timestamp}` and `{body}` are replaced by their values.
///   Any other `{...}` is literal text, which is what lets a JSON body template coexist with this
///   syntax.
///
/// The single pass is the security-relevant part: a two-phase "unescape, then replace" would let a
/// request body containing the characters `{path}` inject the target path into the signed string,
/// and a "replace, then unescape" would let a body containing `\n` forge field boundaries. Values
/// substituted here are never rescanned.
///
/// A literal path written into the template (e.g. `{method}\n/api/hooks/42/execute\n{timestamp}\n{body}`)
/// therefore overrides the `{path}` derived from `target_url` with no extra machinery — the receiver
/// behind a path-rewriting reverse proxy sees, and signs over, the path *it* was handed.
pub fn resolve_hmac_template(
    template: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    body: &str,
) -> String {
    const PLACEHOLDERS: [&str; 4] = ["{method}", "{path}", "{timestamp}", "{body}"];

    let values = [method, path, timestamp, body];
    let mut out = String::with_capacity(template.len() + body.len());
    let mut rest = template;

    while !rest.is_empty() {
        // `find` over the two characters that can start a substitution; everything up to the next
        // one is literal and copied wholesale.
        let Some(idx) = rest.find(['\\', '{']) else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..idx]);
        rest = &rest[idx..];

        if let Some(escaped) = rest.strip_prefix('\\') {
            let mut chars = escaped.chars();
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                // Unknown escape (or a trailing lone backslash): keep both characters as written
                // rather than guessing — silently dropping input from a signed string is worse than
                // an obviously-wrong signature the operator can see and fix.
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => {
                    out.push('\\');
                    break;
                }
            }
            rest = chars.as_str();
            continue;
        }

        match PLACEHOLDERS
            .iter()
            .position(|placeholder| rest.starts_with(placeholder))
        {
            Some(i) => {
                out.push_str(values[i]);
                rest = &rest[PLACEHOLDERS[i].len()..];
            }
            None => {
                out.push('{');
                rest = &rest[1..];
            }
        }
    }

    out
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
        info!(address = %event.address, action = %event.action, "Processing event for webhooks");

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
            // `events` is `None` for "all events" (the historical default); when set, it's a
            // comma-separated allowlist of actions this specific webhook cares about.
            if let Some(events) = &config.events {
                let subscribed = events.split(',').map(|s| s.trim()).any(|a| a == event.action);
                if !subscribed {
                    continue;
                }
            }

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
            
            let mode = AuthMode::from_stored(&config.auth_mode);

            // Sent by the two modes that identify the caller by key. Inserted before the signature
            // so it is covered by nothing and can never be confused for one; a blank column means
            // "no such header" rather than an empty one, which some receivers treat as a real
            // (and failing) credential.
            if mode.sends_api_key()
                && let Some(api_key) = config.api_key.as_deref().filter(|k| !k.is_empty())
            {
                match HeaderValue::from_str(api_key) {
                    Ok(hv) => {
                        headers.insert("X-API-Key", hv);
                    }
                    Err(e) => {
                        error!(webhook = %config.name, "Webhook api_key is not a valid header value: {}", e);
                        continue;
                    }
                }
            }

            let signature = match mode {
                // Legacy/generic: HMAC over the body alone, prefixed `sha256=` the way
                // GitHub-style receivers expect. Unchanged from before auth modes existed.
                AuthMode::BodyOnly => {
                    let mut mac = match Hmac::<Sha256>::new_from_slice(config.secret_token.as_bytes()) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::error!("Failed to create HMAC key: {}", e);
                            continue;
                        }
                    };
                    mac.update(payload.as_bytes());
                    Some(format!("sha256={}", hex::encode(mac.finalize().into_bytes())))
                }
                // CANONICAL_V1: sign the resolved hmac_template and send the timestamp alongside,
                // so the receiver can run its own anti-replay check. The signature is bare hex —
                // with the default template, byte-identical to what the inbound API middleware
                // produces — so a dispatch can authenticate directly against another instance's
                // /api/* route.
                AuthMode::CanonicalV1 => {
                    let timestamp = chrono::Utc::now().timestamp().to_string();
                    // The path is taken from the target URL; a URL that failed to parse cannot be
                    // dispatched at all, so skipping here loses nothing (is_url_safe would reject
                    // it moments later regardless).
                    let path = match reqwest::Url::parse(&config.target_url) {
                        Ok(url) => url.path().to_owned(),
                        Err(e) => {
                            error!(url = %config.target_url, "Unparseable webhook target URL: {}", e);
                            continue;
                        }
                    };
                    let template = config.hmac_template.as_deref().unwrap_or(DEFAULT_HMAC_TEMPLATE);
                    let message = resolve_hmac_template(template, "POST", &path, &timestamp, &payload);

                    let mut mac = match Hmac::<Sha256>::new_from_slice(config.secret_token.as_bytes()) {
                        Ok(m) => m,
                        Err(e) => {
                            error!("Failed to create canonical webhook HMAC key: {}", e);
                            continue;
                        }
                    };
                    mac.update(message.as_bytes());

                    if let Ok(hv) = HeaderValue::from_str(&timestamp) {
                        headers.insert("X-Timestamp", hv);
                    }
                    Some(hex::encode(mac.finalize().into_bytes()))
                }
                // No signature to compute: the key header above (API_KEY_ONLY) or nothing at all
                // (NONE) is the whole credential.
                AuthMode::ApiKeyOnly | AuthMode::None => None,
            };

            if let Some(sig_val) = signature
                && let Ok(hv) = HeaderValue::from_str(&sig_val)
            {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_template_reproduces_the_canonical_v1_string() {
        let resolved = resolve_hmac_template(DEFAULT_HMAC_TEMPLATE, "POST", "/api/ban", "1700", "{}");
        assert_eq!(resolved, "POST\n/api/ban\n1700\n{}");

        // The whole point of CANONICAL_V1 mode: the bytes a dispatch signs are the bytes an inbound
        // request would have signed, so a webhook can authenticate against another instance's API.
        let inbound = crate::crypto::canonical_v1_payload("POST", "/api/ban", "1700", b"{}");
        assert_eq!(resolved.as_bytes(), inbound.as_slice());
    }

    #[test]
    fn a_literal_path_in_the_template_overrides_the_url_derived_one() {
        let resolved = resolve_hmac_template(
            r"{method}\n/api/hooks/42/execute\n{timestamp}\n{body}",
            "POST",
            "/proxied/elsewhere",
            "1700",
            "payload",
        );
        assert_eq!(resolved, "POST\n/api/hooks/42/execute\n1700\npayload");
    }

    #[test]
    fn escapes_are_expanded_and_unknown_ones_kept_verbatim() {
        assert_eq!(resolve_hmac_template(r"a\nb\tc\rd", "", "", "", ""), "a\nb\tc\rd");
        // `\\n` is an escaped backslash followed by `n`, NOT a newline.
        assert_eq!(resolve_hmac_template(r"a\\nb", "", "", "", ""), r"a\nb");
        assert_eq!(resolve_hmac_template(r"a\db", "", "", "", ""), r"a\db");
        assert_eq!(resolve_hmac_template(r"trailing\", "", "", "", ""), r"trailing\");
    }

    #[test]
    fn unknown_braces_are_literal_so_json_templates_survive() {
        assert_eq!(
            resolve_hmac_template(r#"{"sig":"{body}","x":{"y":1}}"#, "", "", "", "B"),
            r#"{"sig":"B","x":{"y":1}}"#
        );
    }

    #[test]
    fn substituted_values_are_never_rescanned() {
        // A body that contains template syntax must land in the signed string verbatim. If it were
        // rescanned, a caller controlling the `cause` field of an IP record could inject the
        // method/path/timestamp of their choosing into what the receiver verifies.
        let hostile = r"{path}\n{timestamp}";
        let resolved = resolve_hmac_template(DEFAULT_HMAC_TEMPLATE, "POST", "/api/ban", "1700", hostile);
        assert_eq!(resolved, format!("POST\n/api/ban\n1700\n{hostile}"));
        assert!(resolved.ends_with(r"{path}\n{timestamp}"));
    }

    #[test]
    fn field_order_and_separators_are_load_bearing() {
        let a = resolve_hmac_template(DEFAULT_HMAC_TEMPLATE, "POST", "/api/ban", "1700", "x");
        let b = resolve_hmac_template(DEFAULT_HMAC_TEMPLATE, "POST", "/api/ba", "n1700", "x");
        assert_ne!(a, b, "the \\n delimiter must keep adjacent fields unambiguous");
    }

    #[test]
    fn from_stored_never_downgrades_an_unreadable_mode_to_none() {
        assert_eq!(AuthMode::from_stored("wat"), AuthMode::BodyOnly);
        assert_eq!(AuthMode::from_stored(""), AuthMode::BodyOnly);
        assert_eq!(AuthMode::from_stored("canonical_v1"), AuthMode::CanonicalV1);
        assert_eq!(AuthMode::from_stored(" NONE "), AuthMode::None);
    }
}
