//! The outbound webhook dispatcher: the background worker that *sends* notifications.
//!
//! # Why this is `dispatch` and not `webhooks`
//!
//! It was `src/webhooks.rs` until the structural audit, which sat one directory away from
//! `src/api/webhooks.rs` — and the two do entirely different jobs. That module is the CRUD surface
//! for webhook **configuration**: a caller creating, listing, and deleting `webhook_config` rows.
//! This one is the **runtime**: it consumes [`WebhookEvent`]s off a channel, resolves each target
//! against the SSRF filter below, signs the body, and makes the outbound HTTP call. Nothing here
//! serves a request, and nothing in `api/webhooks.rs` ever sends one.
//!
//! Two files with the same name whose only distinction was a path prefix is the shape that gets
//! imported wrongly — and, worse, *reviewed* wrongly, because a diff header reading `webhooks.rs`
//! does not say which of the two security models applies.

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

/// Whether a single resolved address is one this instance must never be induced to talk to.
///
/// Deliberately a pure function over an already-resolved [`IpAddr`], so it is unit-testable without
/// any DNS: every interesting case (metadata service, loopback, RFC 1918, IPv4-mapped IPv6) is just
/// an address literal.
///
/// The IPv4-mapped IPv6 normalization is load-bearing. `::ffff:127.0.0.1` is a perfectly ordinary
/// way to write the loopback address, and `Ipv6Addr::is_loopback` is `false` for it — checking the
/// v6 form alone would let `http://[::ffff:127.0.0.1]/` walk straight through. `crate::middleware`
/// already normalizes inbound addresses the same way; this keeps the two directions consistent.
fn is_blocked_address(ip: IpAddr) -> bool {
    // Unwrap `::ffff:a.b.c.d` to `a.b.c.d` so the IPv4 rules below actually apply to it.
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };

    match ip {
        IpAddr::V4(v4) => {
            // `is_link_local()` is what blocks 169.254.0.0/16, and therefore the cloud metadata
            // endpoints (169.254.169.254 on AWS/GCP/Azure) that are the highest-value SSRF target
            // on any hosted deployment.
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                // 100.64.0.0/10 — CGNAT space, routinely used for internal service meshes.
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                // 0.0.0.0/8 — "this network"; on Linux 0.x.y.z reaches the local host.
                || v4.octets()[0] == 0
                // 192.0.0.0/24 (IETF protocol assignments) and 198.18.0.0/15 (benchmarking).
                || v4.octets()[..3] == [192, 0, 0]
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local and fe80::/10 link-local.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Screens a webhook target URL against the SSRF blocklist before any connection is attempted.
///
/// **Every** address the host resolves to is checked, not just the first. A hostname with two A
/// records — one public, one `127.0.0.1` — would otherwise pass this gate on the public record while
/// the HTTP client independently re-resolves and picks the loopback one.
///
/// This remains a check-then-connect design, so it cannot stop a DNS rebinding attack where the
/// second resolution (the client's own) returns a different answer than the one screened here.
/// Closing that requires resolving once and pinning the socket address, i.e. a custom `reqwest`
/// connector — see the SSRF entry in `AGENT_NOTES.MD`.
async fn is_url_safe(url_str: &str, allow_private: bool) -> bool {
    if allow_private { return true; }

    let url = match reqwest::Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return false,
    };

    // Only http/https can be dispatched at all; anything else fails closed rather than relying on
    // the HTTP client to reject it later.
    if url.scheme() != "http" && url.scheme() != "https" {
        return false;
    }

    let host_str = match url.host_str() {
        Some(h) => h,
        None => return false,
    };

    let port = url.port_or_known_default().unwrap_or(80);

    let addrs: Vec<IpAddr> = match tokio::net::lookup_host((host_str, port)).await {
        Ok(addrs) => addrs.map(|a| a.ip()).collect(),
        Err(_) => return false,
    };

    // A name that resolves to nothing is not dispatchable; fail closed rather than "no bad
    // addresses found, therefore safe".
    if addrs.is_empty() {
        return false;
    }

    !addrs.into_iter().any(is_blocked_address)
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
        // Redirects are refused, not followed. `is_url_safe` screens the *configured* target, and
        // `reqwest`'s default policy would follow up to 10 hops afterwards without re-screening any
        // of them — so a webhook pointed at an attacker-controlled public URL that answers `302
        // Location: http://169.254.169.254/latest/meta-data/` would bypass the SSRF filter outright,
        // and the signed payload plus `X-API-Key` would be delivered to the redirect target.
        // A receiver that answers 3xx is now surfaced as a failed delivery instead.
        .redirect(reqwest::redirect::Policy::none())
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
                    Some(format!(
                        "{}{}",
                        crate::crypto::SIGNATURE_PREFIX,
                        hex::encode(mac.finalize().into_bytes())
                    ))
                }
                // CANONICAL_V1: sign the resolved hmac_template and send the timestamp alongside,
                // so the receiver can run its own anti-replay check. Prefixed `sha256=`, exactly
                // like BODY_ONLY above and exactly like what the inbound API middleware now
                // requires — that is the whole point of this mode: with the default template the
                // header is byte-identical to one `crypto::compute_signature` would produce, so a
                // dispatch authenticates directly against another instance's /api/* route (and
                // against `simply_hook_executor`, which has always required the prefix).
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
                    Some(format!(
                        "{}{}",
                        crate::crypto::SIGNATURE_PREFIX,
                        hex::encode(mac.finalize().into_bytes())
                    ))
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

    /// The SSRF blocklist, exercised as a pure function over resolved addresses.
    ///
    /// The cloud metadata endpoint is called out explicitly rather than left implicit in
    /// "link-local": it is the single highest-value SSRF target on a hosted deployment, and a
    /// refactor that dropped `is_link_local()` would otherwise silently reopen it.
    #[test]
    fn blocked_addresses_cover_metadata_loopback_and_rfc1918() {
        for blocked in [
            "169.254.169.254", // AWS/GCP/Azure instance metadata
            "169.254.0.1",
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.5",
            "172.16.4.4",
            "172.31.255.255",
            "192.168.1.1",
            "0.0.0.0",
            "0.0.0.1",
            "100.64.0.1",   // CGNAT
            "100.127.0.1",  // CGNAT upper bound
            "192.0.0.1",    // IETF protocol assignments
            "198.18.0.1",   // benchmarking range
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1",           // unique-local
            "fe80::1",           // link-local
            "::ffff:127.0.0.1",  // IPv4-mapped loopback — false for Ipv6Addr::is_loopback
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
        ] {
            let ip: IpAddr = blocked.parse().expect("test address literal parses");
            assert!(is_blocked_address(ip), "{blocked} must be blocked as an SSRF target");
        }

        // Ordinary public addresses must still be dispatchable, or the feature is useless.
        for allowed in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "100.63.255.255", "2606:4700::1111"] {
            let ip: IpAddr = allowed.parse().expect("test address literal parses");
            assert!(!is_blocked_address(ip), "{allowed} is public and must be allowed");
        }
    }

    #[tokio::test]
    async fn url_screening_rejects_literals_and_non_http_schemes() {
        // Address literals need no DNS, so these assertions are hermetic.
        assert!(!is_url_safe("http://127.0.0.1:8080/hook", false).await);
        assert!(!is_url_safe("http://169.254.169.254/latest/meta-data/", false).await);
        assert!(!is_url_safe("http://[::ffff:127.0.0.1]/hook", false).await);
        assert!(!is_url_safe("http://10.0.0.1/hook", false).await);
        assert!(!is_url_safe("file:///etc/passwd", false).await);
        assert!(!is_url_safe("gopher://127.0.0.1:70/", false).await);
        assert!(!is_url_safe("not a url", false).await);

        // The documented development escape hatch still bypasses the whole check.
        assert!(is_url_safe("http://127.0.0.1:8080/hook", true).await);
    }

    #[test]
    fn from_stored_never_downgrades_an_unreadable_mode_to_none() {
        assert_eq!(AuthMode::from_stored("wat"), AuthMode::BodyOnly);
        assert_eq!(AuthMode::from_stored(""), AuthMode::BodyOnly);
        assert_eq!(AuthMode::from_stored("canonical_v1"), AuthMode::CanonicalV1);
        assert_eq!(AuthMode::from_stored(" NONE "), AuthMode::None);
    }
}
