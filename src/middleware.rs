//! Authentication middleware

use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};
use ipnetwork::IpNetwork;

use crate::entities::prelude::ApiKey;
use crate::error::AppError;
use crate::state::AppState;

/// Normalizes an IPv4-mapped IPv6 address (e.g. `::ffff:192.168.1.1`) down to its plain
/// IPv4 form so it can be matched against IPv4 CIDR ranges in `bound_ips`. Reverse proxies and
/// dual-stack sockets commonly surface IPv4 clients this way, which would otherwise silently fail
/// to match an otherwise-correct IPv4 CIDR and cause a false `403 Forbidden`.
fn normalize_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Extracts the rightmost address from a comma-separated forwarding header, trimmed and parsed.
fn rightmost_ip(header_value: &str) -> Option<std::net::IpAddr> {
    header_value
        .split(',')
        .next_back()
        .map(|s| s.trim())
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
}

/// Middleware to enforce API Key authentication and IP restrictions
pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    // Resilient IP resolution logic: prefer X-Forwarded-For (rightmost hop), then X-Real-IP,
    // and only fall back to the raw TCP peer address if neither proxy header is present/valid.
    let client_ip = headers
        .get("X-Forwarded-For")
        .and_then(|h| h.to_str().ok())
        .and_then(rightmost_ip)
        .or_else(|| {
            headers
                .get("X-Real-IP")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.trim())
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        })
        .unwrap_or(addr.ip()); // Fallback to raw TCP IP
    let client_ip = normalize_ip(client_ip);

    let auth_header = req
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::Unauthorized("Missing API Key".to_owned()))?;

    // Hash the provided key
    let mut hasher = Sha256::new();
    hasher.update(auth_header.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    // Find the API key in the database
    let key_record = ApiKey::find()
        .filter(crate::entities::api_key::Column::KeyHash.eq(key_hash))
        .one(&state.db)
        .await
        .map_err(AppError::DbError)?
        .ok_or(AppError::Unauthorized("Invalid API Key".to_owned()))?;

    // Validate the client IP against the bound CIDRs
    let bound_ips_str = key_record.bound_ips.as_deref().unwrap_or("");
    let networks: Vec<IpNetwork> = bound_ips_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            tracing::error!("Invalid CIDR in database: {:?}", key_record.bound_ips);
            AppError::Internal
        })?;

    let is_allowed = networks.is_empty() || networks.iter().any(|net| net.contains(client_ip));

    if !is_allowed && !key_record.is_master {
        tracing::warn!(
            "Access denied: Client IP {} not in bound networks {:?}",
            client_ip,
            key_record.bound_ips
        );
        return Err(AppError::Forbidden("Client IP not allowed".to_owned()));
    }

    let mut req = req;
    req.extensions_mut().insert(key_record);

    Ok(next.run(req).await)
}
