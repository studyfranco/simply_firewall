use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
};
use axum_client_ip::SecureClientIp;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};
use ipnetwork::IpNetwork;

use crate::entities::prelude::ApiKey;
use crate::error::AppError;
use crate::state::AppState;

pub async fn auth_middleware(
    State(state): State<AppState>,
    SecureClientIp(client_ip): SecureClientIp,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
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

    // Validate the client IP against the bound CIDR
    let bound_net: IpNetwork = key_record.bound_ip.parse().map_err(|_| {
        tracing::error!("Invalid CIDR in database: {}", key_record.bound_ip);
        AppError::Internal
    })?;

    if !bound_net.contains(client_ip) {
        tracing::warn!(
            "Access denied: Client IP {} not in bound network {}",
            client_ip,
            bound_net
        );
        return Err(AppError::Forbidden("Client IP not allowed".to_owned()));
    }

    Ok(next.run(req).await)
}
