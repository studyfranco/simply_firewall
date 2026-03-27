use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use axum_client_ip::SecureClientIp;
use ipnetwork::IpNetwork;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

use crate::entities::{api_key, prelude::*};
use crate::state::AppState;

pub async fn auth_middleware(
    State(state): State<AppState>,
    SecureClientIp(client_ip): SecureClientIp,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = req.headers();
    let api_key = headers.get("x-api-key").ok_or(StatusCode::UNAUTHORIZED)?;
    let api_key_str = api_key.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut hasher = Sha256::new();
    hasher.update(api_key_str.as_bytes());
    let hashed_key = hex::encode(hasher.finalize());

    let key_record = ApiKey::find()
        .filter(api_key::Column::KeyHash.eq(hashed_key))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let network: IpNetwork = key_record
        .bound_ip
        .parse()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if !network.contains(client_ip) {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(req).await)
}
