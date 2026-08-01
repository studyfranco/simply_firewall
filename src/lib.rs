#![warn(missing_docs)]
//! Simply IP Vault Library
//! This module provides the core API router, state, and webhook logic.

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use sea_orm::DatabaseConnection;
use tokio::sync::mpsc;

pub mod api;
pub mod config;
pub mod crypto;
pub mod entities;
pub mod error;
pub mod middleware;
pub mod migration;
pub mod state;
pub mod webhooks;

use state::{AppState, WebhookEvent};

/// Creates the complete Axum router for the application.
pub fn create_app(state: AppState) -> Router {
    // Protected API routes
    let api_routes = Router::new()
        .route("/auth/me", get(api::get_me))
        .route("/ips", get(api::list_ips))
        .route("/ips", delete(api::delete_ip))
        .route("/ban", post(api::handle_ban))
        .route("/white", post(api::handle_white))
        // Admin endpoints
        .route("/keys", post(api::create_api_key))
        .route("/keys", get(api::list_api_keys))
        .route("/keys/{id}", put(api::update_api_key))
        .route("/keys/{id}", delete(api::delete_api_key))
        .route("/keys/{id}/rotate", post(api::rotate_api_key))
        // Narrower sibling of `/rotate`: re-keys only the HMAC signing secret, leaving the key's
        // identity and RBAC grants untouched.
        .route("/keys/{id}/rotate-secret", post(api::rotate_signing_secret))
        .route("/keys/{id}/groups", post(api::update_key_group_permissions))
        // `/permissions` is the same assignment handler as `/groups` under a name that matches
        // the new revoke route below; `/groups` is kept working for backward compatibility.
        .route("/keys/{id}/permissions", post(api::update_key_group_permissions))
        .route("/keys/{id}/permissions/{group_identifier}", delete(api::revoke_key_group_permission))
        .route("/groups", post(api::create_ip_group))
        .route("/groups", get(api::list_ip_groups))
        .route("/groups/{id}", delete(api::delete_ip_group))
        .route("/webhooks", post(api::create_webhook))
        .route("/webhooks", get(api::list_webhooks))
        .route("/webhooks/{id}", put(api::update_webhook))
        .route("/webhooks/{id}", delete(api::delete_webhook))
        .route("/audit-logs", get(api::list_audit_logs))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    // Root Router
    Router::new()
        .fallback_service(ServeDir::new("static"))
        .nest("/api", api_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Helper to create AppState and background worker
pub fn setup_state(db: DatabaseConnection) -> (AppState, mpsc::Sender<WebhookEvent>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<WebhookEvent>(100);
    let db_worker = db.clone();
    let worker_handle = tokio::spawn(async move {
        webhooks::run_webhook_worker(db_worker, rx).await;
    });

    let state = AppState::new(db, tx.clone());

    (state, tx, worker_handle)
}
