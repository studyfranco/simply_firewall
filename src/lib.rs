use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use sea_orm::DatabaseConnection;
use tokio::sync::mpsc;

pub mod api;
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
        .route("/ips/:id", delete(api::delete_ip))
        .route("/ban", post(api::handle_ban))
        .route("/white", post(api::handle_white))
        // Admin endpoints
        .route("/keys", post(api::create_api_key))
        .route("/keys", get(api::list_api_keys))
        .route("/keys/:id", delete(api::delete_api_key))
        .route("/keys/:id/groups", post(api::update_key_group_permissions))
        .route("/groups", post(api::create_ip_group))
        .route("/groups", get(api::list_ip_groups))
        .route("/groups/:id", delete(api::delete_ip_group))
        .route("/webhooks", post(api::create_webhook))
        .route("/webhooks", get(api::list_webhooks))
        .route("/webhooks/:id", delete(api::delete_webhook))
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

    let state = AppState {
        db,
        webhook_tx: tx.clone(),
    };

    (state, tx, worker_handle)
}
