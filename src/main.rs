use std::net::SocketAddr;

use axum::{
    routing::{delete, get, post},
    Router,
};
use axum_client_ip::SecureClientIpSource;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection, EntityTrait};
use sea_orm_migration::MigratorTrait;
use tokio::{net::TcpListener, sync::mpsc};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

mod api;
mod entities;
mod middleware;
mod migration;
mod state;
mod webhooks;

use state::{AppState, WebhookEvent};

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Received shutdown signal. Stopping axum and draining tasks...");
}

/// Bootstrap: if the api_keys table is empty, generate a "Master Key",
/// insert its SHA-256 hash, and print the plaintext key exactly once.
async fn bootstrap_master_key(db: &DatabaseConnection) -> Result<(), Box<dyn std::error::Error>> {
    use crate::entities::{api_key, prelude::ApiKey};

    let existing = ApiKey::find().one(db).await?;
    if existing.is_some() {
        tracing::info!("API keys table is not empty — skipping bootstrap.");
        return Ok(());
    }

    let bound_ip = std::env::var("BOOTSTRAP_SUBNET").unwrap_or_else(|_| "0.0.0.0/0".to_owned());
    let plaintext_key = api::generate_random_key();
    let key_hash = api::hash_key(&plaintext_key);

    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(key_hash),
        bound_ip: Set(bound_ip.clone()),
    };

    model.insert(db).await?;

    tracing::info!("╔══════════════════════════════════════════════════════════════╗");
    tracing::info!("║  BOOTSTRAP: Master API Key Generated                       ║");
    tracing::info!("║  Key:    {}  ║", plaintext_key);
    tracing::info!("║  Bound:  {:54}║", bound_ip);
    tracing::info!("║  ⚠ This key will NOT be shown again. Store it securely!    ║");
    tracing::info!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://firewall.db?mode=rwc".to_owned());
    
    tracing::info!("Connecting to database: {}", db_url);
    let db: DatabaseConnection = Database::connect(&db_url).await?;

    tracing::info!("Running database migrations...");
    migration::Migrator::up(&db, None).await?;

    // Bootstrap master key if api_keys table is empty
    bootstrap_master_key(&db).await?;

    let (tx, rx) = mpsc::channel::<WebhookEvent>(100);

    tracing::info!("Starting webhook background worker...");
    let db_worker = db.clone();
    let worker_handle = tokio::spawn(async move {
        webhooks::run_webhook_worker(db_worker, rx).await;
    });

    let state = AppState { db, webhook_tx: tx };

    // Protected API routes (ban, white, admin CRUD)
    let api_routes = Router::new()
        .route("/ban", post(api::handle_ban))
        .route("/white", post(api::handle_white))
        // Admin — API Keys
        .route("/admin/api-keys", post(api::create_api_key))
        .route("/admin/api-keys", get(api::list_api_keys))
        .route("/admin/api-keys/:id", delete(api::delete_api_key))
        // Admin — IP Groups
        .route("/admin/ip-groups", post(api::create_ip_group))
        .route("/admin/ip-groups", get(api::list_ip_groups))
        .route("/admin/ip-groups/:id", delete(api::delete_ip_group))
        // Admin — Webhooks
        .route("/admin/webhooks", post(api::create_webhook))
        .route("/admin/webhooks", get(api::list_webhooks))
        .route("/admin/webhooks/:id", delete(api::delete_webhook))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    let app = Router::new()
        .fallback_service(ServeDir::new("static"))
        .route("/api/ips", get(api::list_ips))
        .nest("/api", api_routes)
        .layer(TraceLayer::new_for_http())
        .layer(SecureClientIpSource::RightmostXForwardedFor.into_extension())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("Simply Firewall API listening on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("Server stopped accepting HTTP connections. Awaiting webhook worker completion...");
    let _ = worker_handle.await;
    tracing::info!("Graceful shutdown complete.");

    Ok(())
}
