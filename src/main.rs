use std::net::SocketAddr;


use axum_client_ip::SecureClientIpSource;
use axum::{
    routing::{delete, get, post},
    Router,
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection, EntityTrait};
use sea_orm_migration::MigratorTrait;
use tokio::{net::TcpListener, sync::mpsc};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

mod api;
mod entities;
mod error;
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
    tracing::info!("Received shutdown signal.");
}

/// Automatically creates a master API key if none exists in the database.
async fn bootstrap_master_key(db: &DatabaseConnection) -> Result<(), Box<dyn std::error::Error>> {
    use crate::entities::{api_key, prelude::ApiKey};

    // Only bootstrap if the table is empty
    let existing = ApiKey::find().one(db).await?;
    if existing.is_some() {
        return Ok(());
    }

    let plaintext_key = api::generate_random_key();
    let key_hash = api::hash_key(&plaintext_key);
    let bound_ip = std::env::var("BOOTSTRAP_SUBNET").unwrap_or_else(|_| "0.0.0.0/0".to_owned());

    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(key_hash),
        bound_ip: Set(bound_ip.clone()),
    };

    model.insert(db).await?;

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  BOOTSTRAP: Master API Key Generated                       ║");
    println!("║  Key:    {}  ║", plaintext_key);
    println!("║  Bound:  {:54}║", bound_ip);
    println!("║  ⚠ This key will NOT be shown again. Store it securely!    ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://firewall.db?mode=rwc".to_owned());

    tracing::info!("Connecting to database...");
    let db: DatabaseConnection = Database::connect(&db_url).await?;

    tracing::info!("Running database migrations...");
    migration::Migrator::up(&db, None).await?;

    // Seed initial key for zero-trust access
    bootstrap_master_key(&db).await?;

    // Webhook communication channel
    let (tx, rx) = mpsc::channel::<WebhookEvent>(100);

    // Spawn background worker
    let db_worker = db.clone();
    let worker_handle = tokio::spawn(async move {
        webhooks::run_webhook_worker(db_worker, rx).await;
    });

    let state = AppState {
        db,
        webhook_tx: tx.clone(),
    };

    // Protected API routes
    let api_routes = Router::new()
        .route("/ban", post(api::handle_ban))
        .route("/white", post(api::handle_white))
        // Admin endpoints for managing the system itself
        .route("/admin/api-keys", post(api::create_api_key))
        .route("/admin/api-keys", get(api::list_api_keys))
        .route("/admin/api-keys/:id", delete(api::delete_api_key))
        .route("/admin/ip-groups", post(api::create_ip_group))
        .route("/admin/ip-groups", get(api::list_ip_groups))
        .route("/admin/ip-groups/:id", delete(api::delete_ip_group))
        .route("/admin/webhooks", post(api::create_webhook))
        .route("/admin/webhooks", get(api::list_webhooks))
        .route("/admin/webhooks/:id", delete(api::delete_webhook))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    // Root Router
    let app = Router::new()
        .fallback_service(ServeDir::new("static"))
        .route("/api/ips", get(api::list_ips)) // Public listing (or add middleware if desired)
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

    tracing::info!("Stopping webhook worker...");
    // Dropping tx informs rx that no more events are coming, allowing the worker to drain and exit.
    drop(tx);
    let _ = worker_handle.await;

    tracing::info!("Graceful shutdown complete.");
    Ok(())
}
