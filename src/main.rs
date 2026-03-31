use std::net::SocketAddr;


use axum::{
    routing::{delete, get, post},
    Router,
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection, EntityTrait};
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
        name: Set("System Master".to_owned()),
        bound_ips: Set(bound_ip.clone()),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_view_ips: Set(true),
        can_add_ips: Set(true),
        can_edit_ips: Set(true),
        can_delete_ips: Set(true),
        group_id: Set(None),
    };

    model.insert(db).await?;

    tracing::info!(
        "\n╔══════════════════════════════════════════════════════════════╗\n\
         ║  BOOTSTRAP: Master API Key Generated                       ║\n\
         ║  Key:    {}  ║\n\
         ║  Bound:  {:54}║\n\
         ║  ⚠ This key will NOT be shown again. Store it securely!    ║\n\
         ╚══════════════════════════════════════════════════════════════╝",
        plaintext_key, bound_ip
    );

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
    let mut opt = ConnectOptions::new(db_url);
    opt.sqlx_logging_level(log::LevelFilter::Debug);
    let db: DatabaseConnection = Database::connect(opt).await?;

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
        .route("/auth/me", get(api::get_me))
        .route("/ips", get(api::list_ips))
        .route("/ips/:id", delete(api::delete_ip))
        .route("/ban", post(api::handle_ban))
        .route("/white", post(api::handle_white))
        // Admin endpoints for managing the system itself (mapped to the same handlers but following REST)
        .route("/keys", post(api::create_api_key))
        .route("/keys", get(api::list_api_keys))
        .route("/keys/:id", delete(api::delete_api_key))
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
    let app = Router::new()
        .fallback_service(ServeDir::new("static"))
        .nest("/api", api_routes)
        .layer(TraceLayer::new_for_http())
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
