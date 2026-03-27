use std::net::SocketAddr;

use axum::{
    routing::{get, post},
    Router,
};
use axum_client_ip::SecureClientIpSource;
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use tokio::{net::TcpListener, sync::mpsc};
use tower_http::trace::TraceLayer;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://firewall.db?mode=rwc".to_owned());
    
    tracing::info!("Connecting to database: {}", db_url);
    let db: DatabaseConnection = Database::connect(&db_url).await?;

    tracing::info!("Running database migrations...");
    migration::Migrator::up(&db, None).await?;

    let (tx, rx) = mpsc::channel::<WebhookEvent>(100);

    tracing::info!("Starting webhook background worker...");
    let db_worker = db.clone();
    let worker_handle = tokio::spawn(async move {
        webhooks::run_webhook_worker(db_worker, rx).await;
    });

    let state = AppState { db, webhook_tx: tx };

    let api_routes = Router::new()
        .route("/ban", post(api::handle_ban))
        .route("/white", post(api::handle_white))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

use tower_http::services::ServeDir;

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
