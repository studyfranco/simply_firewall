use std::net::SocketAddr;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, QueryFilter};
use sea_orm_migration::MigratorTrait;
use tokio::net::TcpListener;
use uuid::Uuid;
use simply_ip_vault::{create_app, setup_state, api, migration, entities};

/// Waits for a Ctrl+C or (on Unix) SIGTERM signal so `axum::serve` can shut down gracefully.
///
/// If signal registration itself fails, that branch is left pending forever instead of firing
/// immediately: an unregisterable signal should never be treated as "shutdown requested now".
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("Failed to listen for Ctrl+C: {}", e);
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {}", e);
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Received shutdown signal.");
}

/// Generates a default Master API Key if the database does not already contain one.
///
/// Checks specifically for the absence of a key with `is_master = true` (not merely "any key
/// exists"): if every master key were ever deleted while lower-privilege sub-keys remained,
/// administrators could otherwise be permanently locked out.
///
/// If the `INITIAL_MASTER_KEY` environment variable is set, its exact value is used as the
/// plaintext secret instead of generating a random one. This exists purely for deterministic
/// test/CI bootstrap (e.g. `scripts/test_e2e.sh`), where a caller needs to know the master key
/// up front rather than scraping it back out of stdout — it is deliberately **not** documented as
/// a normal deployment option, since a human-chosen, low-entropy secret defeats the point of
/// generating a random 256-bit key. A warning is logged whenever it's used so it can't be enabled
/// by accident in a real deployment without someone noticing in the logs.
async fn bootstrap_master_key(db: &DatabaseConnection) -> Result<(), Box<dyn std::error::Error>> {
    use entities::{api_key, prelude::ApiKey};

    let existing_master = ApiKey::find()
        .filter(api_key::Column::IsMaster.eq(true))
        .one(db)
        .await?;
    if existing_master.is_some() {
        return Ok(());
    }

    let plaintext_key = match std::env::var("INITIAL_MASTER_KEY") {
        Ok(fixed_key) if !fixed_key.is_empty() => {
            tracing::warn!(
                "INITIAL_MASTER_KEY is set: using the provided value as the master key instead \
                 of generating a random one. This is intended for deterministic test/CI bootstrap \
                 only — do not set this in a real deployment."
            );
            fixed_key
        }
        _ => api::generate_random_key(),
    };
    let key_hash = api::hash_key(&plaintext_key);
    let bound_ip = std::env::var("BOOTSTRAP_SUBNET").unwrap_or_else(|_| "0.0.0.0/0".to_owned());

    let prefix = plaintext_key.chars().take(8).collect::<String>();
    let now = chrono::Utc::now().naive_utc();

    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(key_hash),
        name: Set("System Master".to_owned()),
        prefix: Set(prefix),
        bound_ips: Set(Some(bound_ip.clone())),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
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

    // tracing's fmt subscriber buffers writes; a reader tailing/polling the redirected log file
    // right after this point (as scripts/test_e2e.sh used to, before it switched to
    // INITIAL_MASTER_KEY) could otherwise see a truncated or missing banner for a short window.
    // Flushing explicitly makes the banner's appearance in the log deterministic.
    use std::io::Write;
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

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
        .unwrap_or_else(|_| "sqlite://simply_ip_vault.db?mode=rwc".to_owned());

    tracing::info!("Connecting to database...");
    let mut opt = ConnectOptions::new(db_url);
    opt.sqlx_logging_level(log::LevelFilter::Debug);
    let db: DatabaseConnection = Database::connect(opt).await?;

    tracing::info!("Running database migrations...");
    migration::Migrator::up(&db, None).await?;

    bootstrap_master_key(&db).await?;

    let (state, tx, worker_handle) = setup_state(db);

    let app = create_app(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("Simply IP Vault API listening on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("Stopping webhook worker...");
    drop(tx);
    let _ = worker_handle.await;

    tracing::info!("Graceful shutdown complete.");
    Ok(())
}
