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
    // The signing secret follows the same rule as the key itself: deterministic when explicitly
    // provided for test/CI bootstrap, random otherwise.
    let signing_secret = match std::env::var("INITIAL_MASTER_SIGNING_SECRET") {
        Ok(fixed_secret) if !fixed_secret.is_empty() => {
            tracing::warn!(
                "INITIAL_MASTER_SIGNING_SECRET is set: using the provided value as the master \
                 key's HMAC signing secret instead of generating a random one. Intended for \
                 deterministic test/CI bootstrap only — do not set this in a real deployment."
            );
            fixed_secret
        }
        _ => simply_ip_vault::crypto::generate_signing_secret(),
    };

    let key_hash = api::hash_key(&plaintext_key);
    let stored_signing_secret = simply_ip_vault::crypto::seal_signing_secret(&signing_secret)?;
    let bound_ip = std::env::var("BOOTSTRAP_SUBNET").unwrap_or_else(|_| "0.0.0.0/0".to_owned());

    let prefix = plaintext_key.chars().take(8).collect::<String>();
    let now = chrono::Utc::now().naive_utc();

    let model = api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(key_hash),
        signing_secret: Set(Some(stored_signing_secret)),
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

    // The box is drawn against an explicit inner width rather than hardcoded runs of ═, so the
    // borders stay aligned around a 64-hex-char credential (the previous fixed layout did not).
    const W: usize = 82;
    let border = "═".repeat(W);
    let body: String = [
        format!("X-API-Key      : {plaintext_key}"),
        format!("Signing secret : {signing_secret}"),
        format!("Bound IPs      : {bound_ip}"),
        String::new(),
        "Both values are needed to sign requests (X-Timestamp + X-Signature-256).".to_owned(),
        "They will NOT be shown again — store them securely!".to_owned(),
    ]
    .iter()
    .map(|row| format!("║ {row:<W$} ║\n"))
    .collect();

    tracing::info!(
        "\n╔{border}╗\n║ {:<W$} ║\n╠{border}╣\n{body}╚{border}╝",
        "BOOTSTRAP: Master API Key Generated"
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

    // Surfaced at boot because the two modes are indistinguishable from the API's behaviour: an
    // operator who mistyped the env var would otherwise never learn that signing secrets are
    // sitting in the database in plaintext.
    if simply_ip_vault::crypto::encryption_enabled() {
        tracing::info!("VAULT_ENCRYPTION_KEY is set: signing secrets are encrypted at rest (AES-GCM-256).");
    } else {
        tracing::warn!(
            "VAULT_ENCRYPTION_KEY is not set: API key signing secrets are stored UNENCRYPTED. \
             This is the zero-config development default — set it for any real deployment."
        );
    }

    // Same reasoning as the encryption warning above, and with a sharper failure mode: with no
    // trusted proxies configured, a deployment that *is* behind a reverse proxy will reject every
    // request from a CIDR-bound key with 403, because every request appears to come from the proxy.
    // That is the safe direction to fail, but only if the operator is told why.
    let trusted_proxies = simply_ip_vault::config::trusted_proxies_from_env();
    if trusted_proxies.is_empty() {
        tracing::warn!(
            "{} is not set: X-Forwarded-For and X-Real-IP are IGNORED and every key is matched \
             against its raw TCP peer address. This is correct for a directly-exposed deployment; \
             behind a reverse proxy you must set it, or CIDR-bound keys will be rejected.",
            simply_ip_vault::config::TRUSTED_PROXIES_ENV
        );
    } else {
        tracing::info!(
            "{} is set: forwarding headers are honoured from {} network(s): {:?}",
            simply_ip_vault::config::TRUSTED_PROXIES_ENV,
            trusted_proxies.len(),
            trusted_proxies
        );
    }

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
