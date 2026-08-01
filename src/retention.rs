//! Background retention worker: permanently drops soft-deleted IP records once they age out.
//!
//! A soft delete (`ip_records.is_deleted`) is reversible by design — it exists so a mistyped
//! `DELETE`, or one issued by a compromised delegated key, is recoverable. That safety net is only
//! worth anything if it is *bounded*: without a purge the table grows forever and "deleted" data
//! lives indefinitely, which is a data-retention problem rather than a safety feature.
//!
//! 92 days ≈ one quarter, chosen so a record deleted at the start of a quarter survives review at
//! its end. Configurable through [`RETENTION_DAYS_ENV`]; `0` disables purging entirely for
//! operators who would rather keep everything and manage it themselves.

use std::time::Duration;

use chrono::Utc;
use sea_orm::{ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};
use tokio::sync::mpsc;

use crate::entities::ip_record;

/// Days a soft-deleted record is kept before the purge removes it for good.
pub const DEFAULT_RETENTION_DAYS: i64 = 92;

/// Overrides [`DEFAULT_RETENTION_DAYS`]. `0` disables purging.
pub const RETENTION_DAYS_ENV: &str = "IP_RETENTION_DAYS";

/// Overrides the interval between sweeps, in seconds. Defaults to hourly.
pub const RETENTION_SWEEP_ENV: &str = "IP_RETENTION_SWEEP_SECONDS";

/// Default seconds between sweeps.
const DEFAULT_SWEEP_SECONDS: u64 = 3600;

/// Reads the configured retention window, falling back to [`DEFAULT_RETENTION_DAYS`].
///
/// A malformed value warns and falls back rather than aborting startup — matching how the rest of
/// the codebase treats bad overrides — and the fallback is the *safe* direction here: keeping data
/// longer than intended is recoverable, deleting it early is not.
pub fn retention_days_from_env() -> i64 {
    match std::env::var(RETENTION_DAYS_ENV) {
        Ok(raw) => match raw.trim().parse::<i64>() {
            Ok(days) if days >= 0 => days,
            _ => {
                tracing::warn!(
                    "Invalid {RETENTION_DAYS_ENV} value {raw:?} — falling back to \
                     {DEFAULT_RETENTION_DAYS} days."
                );
                DEFAULT_RETENTION_DAYS
            }
        },
        Err(_) => DEFAULT_RETENTION_DAYS,
    }
}

/// Reads the configured sweep interval, clamped to at least one second.
fn sweep_seconds_from_env() -> u64 {
    match std::env::var(RETENTION_SWEEP_ENV) {
        Ok(raw) => raw.trim().parse::<u64>().unwrap_or(DEFAULT_SWEEP_SECONDS).max(1),
        Err(_) => DEFAULT_SWEEP_SECONDS,
    }
}

/// Permanently deletes soft-deleted IP records whose `deleted_at` is older than `retention_days`.
///
/// Returns the number of rows removed. A non-positive `retention_days` disables purging and is a
/// no-op, so an operator can retain the trash indefinitely without also disabling the worker.
///
/// Both conditions are required, not just the timestamp: a row with `deleted_at` set but
/// `is_deleted = false` is a *restored* record that kept its old timestamp, and purging it would
/// silently destroy live data. Matching on the flag as well makes that impossible by construction.
///
/// The `ip_record_group_memberships` rows go with it via the schema's `ON DELETE CASCADE`, so no
/// orphan junction rows survive the purge.
pub async fn purge_expired_ip_records(
    db: &DatabaseConnection,
    retention_days: i64,
) -> Result<u64, DbErr> {
    if retention_days <= 0 {
        return Ok(0);
    }

    let threshold = (Utc::now() - chrono::Duration::days(retention_days)).naive_utc();

    let result = ip_record::Entity::delete_many()
        .filter(ip_record::Column::IsDeleted.eq(true))
        .filter(ip_record::Column::DeletedAt.is_not_null())
        .filter(ip_record::Column::DeletedAt.lt(threshold))
        .exec(db)
        .await?;

    Ok(result.rows_affected)
}

/// Runs the retention sweep on a fixed interval until shutdown.
///
/// The worker owns the receiving half of a channel whose sender lives in `main`; dropping that
/// sender is the shutdown signal, so the worker stops cleanly during graceful shutdown rather than
/// being aborted mid-delete. The first tick fires immediately, so a process restarted more often
/// than the sweep interval still clears its backlog.
pub async fn run_retention_worker(db: DatabaseConnection, mut shutdown: mpsc::Receiver<()>) {
    let retention_days = retention_days_from_env();
    if retention_days <= 0 {
        tracing::info!(
            "IP retention purge is disabled ({RETENTION_DAYS_ENV}=0): soft-deleted records are \
             kept indefinitely."
        );
        return;
    }

    let sweep_seconds = sweep_seconds_from_env();
    tracing::info!(
        retention_days,
        sweep_seconds,
        "IP retention worker started — soft-deleted records are purged after {retention_days} days."
    );

    let mut ticker = tokio::time::interval(Duration::from_secs(sweep_seconds));
    // If a sweep runs long (a large backlog on slow storage), skip the ticks it missed rather than
    // firing them back to back the moment it finishes.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match purge_expired_ip_records(&db, retention_days).await {
                    Ok(0) => tracing::debug!("Retention sweep: nothing to purge."),
                    Ok(n) => tracing::info!("Retention sweep: purged {n} soft-deleted IP record(s)."),
                    Err(e) => tracing::error!("Retention sweep failed: {e}"),
                }
            }
            _ = shutdown.recv() => break,
        }
    }

    tracing::info!("IP retention worker shut down.");
}
