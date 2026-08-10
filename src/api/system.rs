//! Unauthenticated liveness and readiness probes.
//!
//! # Why these two are not behind `auth_middleware`
//!
//! Everything else this service exposes requires an HMAC-signed request, and that is not a posture
//! these endpoints can share. The callers are orchestrators — Docker's `HEALTHCHECK`, a Kubernetes
//! probe, a load balancer's backend check — and none of them can compute an HMAC over a body with a
//! rolling timestamp. Giving a probe a credential to hold would mean minting a long-lived key whose
//! only job is to be readable by the platform, which is a worse trade than the one below.
//!
//! So they are mounted on the root router, outside the `/api` nest, and they are written to be safe
//! without a caller identity:
//!
//! - **No data.** Neither response contains a key, a record, a group, a count, or a name.
//! - **No error detail.** A failing readiness probe answers `503` with a fixed string. The database
//!   error itself goes to the log, where an operator can read it and an anonymous caller cannot —
//!   a connection string or a file path in an unauthenticated response body is an information leak.
//! - **No writes**, and one bounded read.
//!
//! # Liveness and readiness are different questions
//!
//! [`health_check`] answers "is this process running?" and touches nothing. [`readiness_check`]
//! answers "can this process serve a request?" and therefore has to prove the database is reachable,
//! because a vault whose database has gone away is up and useless. Conflating them is the classic
//! operational mistake: a liveness probe that checks a dependency makes an orchestrator *restart*
//! the service when the **database** is down, replacing a partial outage with a crash loop.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use sea_orm::{EntityTrait, QuerySelect};
use serde_json::json;

use crate::state::AppState;

/// Handles `GET /health` — liveness. Always `200` if the process is answering at all.
///
/// Deliberately dependency-free: no database, no lock, no `await` on anything that can hang. That is
/// the entire contract. An orchestrator uses this to decide whether to **restart** the container, so
/// anything checked here becomes a reason to kill a process that is otherwise fine — see the module
/// header. Readiness is the endpoint that gets to have opinions.
pub async fn health_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "service": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
}

/// Handles `GET /ready` — readiness. `200` when this process can serve traffic, `503` when it cannot.
///
/// Two things are checked, and both are properties of *this process* rather than of the request:
///
/// 1. **The database answers.** A bounded, indexed-by-primary-key read of at most one row — not a
///    `COUNT(*)`, which on a large `api_keys` table would make every probe a table scan and turn the
///    health check itself into load.
/// 2. **The Master identity is pinned.** `main.rs` pins before binding the listener, so in production
///    this is a `OnceLock` read that cannot be false. It is asserted anyway because that ordering is
///    a *convention* enforced by one line of `main.rs`, and a future edit that binds first would
///    otherwise produce a service reporting itself ready while every master-only route was quietly
///    refusing. Cheap to check, and it catches a regression that is otherwise invisible.
///
/// A failure names *which* of the two failed, but never why: the database error is logged, not
/// returned. See the module header.
pub async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(e) = crate::entities::prelude::ApiKey::find()
        .select_only()
        .column(crate::entities::api_key::Column::Id)
        .limit(1)
        .into_tuple::<uuid::Uuid>()
        .all(&state.db)
        .await
    {
        tracing::error!("Readiness probe failed: the database is unreachable: {e}");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unavailable", "reason": "database unreachable" })),
        );
    }

    if state.master_pin.get().is_none() {
        tracing::error!(
            "Readiness probe failed: no Master identity is pinned. This process should not have \
             bound its listener — see main.rs and RBAC_MODEL.md §5."
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unavailable", "reason": "master identity not pinned" })),
        );
    }

    (
        StatusCode::OK,
        Json(json!({ "status": "ready", "database": "ok", "master_pinned": true })),
    )
}
