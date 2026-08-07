//! Application errors

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Global application error type
#[derive(Error, Debug)]
pub enum AppError {
    /// Database error
    #[error("Database error: {0}")]
    DbError(#[from] sea_orm::DbErr),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Unauthorized access
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Forbidden access
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Resource not found
    #[error("Not Found")]
    NotFound,

    /// The request conflicts with the current state of a resource (e.g. a unique-name collision)
    #[error("Conflict: {0}")]
    Conflict(String),

    /// A conflict the caller is expected to *resolve*, carrying the structured detail needed to do so.
    ///
    /// Exists for `RBAC_MODEL.md` §6's pre-flight inventory, which requires the refusal to return "a
    /// structured payload enumerating each owned entity with enough detail to decide its fate: type,
    /// id, name, and current owner". A bare message would make the caller go and find that itself, and
    /// the whole point of the refusal is that the service already knows.
    ///
    /// The `details` object is merged into the response body alongside `error`, so a client that only
    /// reads `error` behaves exactly as it does for [`Self::Conflict`].
    #[error("Conflict: {message}")]
    ConflictWithDetails {
        /// Human-readable summary, in the same `error` field every other variant uses.
        message: String,
        /// Machine-readable detail, merged into the response body at the top level.
        details: serde_json::Value,
    },

    /// Internal server error
    #[error("Internal Server Error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Handled ahead of the flat match because it is the one variant whose body is not just
        // `{"error": ...}` — the structured detail is merged in at the top level rather than nested,
        // so `error` reads identically to every other variant for a client that ignores the rest.
        if let AppError::ConflictWithDetails { message, details } = self {
            let mut body = json!({ "error": message });
            if let (Some(object), Some(extra)) = (body.as_object_mut(), details.as_object()) {
                for (k, v) in extra {
                    object.insert(k.clone(), v.clone());
                }
            }
            return (StatusCode::CONFLICT, Json(body)).into_response();
        }

        let (status, error_message) = match self {
            AppError::DbError(err) => {
                tracing::error!("Database error: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error".to_string())
            }
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_string()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            // Returned above; repeated here only because the match must stay exhaustive.
            AppError::ConflictWithDetails { message, .. } => (StatusCode::CONFLICT, message),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "An internal server error occurred".to_string()),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
