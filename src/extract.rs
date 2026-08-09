//! Request extractors that make a rejection a property of the **type**, not of a handler.
//!
//! `RBAC_MODEL.md` §5 draws the distinction this module exists for: "Removing the field from the
//! payload type is required; rejecting it at the handler is not sufficient, since a later handler can
//! reintroduce the path."
//!
//! Deleting a field from a payload struct is only half of that. Serde's default is to *ignore*
//! unknown fields, so a struct without `is_master` accepts `{"is_master": true}` and silently drops
//! it — which is worse than the handler check it replaced, because nothing refuses and nothing logs.
//! `#[serde(deny_unknown_fields)]` is what turns the field's absence into a refusal, and
//! [`StrictJson`] is what turns that refusal into the same `400` the handler used to produce.

use axum::{
    extract::{FromRequest, Request, rejection::JsonRejection},
    Json,
};
use serde::de::DeserializeOwned;

use crate::error::AppError;

/// [`Json`], with deserialization failures reported as [`AppError::InvalidInput`] (`400`) instead of
/// axum's default `422`.
///
/// # Why not just use `Json`
///
/// Two reasons, and only the second is about status codes.
///
/// The first is that a rejection carrying serde's own message is *evidence of where the refusal
/// happened*. When a payload struct denies unknown fields, the body text names the field
/// (``unknown field `is_master` ``), which a test can distinguish from a handler's hand-written
/// message. That is what lets the compliance suite assert the control lives in the type rather than
/// in a guard some future edit could drop — an assertion it could not otherwise make, since both
/// spellings produce the same status.
///
/// The second is continuity: these endpoints answered `400` for a rejected field before the check
/// moved into the type, and moving a control inward should not change what a client sees.
///
/// # Only the content errors are remapped
///
/// A blanket "every rejection becomes `400`" would be wrong, and quietly so. The router-wide body
/// limit surfaces here as a `JsonRejection` too, and collapsing it would demote `413 Payload Too
/// Large` into an indistinguishable bad request — a caller that sent 4 MiB would be told its *fields*
/// were wrong. So the remap covers exactly the two variants that mean "we read the body and would not
/// accept it", and every other rejection keeps the status axum chose.
///
/// `simply_hook_executor` passes every status through, including for a rejected field, so a payload
/// carrying `is_master` answers `422` there and `400` here. Deliberate, and the one divergence in
/// this file: this service documented `400` for that case before the control moved into the type.
pub struct StrictJson<T>(pub T);

impl<T, S> FromRequest<S> for StrictJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            // `body_text` is the human-readable form axum would have rendered itself, so the caller
            // gets serde's field-level detail rather than a generic "invalid body".
            Err(rejection @ (JsonRejection::JsonDataError(_) | JsonRejection::JsonSyntaxError(_))) => {
                Err(AppError::InvalidInput(JsonRejection::body_text(&rejection)))
            }
            Err(other) => {
                Err(AppError::BodyRejected(other.status(), JsonRejection::body_text(&other)))
            }
        }
    }
}
