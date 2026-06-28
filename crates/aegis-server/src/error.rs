//! Server error types

use thiserror::Error;
use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("rate limited")]
    RateLimited,

    #[error("internal server error")]
    Internal(String),

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("invalid capability token")]
    InvalidToken,

    #[error("queue expired")]
    QueueExpired,

    #[error("envelope expired")]
    EnvelopeExpired,
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ServerError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            ServerError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            ServerError::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            ServerError::BadRequest(s) => (StatusCode::BAD_REQUEST, s.clone()),
            ServerError::Conflict(s) => (StatusCode::CONFLICT, s.clone()),
            ServerError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            ServerError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".into()),
            ServerError::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, self.to_string()),
            ServerError::InvalidToken => (StatusCode::FORBIDDEN, self.to_string()),
            ServerError::QueueExpired => (StatusCode::GONE, self.to_string()),
            ServerError::EnvelopeExpired => (StatusCode::GONE, self.to_string()),
        };

        let body = ErrorBody { error: message };
        (status, Json(body)).into_response()
    }
}
