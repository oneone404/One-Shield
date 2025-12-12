//! Error handling

use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde_json::json;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
pub enum AppError {
    // Auth errors
    InvalidCredentials,
    TokenExpired,
    TokenInvalid,
    Unauthorized,
    Forbidden,

    // Resource errors
    NotFound(String),
    AlreadyExists(String),

    // Validation errors
    ValidationError(String),

    // Database errors
    DatabaseError(String),

    // External service errors
    ExternalServiceError(String),

    // Generic errors
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid email or password"),
            AppError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token has expired"),
            AppError::TokenInvalid => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Authentication required"),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Access denied"),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.as_str()),
            AppError::AlreadyExists(msg) => (StatusCode::CONFLICT, msg.as_str()),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::DatabaseError(msg) => {
                tracing::error!("Database error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error occurred")
            }
            AppError::ExternalServiceError(msg) => {
                tracing::error!("External service error: {}", msg);
                (StatusCode::BAD_GATEWAY, "External service error")
            }
            AppError::InternalError(msg) => {
                tracing::error!("Internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::DatabaseError(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(_: jsonwebtoken::errors::Error) -> Self {
        AppError::TokenInvalid
    }
}
