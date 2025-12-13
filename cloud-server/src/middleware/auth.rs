//! Authentication middleware

use axum::{
    extract::{State, Request},
    middleware::Next,
    response::Response,
    http::header::AUTHORIZATION,
};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::{decode, DecodingKey, Validation};
use sha2::{Sha256, Digest};
use uuid::Uuid;

use crate::{AppState, AppError};
use crate::handlers::auth::Claims;
use crate::models::Endpoint;

/// User context extracted from JWT
#[derive(Debug, Clone)]
pub struct UserContext {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub role: String,
}

impl UserContext {
    /// Check if user has admin role
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

/// RBAC: Require admin role
/// Use this instead of inline `if user.role != "admin"` checks
pub fn require_admin(user: &UserContext) -> Result<(), AppError> {
    if !user.is_admin() {
        tracing::warn!("Admin required but user {} has role '{}'", user.user_id, user.role);
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// RBAC: Require specific role
pub fn require_role(user: &UserContext, required_role: &str) -> Result<(), AppError> {
    if user.role != required_role {
        tracing::warn!(
            "Role '{}' required but user {} has role '{}'",
            required_role, user.user_id, user.role
        );
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Agent context extracted from token
#[derive(Debug, Clone)]
pub struct AgentContext {
    pub endpoint_id: Uuid,
    pub org_id: Uuid,
    pub ip_address: Option<String>,
    pub policy_version: Option<i32>,
}

/// Middleware: Require user JWT authentication
pub async fn require_user_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer_token(&req)?;

    // Decode JWT
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::default()
    ).map_err(|_| AppError::TokenInvalid)?;

    let claims = token_data.claims;

    // Create user context
    let user_ctx = UserContext {
        user_id: Uuid::parse_str(&claims.sub).map_err(|_| AppError::TokenInvalid)?,
        org_id: Uuid::parse_str(&claims.org).map_err(|_| AppError::TokenInvalid)?,
        role: claims.role,
    };

    // Insert into request extensions
    req.extensions_mut().insert(user_ctx);

    Ok(next.run(req).await)
}

/// Middleware: Require agent token authentication
pub async fn require_agent_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_bearer_token(&req)?;

    // Hash the token
    let token_hash = hash_token(&token);

    // Find endpoint by token hash
    let endpoint = Endpoint::find_by_token_hash(&state.pool, &token_hash)
        .await
        .map_err(|_| AppError::InternalError("Database error".to_string()))?
        .ok_or(AppError::Unauthorized)?;

    // Extract IP address
    let ip_address = req.headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

    // Create agent context
    let agent_ctx = AgentContext {
        endpoint_id: endpoint.id,
        org_id: endpoint.org_id,
        ip_address,
        policy_version: Some(endpoint.baseline_version),
    };

    // Insert into request extensions
    req.extensions_mut().insert(agent_ctx);

    Ok(next.run(req).await)
}

/// Extract bearer token from Authorization header
fn extract_bearer_token(req: &Request) -> Result<String, AppError> {
    let auth_header = req.headers()
        .get(AUTHORIZATION)
        .ok_or(AppError::Unauthorized)?
        .to_str()
        .map_err(|_| AppError::Unauthorized)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized);
    }

    Ok(auth_header[7..].to_string())
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

// Implement FromRequestParts for UserContext
#[axum::async_trait]
impl<S> FromRequestParts<S> for UserContext
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions
            .get::<UserContext>()
            .cloned()
            .ok_or(AppError::Unauthorized)
    }
}

// Implement FromRequestParts for AgentContext
#[axum::async_trait]
impl<S> FromRequestParts<S> for AgentContext
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions
            .get::<AgentContext>()
            .cloned()
            .ok_or(AppError::Unauthorized)
    }
}

