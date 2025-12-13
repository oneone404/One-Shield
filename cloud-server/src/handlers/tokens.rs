//! Token management handlers

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use uuid::Uuid;

use crate::{AppError, AppResult, AppState};
use crate::middleware::auth::{UserContext, require_admin};
use crate::models::{CreateTokenRequest, OrganizationToken, TokenInfo};

/// Response for creating a token
#[derive(Serialize)]
pub struct CreateTokenResponse {
    pub id: Uuid,
    pub token: String,
    pub install_url: String,
    pub install_command: String,
}

/// List all tokens for the user's organization
/// Note: Viewing tokens is allowed for all roles (admin and viewer)
pub async fn list_tokens(
    State(state): State<AppState>,
    user: UserContext,
) -> AppResult<Json<Vec<TokenInfo>>> {
    let tokens = OrganizationToken::list_by_org(&state.pool, user.org_id).await?;
    let infos: Vec<TokenInfo> = tokens.iter().map(|t| t.to_info()).collect();
    Ok(Json(infos))
}

/// Create a new enrollment token
/// Requires: Admin role
pub async fn create_token(
    State(state): State<AppState>,
    user: UserContext,
    Json(req): Json<CreateTokenRequest>,
) -> AppResult<Json<CreateTokenResponse>> {
    // RBAC: Admin only
    require_admin(&user)?;

    let token = OrganizationToken::create(
        &state.pool,
        user.org_id,
        Some(user.user_id),
        req,
    ).await?;

    let install_url = format!(
        "https://dashboard.accone.vn/install?token={}",
        token.token
    );

    let install_command = format!(
        "OneShield.exe --enroll-token={}",
        token.token
    );

    tracing::info!("Token created: {} by admin {}", token.id, user.user_id);

    Ok(Json(CreateTokenResponse {
        id: token.id,
        token: token.token,
        install_url,
        install_command,
    }))
}

/// Get token details
/// Note: Viewing is allowed for all roles
pub async fn get_token(
    State(state): State<AppState>,
    user: UserContext,
    Path(token_id): Path<Uuid>,
) -> AppResult<Json<TokenInfo>> {
    let token = OrganizationToken::get_by_id(&state.pool, token_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Token not found".to_string()))?;

    // Verify ownership
    if token.org_id != user.org_id {
        return Err(AppError::Forbidden);
    }

    Ok(Json(token.to_info()))
}

/// Revoke a token
/// Requires: Admin role
pub async fn revoke_token(
    State(state): State<AppState>,
    user: UserContext,
    Path(token_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    // RBAC: Admin only
    require_admin(&user)?;

    // Verify ownership
    let token = OrganizationToken::get_by_id(&state.pool, token_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Token not found".to_string()))?;

    if token.org_id != user.org_id {
        return Err(AppError::Forbidden);
    }

    OrganizationToken::revoke(&state.pool, token_id).await?;

    tracing::info!("Token revoked: {} by admin {}", token_id, user.user_id);

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Token revoked successfully"
    })))
}

