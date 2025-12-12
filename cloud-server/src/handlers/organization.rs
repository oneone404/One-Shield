//! Organization handlers

use axum::{extract::State, Json};
use sqlx::Row;

use crate::{AppState, AppResult, AppError};
use crate::models::{Organization, User, UserInfo};
use crate::middleware::auth::UserContext;

/// Get organization details
pub async fn get(
    State(state): State<AppState>,
    user: UserContext,
) -> AppResult<Json<Organization>> {
    let org = Organization::find_by_id(&state.pool, user.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    Ok(Json(org))
}

/// List users in organization
pub async fn list_users(
    State(state): State<AppState>,
    user: UserContext,
) -> AppResult<Json<Vec<UserInfo>>> {
    let users = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE org_id = $1 ORDER BY created_at DESC"
    )
    .bind(user.org_id)
    .fetch_all(&state.pool)
    .await?;

    let user_infos: Vec<_> = users.iter().map(|u| u.to_info()).collect();
    Ok(Json(user_infos))
}
