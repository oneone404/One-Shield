//! Policies handlers

use axum::{extract::{State, Path}, Json};
use uuid::Uuid;

use crate::{AppState, AppResult, AppError};
use crate::models::{Policy, CreatePolicy, UpdatePolicy};
use crate::middleware::auth::UserContext;

/// List policies for organization
pub async fn list(
    State(state): State<AppState>,
    user: UserContext,
) -> AppResult<Json<Vec<Policy>>> {
    let policies = Policy::list_by_org(&state.pool, user.org_id).await?;
    Ok(Json(policies))
}

/// Get single policy
pub async fn get(
    State(state): State<AppState>,
    user: UserContext,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Policy>> {
    let policy = Policy::find_by_id(&state.pool, id)
        .await?
        .ok_or_else(|| AppError::NotFound("Policy not found".to_string()))?;

    // Verify org ownership
    if policy.org_id != user.org_id {
        return Err(AppError::Forbidden);
    }

    Ok(Json(policy))
}

/// Create new policy
pub async fn create(
    State(state): State<AppState>,
    user: UserContext,
    Json(req): Json<CreatePolicy>,
) -> AppResult<Json<Policy>> {
    let policy = Policy::create(&state.pool, user.org_id, req).await?;
    Ok(Json(policy))
}

/// Update policy
pub async fn update(
    State(state): State<AppState>,
    user: UserContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdatePolicy>,
) -> AppResult<Json<Policy>> {
    // Verify ownership first
    let existing = Policy::find_by_id(&state.pool, id)
        .await?
        .ok_or_else(|| AppError::NotFound("Policy not found".to_string()))?;

    if existing.org_id != user.org_id {
        return Err(AppError::Forbidden);
    }

    let policy = Policy::update(&state.pool, id, req)
        .await?
        .ok_or_else(|| AppError::NotFound("Policy not found".to_string()))?;

    Ok(Json(policy))
}
