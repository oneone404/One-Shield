//! Endpoints handlers

use axum::{extract::{State, Path, Query}, Json};
use uuid::Uuid;
use serde::Deserialize;

use crate::{AppState, AppResult, AppError};
use crate::models::Endpoint;
use crate::middleware::auth::UserContext;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
}

/// List all endpoints for organization
pub async fn list(
    State(state): State<AppState>,
    user: UserContext,
    Query(query): Query<ListQuery>,
) -> AppResult<Json<Vec<Endpoint>>> {
    let limit = query.limit.unwrap_or(50);
    let endpoints = Endpoint::list_by_org(&state.pool, user.org_id, limit).await?;
    Ok(Json(endpoints))
}

/// Get single endpoint
pub async fn get(
    State(state): State<AppState>,
    user: UserContext,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Endpoint>> {
    let endpoint = Endpoint::find_by_id(&state.pool, id)
        .await?
        .ok_or_else(|| AppError::NotFound("Endpoint not found".to_string()))?;

    // Verify org ownership
    if endpoint.org_id != user.org_id {
        return Err(AppError::Forbidden);
    }

    Ok(Json(endpoint))
}

/// Delete endpoint
pub async fn delete(
    State(state): State<AppState>,
    user: UserContext,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let deleted = Endpoint::delete(&state.pool, id, user.org_id).await?;

    if !deleted {
        return Err(AppError::NotFound("Endpoint not found".to_string()));
    }

    Ok(Json(serde_json::json!({ "deleted": true })))
}
