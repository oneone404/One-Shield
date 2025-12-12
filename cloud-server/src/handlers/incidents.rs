//! Incidents handlers

use axum::{extract::{State, Path, Query}, Json};
use uuid::Uuid;

use crate::{AppState, AppResult, AppError};
use crate::models::{Incident, IncidentFilter, UpdateIncidentStatus};
use crate::middleware::auth::UserContext;

/// List incidents for organization
pub async fn list(
    State(state): State<AppState>,
    user: UserContext,
    Query(filter): Query<IncidentFilter>,
) -> AppResult<Json<Vec<Incident>>> {
    let incidents = Incident::list_by_org(&state.pool, user.org_id, filter).await?;
    Ok(Json(incidents))
}

/// Get single incident
pub async fn get(
    State(state): State<AppState>,
    _user: UserContext,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Incident>> {
    let incident = Incident::find_by_id(&state.pool, id)
        .await?
        .ok_or_else(|| AppError::NotFound("Incident not found".to_string()))?;

    Ok(Json(incident))
}

/// Update incident status
pub async fn update_status(
    State(state): State<AppState>,
    _user: UserContext,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateIncidentStatus>,
) -> AppResult<Json<Incident>> {
    let incident = Incident::update_status(&state.pool, id, &req.status, req.assigned_to)
        .await?
        .ok_or_else(|| AppError::NotFound("Incident not found".to_string()))?;

    Ok(Json(incident))
}
