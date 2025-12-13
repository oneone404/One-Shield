//! Organization handlers

use axum::{extract::State, Json};
use serde::Serialize;

use crate::{AppState, AppResult, AppError};
use crate::models::{Organization, User, UserInfo, OrgTier};
use crate::middleware::auth::UserContext;

/// Organization features based on tier
#[derive(Debug, Serialize)]
pub struct OrgFeatures {
    pub can_create_tokens: bool,
    pub can_manage_users: bool,
    pub can_view_audit_logs: bool,
    pub can_access_api: bool,
    pub max_devices: i32,
}

/// Organization info response with tier and features
#[derive(Debug, Serialize)]
pub struct OrgInfoResponse {
    pub id: uuid::Uuid,
    pub name: String,
    pub tier: String,
    pub max_agents: i32,
    pub current_agents: i64,
    pub features: OrgFeatures,
}

/// Get organization details with tier and features
pub async fn get(
    State(state): State<AppState>,
    user: UserContext,
) -> AppResult<Json<OrgInfoResponse>> {
    let org = Organization::find_by_id(&state.pool, user.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let current_agents = org.count_agents(&state.pool).await.unwrap_or(0);
    let tier = org.get_tier();
    let is_org = tier == OrgTier::Organization;

    let features = OrgFeatures {
        can_create_tokens: is_org,
        can_manage_users: is_org,
        can_view_audit_logs: is_org,
        can_access_api: is_org,
        max_devices: org.max_devices(),
    };

    Ok(Json(OrgInfoResponse {
        id: org.id,
        name: org.name,
        tier: tier.as_str().to_string(),
        max_agents: org.max_agents,
        current_agents,
        features,
    }))
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
