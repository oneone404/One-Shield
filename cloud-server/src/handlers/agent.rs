//! Agent handlers

use axum::{extract::State, Json};
use sha2::{Sha256, Digest};
use uuid::Uuid;
use chrono::Utc;
use sqlx::Row;

use crate::{AppState, AppError, AppResult};
use crate::models::{
    Endpoint, RegisterAgentRequest, RegisterAgentResponse,
    HeartbeatRequest, HeartbeatResponse, AgentCommand,
    Baseline, SyncBaselineRequest, SyncBaselineResponse,
    Incident, CreateIncident, SyncIncidentsRequest, SyncIncidentsResponse,
    Policy,
};
use crate::middleware::auth::AgentContext;

/// Register new agent
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterAgentRequest>,
) -> AppResult<Json<RegisterAgentResponse>> {
    // Validate registration key (simple validation - in production, use proper key management)
    if req.registration_key != state.config.agent_secret {
        return Err(AppError::Unauthorized);
    }

    // For demo, use default org. In production, extract org from registration key
    let org_id = get_default_org(&state.pool).await?;

    // Generate agent token
    let token = Uuid::new_v4().to_string();
    let token_hash = hash_token(&token);

    // Register endpoint
    let endpoint = Endpoint::register(&state.pool, org_id, req, token_hash).await?;

    tracing::info!("Agent registered: {} ({})", endpoint.hostname, endpoint.id);

    Ok(Json(RegisterAgentResponse {
        agent_id: endpoint.id,
        token,
        org_id,
    }))
}

/// Agent heartbeat
pub async fn heartbeat(
    State(state): State<AppState>,
    agent: AgentContext,
    Json(req): Json<HeartbeatRequest>,
) -> AppResult<Json<HeartbeatResponse>> {
    // Update heartbeat
    Endpoint::update_heartbeat(&state.pool, agent.endpoint_id, agent.ip_address.clone(), &req.agent_version).await?;

    // Record metrics
    record_heartbeat_metrics(&state.pool, agent.endpoint_id, &req).await?;

    // Check for policy updates
    let policy = Policy::get_active(&state.pool, agent.org_id).await?;
    let (policy_version, has_update) = match policy {
        Some(p) => (p.version, p.version > agent.policy_version.unwrap_or(0)),
        None => (0, false),
    };

    // Collect pending commands (for now, empty)
    let commands: Vec<AgentCommand> = vec![];

    Ok(Json(HeartbeatResponse {
        server_time: Utc::now().timestamp(),
        policy_version,
        has_policy_update: has_update,
        commands,
    }))
}

/// Sync baseline from agent
pub async fn sync_baseline(
    State(state): State<AppState>,
    agent: AgentContext,
    Json(req): Json<SyncBaselineRequest>,
) -> AppResult<Json<SyncBaselineResponse>> {
    // Update baseline
    let baseline = Baseline::upsert(&state.pool, agent.endpoint_id, req).await?;

    // Update endpoint baseline hash
    sqlx::query(
        "UPDATE endpoints SET baseline_hash = $2, baseline_version = $3, updated_at = NOW() WHERE id = $1"
    )
    .bind(agent.endpoint_id)
    .bind(baseline.mean_values.to_string())
    .bind(baseline.version)
    .execute(&state.pool)
    .await?;

    tracing::debug!("Baseline synced for agent {}", agent.endpoint_id);

    Ok(Json(SyncBaselineResponse {
        accepted: true,
        server_version: baseline.version,
        server_time: Utc::now().timestamp(),
    }))
}

/// Sync incidents from agent
pub async fn sync_incidents(
    State(state): State<AppState>,
    agent: AgentContext,
    Json(req): Json<SyncIncidentsRequest>,
) -> AppResult<Json<SyncIncidentsResponse>> {
    let mut synced = 0;

    for incident_data in req.incidents {
        match Incident::create(&state.pool, agent.endpoint_id, incident_data).await {
            Ok(_) => synced += 1,
            Err(e) => tracing::warn!("Failed to sync incident: {}", e),
        }
    }

    tracing::info!("Synced {} incidents from agent {}", synced, agent.endpoint_id);

    Ok(Json(SyncIncidentsResponse {
        synced_count: synced,
        server_time: Utc::now().timestamp(),
    }))
}

/// Get active policy for agent
pub async fn get_policy(
    State(state): State<AppState>,
    agent: AgentContext,
) -> AppResult<Json<Option<Policy>>> {
    let policy = Policy::get_active(&state.pool, agent.org_id).await?;
    Ok(Json(policy))
}

// Helper functions

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

async fn get_default_org(pool: &sqlx::PgPool) -> AppResult<Uuid> {
    // Get first org, or create default
    let row = sqlx::query("SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1")
        .fetch_optional(pool)
        .await?;

    match row {
        Some(r) => Ok(r.get::<Uuid, _>("id")),
        None => {
            // Create default org
            let org = crate::models::Organization::create(
                pool,
                crate::models::CreateOrganization {
                    name: "Default Organization".to_string(),
                    max_agents: Some(100),
                }
            ).await?;
            Ok(org.id)
        }
    }
}

async fn record_heartbeat_metrics(
    pool: &sqlx::PgPool,
    endpoint_id: Uuid,
    req: &HeartbeatRequest,
) -> AppResult<()> {
    sqlx::query(
        r#"
        INSERT INTO heartbeat_history (endpoint_id, cpu_usage, memory_usage, disk_usage, incident_count, process_count)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#
    )
    .bind(endpoint_id)
    .bind(req.cpu_usage)
    .bind(req.memory_usage)
    .bind(req.disk_usage)
    .bind(req.incident_count)
    .bind(req.process_count)
    .execute(pool)
    .await?;
    Ok(())
}
