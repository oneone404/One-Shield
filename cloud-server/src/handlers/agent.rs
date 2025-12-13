//! Agent handlers

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
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
    Policy, OrganizationToken,
};
use crate::middleware::auth::AgentContext;

/// Enrollment request (uses org token instead of registration_key)
#[derive(Debug, Deserialize)]
pub struct EnrollAgentRequest {
    /// Organization enrollment token (ORG_xxx)
    pub enrollment_token: String,
    /// Hardware ID of the machine
    pub hwid: String,
    /// Machine hostname
    pub hostname: String,
    /// Operating system type
    #[serde(default = "default_os_type")]
    pub os_type: String,
    /// Operating system version
    #[serde(default)]
    pub os_version: Option<String>,
    /// Agent version
    #[serde(default)]
    pub agent_version: Option<String>,
}

fn default_os_type() -> String {
    "Windows".to_string()
}

/// Enrollment response
#[derive(Debug, Serialize)]
pub struct EnrollAgentResponse {
    pub agent_id: Uuid,
    pub agent_token: String,
    pub org_id: Uuid,
    pub org_name: String,
}

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
            // Create default org (organization tier for legacy/fallback)
            let org = crate::models::Organization::create(
                pool,
                crate::models::CreateOrganization {
                    name: "Default Organization".to_string(),
                    max_agents: Some(100),
                    tier: Some("organization".to_string()),
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

/// Get organization name by ID
async fn get_org_name(pool: &sqlx::PgPool, org_id: Uuid) -> AppResult<String> {
    let row = sqlx::query("SELECT name FROM organizations WHERE id = $1")
        .bind(org_id)
        .fetch_optional(pool)
        .await?;

    match row {
        Some(r) => Ok(r.get::<String, _>("name")),
        None => Ok("Unknown Organization".to_string()),
    }
}

/// Find existing endpoint by HWID
async fn find_endpoint_by_hwid(pool: &sqlx::PgPool, hwid: &str) -> AppResult<Option<Endpoint>> {
    let endpoint = sqlx::query_as::<_, Endpoint>(
        "SELECT * FROM endpoints WHERE hwid = $1"
    )
    .bind(hwid)
    .fetch_optional(pool)
    .await?;

    Ok(endpoint)
}

/// Enroll agent using organization enrollment token (Phase 12)
/// This is the new enrollment flow - race-condition safe with atomic token usage
pub async fn enroll(
    State(state): State<AppState>,
    Json(req): Json<EnrollAgentRequest>,
) -> AppResult<Json<EnrollAgentResponse>> {
    // 1. Lookup token by value
    let token = OrganizationToken::get_by_value(&state.pool, &req.enrollment_token)
        .await?
        .ok_or_else(|| {
            tracing::warn!("Invalid enrollment token: {}", &req.enrollment_token[..8.min(req.enrollment_token.len())]);
            AppError::Unauthorized
        })?;

    // 2. Check if HWID already registered (re-enrollment case)
    if let Some(existing) = find_endpoint_by_hwid(&state.pool, &req.hwid).await? {
        // Re-enrollment: Generate new agent token but keep same agent_id
        let new_token = Uuid::new_v4().to_string();
        let token_hash = hash_token(&new_token);

        // Update token hash in DB
        sqlx::query("UPDATE endpoints SET token_hash = $2, updated_at = NOW() WHERE id = $1")
            .bind(existing.id)
            .bind(&token_hash)
            .execute(&state.pool)
            .await?;

        let org_name = get_org_name(&state.pool, existing.org_id).await?;

        tracing::info!("Agent re-enrolled: {} (HWID: {}...)", existing.hostname, &req.hwid[..8.min(req.hwid.len())]);

        return Ok(Json(EnrollAgentResponse {
            agent_id: existing.id,
            agent_token: new_token,
            org_id: existing.org_id,
            org_name,
        }));
    }

    // 3. Atomic: Try to use the token (race-condition safe)
    if !OrganizationToken::try_use(&state.pool, token.id).await? {
        // Token exhausted, expired, or revoked
        tracing::warn!("Token exhausted/expired: {}", token.id);
        return Err(AppError::Forbidden);
    }

    // 4. Generate agent token
    let agent_token = Uuid::new_v4().to_string();
    let token_hash = hash_token(&agent_token);

    // 5. Register new endpoint with HWID
    let endpoint_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO endpoints (id, org_id, hostname, os_type, os_version, agent_version, hwid, token_hash, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'online')
        "#
    )
    .bind(endpoint_id)
    .bind(token.org_id)
    .bind(&req.hostname)
    .bind(&req.os_type)
    .bind(&req.os_version)
    .bind(&req.agent_version)
    .bind(&req.hwid)
    .bind(&token_hash)
    .execute(&state.pool)
    .await?;

    // 6. Get org name
    let org_name = get_org_name(&state.pool, token.org_id).await?;

    tracing::info!(
        "Agent enrolled: {} (id: {}, org: {}, hwid: {}...)",
        req.hostname,
        endpoint_id,
        org_name,
        &req.hwid[..8.min(req.hwid.len())]
    );

    Ok(Json(EnrollAgentResponse {
        agent_id: endpoint_id,
        agent_token,
        org_id: token.org_id,
        org_name,
    }))
}

