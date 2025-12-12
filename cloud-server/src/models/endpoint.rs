//! Endpoint (Agent) model

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Endpoint {
    pub id: Uuid,
    pub org_id: Uuid,
    pub hostname: String,
    pub os_type: Option<String>,
    pub os_version: Option<String>,
    pub agent_version: Option<String>,
    pub ip_address: Option<String>,
    #[serde(skip_serializing)]
    pub token_hash: Option<String>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub status: String,
    pub baseline_hash: Option<String>,
    pub baseline_version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointSummary {
    pub id: Uuid,
    pub hostname: String,
    pub os_type: Option<String>,
    pub status: String,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub incident_count: i64,
}

#[derive(Debug, Deserialize)]
pub struct RegisterAgentRequest {
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub agent_version: String,
    pub registration_key: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterAgentResponse {
    pub agent_id: Uuid,
    pub token: String,
    pub org_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: Option<f32>,
    pub incident_count: i32,
    pub process_count: Option<i32>,
    pub agent_version: String,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub server_time: i64,
    pub policy_version: i32,
    pub has_policy_update: bool,
    pub commands: Vec<AgentCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentCommand {
    UpdatePolicy { version: i32 },
    CollectDiagnostics,
    RestartService,
    UpdateAgent { url: String, checksum: String },
}

impl Endpoint {
    pub async fn register(
        pool: &PgPool,
        org_id: Uuid,
        data: RegisterAgentRequest,
        token_hash: String
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, Endpoint>(
            r#"
            INSERT INTO endpoints (org_id, hostname, os_type, os_version, agent_version, token_hash, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'online')
            RETURNING *
            "#
        )
        .bind(org_id)
        .bind(&data.hostname)
        .bind(&data.os_type)
        .bind(&data.os_version)
        .bind(&data.agent_version)
        .bind(&token_hash)
        .fetch_one(pool)
        .await
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Endpoint>("SELECT * FROM endpoints WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    pub async fn find_by_token_hash(pool: &PgPool, token_hash: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Endpoint>("SELECT * FROM endpoints WHERE token_hash = $1")
            .bind(token_hash)
            .fetch_optional(pool)
            .await
    }

    pub async fn list_by_org(pool: &PgPool, org_id: Uuid, limit: i64) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Endpoint>(
            r#"
            SELECT * FROM endpoints
            WHERE org_id = $1
            ORDER BY last_heartbeat DESC NULLS LAST
            LIMIT $2
            "#
        )
        .bind(org_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    pub async fn update_heartbeat(
        pool: &PgPool,
        id: Uuid,
        ip_address: Option<String>,
        agent_version: &str
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE endpoints
            SET last_heartbeat = NOW(),
                status = 'online',
                ip_address = COALESCE($2, ip_address),
                agent_version = $3,
                updated_at = NOW()
            WHERE id = $1
            "#
        )
        .bind(id)
        .bind(ip_address)
        .bind(agent_version)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn delete(pool: &PgPool, id: Uuid, org_id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM endpoints WHERE id = $1 AND org_id = $2")
            .bind(id)
            .bind(org_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}
