//! Policy model

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Policy {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub config: serde_json::Value,
    pub version: i32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub scan_interval_seconds: i32,
    pub baseline_sensitivity: f32,
    pub enable_amsi: bool,
    pub enable_injection_detection: bool,
    pub enable_keylogger_detection: bool,
    pub enable_iat_analysis: bool,
    pub auto_quarantine: bool,
    pub notification_channels: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            scan_interval_seconds: 2,
            baseline_sensitivity: 0.7,
            enable_amsi: true,
            enable_injection_detection: true,
            enable_keylogger_detection: true,
            enable_iat_analysis: true,
            auto_quarantine: false,
            notification_channels: vec!["dashboard".to_string()],
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicy {
    pub name: String,
    pub description: Option<String>,
    pub config: PolicyConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePolicy {
    pub name: Option<String>,
    pub description: Option<String>,
    pub config: Option<PolicyConfig>,
    pub is_active: Option<bool>,
}

impl Policy {
    pub async fn create(pool: &PgPool, org_id: Uuid, data: CreatePolicy) -> Result<Self, sqlx::Error> {
        let config_json = serde_json::to_value(&data.config).unwrap();

        sqlx::query_as::<_, Policy>(
            r#"
            INSERT INTO policies (org_id, name, description, config)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#
        )
        .bind(org_id)
        .bind(&data.name)
        .bind(&data.description)
        .bind(&config_json)
        .fetch_one(pool)
        .await
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Policy>("SELECT * FROM policies WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    pub async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Policy>(
            "SELECT * FROM policies WHERE org_id = $1 ORDER BY created_at DESC"
        )
        .bind(org_id)
        .fetch_all(pool)
        .await
    }

    pub async fn get_active(pool: &PgPool, org_id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Policy>(
            r#"
            SELECT * FROM policies
            WHERE org_id = $1 AND is_active = true
            ORDER BY version DESC
            LIMIT 1
            "#
        )
        .bind(org_id)
        .fetch_optional(pool)
        .await
    }

    pub async fn update(pool: &PgPool, id: Uuid, data: UpdatePolicy) -> Result<Option<Self>, sqlx::Error> {
        // Get current policy
        let current = Self::find_by_id(pool, id).await?;
        let Some(current) = current else {
            return Ok(None);
        };

        let new_config = data.config
            .map(|c| serde_json::to_value(c).unwrap())
            .unwrap_or(current.config);

        sqlx::query_as::<_, Policy>(
            r#"
            UPDATE policies
            SET name = COALESCE($2, name),
                description = COALESCE($3, description),
                config = $4,
                is_active = COALESCE($5, is_active),
                version = version + 1,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#
        )
        .bind(id)
        .bind(&data.name)
        .bind(&data.description)
        .bind(&new_config)
        .bind(data.is_active)
        .fetch_optional(pool)
        .await
    }
}
