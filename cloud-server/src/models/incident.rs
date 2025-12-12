//! Incident model

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Incident {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub mitre_techniques: Option<serde_json::Value>,
    pub threat_class: Option<String>,
    pub confidence: Option<f32>,
    pub status: String,
    pub assigned_to: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateIncident {
    pub id: Uuid,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub mitre_techniques: Option<Vec<String>>,
    pub threat_class: Option<String>,
    pub confidence: Option<f32>,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct SyncIncidentsRequest {
    pub incidents: Vec<CreateIncident>,
}

#[derive(Debug, Serialize)]
pub struct SyncIncidentsResponse {
    pub synced_count: usize,
    pub server_time: i64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIncidentStatus {
    pub status: String,
    pub assigned_to: Option<Uuid>,
}

#[derive(Debug, Deserialize, Default)]
pub struct IncidentFilter {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub endpoint_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Incident {
    pub async fn create(
        pool: &PgPool,
        endpoint_id: Uuid,
        data: CreateIncident
    ) -> Result<Self, sqlx::Error> {
        let mitre_json = data.mitre_techniques
            .map(|v| serde_json::to_value(v).unwrap());

        let created = DateTime::from_timestamp(data.created_at, 0)
            .unwrap_or_else(Utc::now);

        sqlx::query_as::<_, Incident>(
            r#"
            INSERT INTO incidents (id, endpoint_id, severity, title, description, mitre_techniques, threat_class, confidence, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (id) DO UPDATE SET
                severity = EXCLUDED.severity,
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                updated_at = NOW()
            RETURNING *
            "#
        )
        .bind(data.id)
        .bind(endpoint_id)
        .bind(&data.severity)
        .bind(&data.title)
        .bind(&data.description)
        .bind(&mitre_json)
        .bind(&data.threat_class)
        .bind(data.confidence)
        .bind(created)
        .fetch_one(pool)
        .await
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Incident>("SELECT * FROM incidents WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    pub async fn list_by_org(
        pool: &PgPool,
        org_id: Uuid,
        filter: IncidentFilter
    ) -> Result<Vec<Self>, sqlx::Error> {
        let limit = filter.limit.unwrap_or(50);
        let offset = filter.offset.unwrap_or(0);

        // Simple query without complex filtering for now
        sqlx::query_as::<_, Incident>(
            r#"
            SELECT i.* FROM incidents i
            JOIN endpoints e ON i.endpoint_id = e.id
            WHERE e.org_id = $1
            ORDER BY i.created_at DESC
            LIMIT $2 OFFSET $3
            "#
        )
        .bind(org_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    pub async fn update_status(
        pool: &PgPool,
        id: Uuid,
        status: &str,
        assigned_to: Option<Uuid>
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Incident>(
            r#"
            UPDATE incidents
            SET status = $2, assigned_to = $3, updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#
        )
        .bind(id)
        .bind(status)
        .bind(assigned_to)
        .fetch_optional(pool)
        .await
    }

    pub async fn count_by_severity(pool: &PgPool, org_id: Uuid) -> Result<Vec<(String, i64)>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT i.severity, COUNT(*) as count
            FROM incidents i
            JOIN endpoints e ON i.endpoint_id = e.id
            WHERE e.org_id = $1 AND i.status = 'open'
            GROUP BY i.severity
            "#
        )
        .bind(org_id)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|r| {
            (r.get::<String, _>("severity"), r.get::<i64, _>("count"))
        }).collect())
    }
}
