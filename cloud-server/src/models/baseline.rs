//! Baseline model

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Baseline {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub mean_values: serde_json::Value,
    pub variance_values: Option<serde_json::Value>,
    pub sample_count: i64,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct SyncBaselineRequest {
    pub baseline_hash: String,
    pub mean_values: Vec<f32>,
    pub variance_values: Option<Vec<f32>>,
    pub sample_count: u64,
    pub version: i32,
}

#[derive(Debug, Serialize)]
pub struct SyncBaselineResponse {
    pub accepted: bool,
    pub server_version: i32,
    pub server_time: i64,
}

impl Baseline {
    pub async fn upsert(
        pool: &PgPool,
        endpoint_id: Uuid,
        data: SyncBaselineRequest
    ) -> Result<Self, sqlx::Error> {
        let mean_json = serde_json::to_value(&data.mean_values).unwrap();
        let variance_json = data.variance_values.map(|v| serde_json::to_value(v).unwrap());

        sqlx::query_as::<_, Baseline>(
            r#"
            INSERT INTO baselines (endpoint_id, mean_values, variance_values, sample_count, version)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (endpoint_id) DO UPDATE SET
                mean_values = EXCLUDED.mean_values,
                variance_values = EXCLUDED.variance_values,
                sample_count = EXCLUDED.sample_count,
                version = EXCLUDED.version,
                updated_at = NOW()
            RETURNING *
            "#
        )
        .bind(endpoint_id)
        .bind(&mean_json)
        .bind(&variance_json)
        .bind(data.sample_count as i64)
        .bind(data.version)
        .fetch_one(pool)
        .await
    }

    pub async fn find_by_endpoint(pool: &PgPool, endpoint_id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Baseline>("SELECT * FROM baselines WHERE endpoint_id = $1")
            .bind(endpoint_id)
            .fetch_optional(pool)
            .await
    }
}
