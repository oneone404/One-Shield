//! Organization model

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub license_key: Option<String>,
    pub max_agents: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrganization {
    pub name: String,
    pub max_agents: Option<i32>,
}

impl Organization {
    pub async fn create(pool: &PgPool, data: CreateOrganization) -> Result<Self, sqlx::Error> {
        let license_key = format!("OS-{}", Uuid::new_v4().to_string().split('-').next().unwrap().to_uppercase());

        sqlx::query_as::<_, Organization>(
            r#"
            INSERT INTO organizations (name, license_key, max_agents)
            VALUES ($1, $2, $3)
            RETURNING id, name, license_key, max_agents, created_at, updated_at
            "#
        )
        .bind(&data.name)
        .bind(&license_key)
        .bind(data.max_agents.unwrap_or(10))
        .fetch_one(pool)
        .await
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    pub async fn count_agents(&self, pool: &PgPool) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM endpoints WHERE org_id = $1")
            .bind(self.id)
            .fetch_one(pool)
            .await?;

        Ok(row.get::<i64, _>("count"))
    }
}
