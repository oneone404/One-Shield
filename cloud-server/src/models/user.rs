//! User model

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub org_id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub name: Option<String>,
    pub role: String,
    pub is_active: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    Analyst,
    Viewer,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Analyst => "analyst",
            Self::Viewer => "viewer",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub org_id: Uuid,
    pub email: String,
    pub password: String,
    pub name: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub role: String,
    pub org_id: Uuid,
}

impl User {
    pub async fn create(pool: &PgPool, data: CreateUser, password_hash: String) -> Result<Self, sqlx::Error> {
        sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (org_id, email, password_hash, name, role)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#
        )
        .bind(data.org_id)
        .bind(&data.email)
        .bind(&password_hash)
        .bind(&data.name)
        .bind(data.role.unwrap_or_else(|| "viewer".to_string()))
        .fetch_one(pool)
        .await
    }

    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1 AND is_active = true")
            .bind(email)
            .fetch_optional(pool)
            .await
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    pub async fn update_last_login(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET last_login = NOW() WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub fn to_info(&self) -> UserInfo {
        UserInfo {
            id: self.id,
            email: self.email.clone(),
            name: self.name.clone(),
            role: self.role.clone(),
            org_id: self.org_id,
        }
    }
}
