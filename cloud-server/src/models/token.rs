//! Organization Token model for enrollment

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Organization Enrollment Token
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct OrganizationToken {
    pub id: Uuid,
    pub org_id: Uuid,
    pub token: String,
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_uses: Option<i32>,
    pub uses_count: i32,
    pub is_active: bool,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Create token request
#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    #[serde(default)]
    pub expires_in_days: Option<i64>,
    #[serde(default)]
    pub max_uses: Option<i32>,
}

/// Token info for API response (hides full token)
#[derive(Debug, Serialize)]
pub struct TokenInfo {
    pub id: Uuid,
    pub name: String,
    pub token_preview: String,
    pub uses_count: i32,
    pub max_uses: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl OrganizationToken {
    /// Generate a new enrollment token
    pub fn generate_token(org_id: Uuid) -> String {
        // Format: ORG_{org_id_first_8_chars}_{random_uuid_first_8_chars}
        let org_prefix = &org_id.to_string()[..8];
        let random_suffix = &Uuid::new_v4().to_string()[..8];
        format!("ORG_{}_{}", org_prefix, random_suffix)
    }

    /// Create a new token
    pub async fn create(
        pool: &PgPool,
        org_id: Uuid,
        created_by: Option<Uuid>,
        req: CreateTokenRequest,
    ) -> Result<Self, sqlx::Error> {
        let token = Self::generate_token(org_id);

        let expires_at = req.expires_in_days.map(|days| {
            Utc::now() + chrono::Duration::days(days)
        });

        let result = sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO organization_tokens (org_id, token, name, expires_at, max_uses, created_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#
        )
        .bind(org_id)
        .bind(&token)
        .bind(&req.name)
        .bind(expires_at)
        .bind(req.max_uses)
        .bind(created_by)
        .fetch_one(pool)
        .await?;

        Ok(result)
    }

    /// List all tokens for an organization
    pub async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            "SELECT * FROM organization_tokens WHERE org_id = $1 ORDER BY created_at DESC"
        )
        .bind(org_id)
        .fetch_all(pool)
        .await
    }

    /// Get token by ID
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>("SELECT * FROM organization_tokens WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    /// Get token by value
    pub async fn get_by_value(pool: &PgPool, token: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>("SELECT * FROM organization_tokens WHERE token = $1")
            .bind(token)
            .fetch_optional(pool)
            .await
    }

    /// Atomic: Try to use the token (race-condition safe)
    /// Returns true if token was successfully used, false if exhausted/expired/revoked
    pub async fn try_use(pool: &PgPool, token_id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE organization_tokens
            SET uses_count = uses_count + 1
            WHERE id = $1
              AND (max_uses IS NULL OR uses_count < max_uses)
              AND is_active = true
              AND (expires_at IS NULL OR expires_at > NOW())
            RETURNING id
            "#
        )
        .bind(token_id)
        .fetch_optional(pool)
        .await?;

        Ok(result.is_some())
    }

    /// Revoke a token
    pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE organization_tokens SET is_active = false, revoked_at = NOW() WHERE id = $1"
        )
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Convert to TokenInfo (hides full token)
    pub fn to_info(&self) -> TokenInfo {
        let token_preview = if self.token.len() > 16 {
            format!("{}...{}", &self.token[..8], &self.token[self.token.len()-4..])
        } else {
            self.token.clone()
        };

        TokenInfo {
            id: self.id,
            name: self.name.clone(),
            token_preview,
            uses_count: self.uses_count,
            max_uses: self.max_uses,
            expires_at: self.expires_at,
            is_active: self.is_active,
            created_at: self.created_at,
        }
    }

    /// Check if token is valid (not expired, not revoked, within limits)
    pub fn is_valid(&self) -> bool {
        if !self.is_active {
            return false;
        }

        if let Some(expires) = self.expires_at {
            if expires < Utc::now() {
                return false;
            }
        }

        if let Some(max) = self.max_uses {
            if self.uses_count >= max {
                return false;
            }
        }

        true
    }
}
