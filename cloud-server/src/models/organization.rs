//! Organization model

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Row};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Organization tier - determines feature access
/// Note: Only 3 tiers, NOT tách Enterprise (Phase 13 decision)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum OrgTier {
    /// Free personal tier - 1 device
    PersonalFree,
    /// Pro personal tier - 10 devices, $9/mo
    PersonalPro,
    /// Organization tier - unlimited, enterprise features
    Organization,
}

impl OrgTier {
    /// Parse tier string from database
    pub fn from_str(s: &str) -> Self {
        match s {
            "personal_free" => OrgTier::PersonalFree,
            "personal_pro" => OrgTier::PersonalPro,
            // "enterprise" mapped to Organization for backwards compat
            "organization" | "enterprise" => OrgTier::Organization,
            _ => OrgTier::PersonalFree,
        }
    }

    /// Convert to database string
    pub fn as_str(&self) -> &'static str {
        match self {
            OrgTier::PersonalFree => "personal_free",
            OrgTier::PersonalPro => "personal_pro",
            OrgTier::Organization => "organization",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub license_key: Option<String>,
    pub max_agents: i32,
    /// Tier: personal_free, personal_pro, organization
    pub tier: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrganization {
    pub name: String,
    pub max_agents: Option<i32>,
    pub tier: Option<String>,
}

impl Organization {
    pub async fn create(pool: &PgPool, data: CreateOrganization) -> Result<Self, sqlx::Error> {
        let license_key = format!("OS-{}", Uuid::new_v4().to_string().split('-').next().unwrap().to_uppercase());
        let tier = data.tier.unwrap_or_else(|| "personal_free".to_string());

        sqlx::query_as::<_, Organization>(
            r#"
            INSERT INTO organizations (name, license_key, max_agents, tier)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, license_key, max_agents, tier, created_at, updated_at
            "#
        )
        .bind(&data.name)
        .bind(&license_key)
        .bind(data.max_agents.unwrap_or(10))
        .bind(&tier)
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

    // ==========================================
    // Tier-based feature checks (Phase 13)
    // ==========================================

    /// Get organization tier
    pub fn get_tier(&self) -> OrgTier {
        OrgTier::from_str(self.tier.as_deref().unwrap_or("personal_free"))
    }

    /// Check if personal tier (Free or Pro)
    pub fn is_personal(&self) -> bool {
        matches!(self.get_tier(), OrgTier::PersonalFree | OrgTier::PersonalPro)
    }

    /// Check if organization tier (enterprise features)
    pub fn is_organization(&self) -> bool {
        self.get_tier() == OrgTier::Organization
    }

    /// Only Organization tier can create enrollment tokens
    pub fn can_create_tokens(&self) -> bool {
        self.is_organization()
    }

    /// Get max devices allowed for this tier
    pub fn max_devices(&self) -> i32 {
        match self.get_tier() {
            OrgTier::PersonalFree => 1,
            OrgTier::PersonalPro => 10,
            OrgTier::Organization => self.max_agents,
        }
    }

    /// Check if can add more devices
    pub async fn can_add_device(&self, pool: &PgPool) -> Result<bool, sqlx::Error> {
        let current = self.count_agents(pool).await?;
        Ok(current < self.max_devices() as i64)
    }
}
