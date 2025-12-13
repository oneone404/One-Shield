//! Authentication handlers

use axum::{extract::State, Json};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{Utc, Duration};

use crate::{AppState, AppError, AppResult};
use crate::models::{User, LoginRequest, LoginResponse, CreateUser, Organization, CreateOrganization};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      // User ID
    pub org: String,      // Organization ID
    pub role: String,     // User role
    pub exp: usize,       // Expiration timestamp
    pub iat: usize,       // Issued at
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
    pub organization_name: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub email: String,
}

/// Login endpoint
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    // Find user by email
    let user = User::find_by_email(&state.pool, &req.email)
        .await?
        .ok_or(AppError::InvalidCredentials)?;

    // Verify password
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| AppError::InternalError("Invalid password hash".to_string()))?;

    Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::InvalidCredentials)?;

    // Update last login
    User::update_last_login(&state.pool, user.id).await?;

    // Generate JWT
    let token = generate_jwt(&user, &state.config.jwt_secret, state.config.jwt_expiration_hours)?;

    Ok(Json(LoginResponse {
        token,
        user: user.to_info(),
    }))
}

/// Register new organization and admin user
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> AppResult<Json<RegisterResponse>> {
    // Check if email already exists
    if User::find_by_email(&state.pool, &req.email).await?.is_some() {
        return Err(AppError::AlreadyExists("Email already registered".to_string()));
    }

    // Create organization (defaults to organization tier for dashboard signup)
    let org = Organization::create(
        &state.pool,
        CreateOrganization {
            name: req.organization_name,
            max_agents: Some(10),
            tier: Some("organization".to_string()),
        }
    ).await?;

    // Hash password
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|e| AppError::InternalError(e.to_string()))?
        .to_string();

    // Create admin user
    let user = User::create(
        &state.pool,
        CreateUser {
            org_id: org.id,
            email: req.email.clone(),
            password: req.password,
            name: req.name,
            role: Some("admin".to_string()),
        },
        password_hash
    ).await?;

    tracing::info!("New organization registered: {} ({})", org.name, org.id);

    Ok(Json(RegisterResponse {
        user_id: user.id,
        org_id: org.id,
        email: user.email,
    }))
}

/// Generate JWT token
fn generate_jwt(user: &User, secret: &str, expiration_hours: u64) -> AppResult<String> {
    let now = Utc::now();
    let exp = now + Duration::hours(expiration_hours as i64);

    let claims = Claims {
        sub: user.id.to_string(),
        org: user.org_id.to_string(),
        role: user.role.clone(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes())
    ).map_err(|e| AppError::InternalError(e.to_string()))
}

// ╔══════════════════════════════════════════════════════════════╗
// ║   POST /api/v1/personal/enroll                                ║
// ║   ⚠️ OPINIONATED ENDPOINT - Desktop App Only                  ║
// ║                                                               ║
// ║   This endpoint does multiple things:                         ║
// ║   1. Login (if user exists)                                   ║
// ║   2. Register (if new user)                                   ║
// ║   3. Create personal org                                      ║
// ║   4. Attach agent to org                                      ║
// ║   5. Enforce device limit per tier                            ║
// ║                                                               ║
// ║   DO NOT use for: web signup, mobile, API integrations        ║
// ╚══════════════════════════════════════════════════════════════╝

#[derive(Debug, Deserialize)]
pub struct PersonalEnrollRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
    pub hwid: String,
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub agent_version: String,
}

#[derive(Debug, Serialize)]
pub struct PersonalEnrollResponse {
    // User info
    pub user_id: Uuid,
    pub jwt_token: String,
    // Agent info
    pub agent_id: Uuid,
    pub agent_token: String,
    // Org info
    pub org_id: Uuid,
    pub org_name: String,
    pub tier: String,
    // Status
    pub is_new_user: bool,
}

/// Personal enrollment endpoint for desktop app
/// Handles both login and registration with agent attachment
pub async fn personal_enroll(
    State(state): State<AppState>,
    Json(req): Json<PersonalEnrollRequest>,
) -> AppResult<Json<PersonalEnrollResponse>> {
    use sha2::{Sha256, Digest};

    // Check if user already exists
    if let Some(user) = User::find_by_email(&state.pool, &req.email).await? {
        // ==========================================
        // LOGIN FLOW - Existing user
        // ==========================================

        // Verify password
        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|_| AppError::InternalError("Invalid password hash".to_string()))?;

        Argon2::default()
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .map_err(|_| AppError::InvalidCredentials)?;

        // Get org
        let org = Organization::find_by_id(&state.pool, user.org_id)
            .await?
            .ok_or_else(|| AppError::InternalError("Organization not found".to_string()))?;

        // 🔒 IMPORTANT: Block Organization tier users from using /personal/enroll
        // They MUST use enrollment tokens via /agent/enroll
        if org.is_organization() {
            tracing::warn!(
                "Organization user {} tried to use /personal/enroll (org: {})",
                user.email, org.name
            );
            return Err(AppError::Forbidden);
        }

        // Check device limit
        let device_count = org.count_agents(&state.pool).await?;
        let max_devices = org.max_devices();

        // Check if this HWID already registered
        let existing_agent = find_agent_by_hwid(&state.pool, user.org_id, &req.hwid).await?;

        if existing_agent.is_none() && device_count >= max_devices as i64 {
            return Err(AppError::ValidationError(format!(
                "Device limit reached ({}/{}). Upgrade to add more devices.",
                device_count, max_devices
            )));
        }

        // Register or update agent
        let (agent_id, agent_token) = match existing_agent {
            Some(agent_id) => {
                // Re-generate token for existing agent
                let new_token = Uuid::new_v4().to_string();
                let token_hash = format!("{:x}", Sha256::digest(new_token.as_bytes()));
                update_agent_token(&state.pool, agent_id, &token_hash, &req.hostname).await?;
                (agent_id, new_token)
            }
            None => {
                // Create new agent
                let agent_token = Uuid::new_v4().to_string();
                let token_hash = format!("{:x}", Sha256::digest(agent_token.as_bytes()));
                let agent_id = create_agent(
                    &state.pool,
                    user.org_id,
                    &req.hwid,
                    &req.hostname,
                    &req.os_type,
                    &req.os_version,
                    &req.agent_version,
                    &token_hash
                ).await?;
                (agent_id, agent_token)
            }
        };

        // Update last login
        User::update_last_login(&state.pool, user.id).await?;

        // Generate JWT
        let jwt = generate_jwt(&user, &state.config.jwt_secret, state.config.jwt_expiration_hours)?;

        tracing::info!(
            "Personal login: {} (agent: {}, org: {})",
            user.email, agent_id, org.name
        );

        return Ok(Json(PersonalEnrollResponse {
            user_id: user.id,
            jwt_token: jwt,
            agent_id,
            agent_token,
            org_id: org.id,
            org_name: org.name,
            tier: org.tier.unwrap_or_else(|| "personal_free".to_string()),
            is_new_user: false,
        }));
    }

    // ==========================================
    // REGISTER FLOW - New user
    // ==========================================

    // Create personal org
    let org_name = format!("Personal - {}", &req.email);
    let org = Organization::create(
        &state.pool,
        CreateOrganization {
            name: org_name.clone(),
            max_agents: Some(1),  // Free tier = 1 device
            tier: Some("personal_free".to_string()),
        }
    ).await?;

    // Hash password
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|e| AppError::InternalError(e.to_string()))?
        .to_string();

    // Create admin user
    let user = User::create(
        &state.pool,
        CreateUser {
            org_id: org.id,
            email: req.email.clone(),
            password: req.password.clone(),
            name: req.name.clone(),
            role: Some("admin".to_string()),
        },
        password_hash
    ).await?;

    // Create agent
    let agent_token = Uuid::new_v4().to_string();
    let token_hash = format!("{:x}", Sha256::digest(agent_token.as_bytes()));
    let agent_id = create_agent(
        &state.pool,
        org.id,
        &req.hwid,
        &req.hostname,
        &req.os_type,
        &req.os_version,
        &req.agent_version,
        &token_hash
    ).await?;

    // Generate JWT
    let jwt = generate_jwt(&user, &state.config.jwt_secret, state.config.jwt_expiration_hours)?;

    tracing::info!(
        "Personal signup: {} (agent: {}, org: {})",
        user.email, agent_id, org_name
    );

    Ok(Json(PersonalEnrollResponse {
        user_id: user.id,
        jwt_token: jwt,
        agent_id,
        agent_token,
        org_id: org.id,
        org_name,
        tier: "personal_free".to_string(),
        is_new_user: true,
    }))
}

// Helper: Find agent by HWID in org
async fn find_agent_by_hwid(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    hwid: &str
) -> Result<Option<Uuid>, sqlx::Error> {
    let row = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM endpoints WHERE org_id = $1 AND hwid = $2"
    )
    .bind(org_id)
    .bind(hwid)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

// Helper: Update agent token
async fn update_agent_token(
    pool: &sqlx::PgPool,
    agent_id: Uuid,
    token_hash: &str,
    hostname: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE endpoints
        SET token_hash = $1, hostname = $2, last_seen = NOW()
        WHERE id = $3
        "#
    )
    .bind(token_hash)
    .bind(hostname)
    .bind(agent_id)
    .execute(pool)
    .await?;

    Ok(())
}

// Helper: Create new agent
async fn create_agent(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    hwid: &str,
    hostname: &str,
    os_type: &str,
    os_version: &str,
    agent_version: &str,
    token_hash: &str,
) -> Result<Uuid, sqlx::Error> {
    let id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO endpoints (org_id, hwid, hostname, os_type, os_version, agent_version, token_hash, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'online')
        RETURNING id
        "#
    )
    .bind(org_id)
    .bind(hwid)
    .bind(hostname)
    .bind(os_type)
    .bind(os_version)
    .bind(agent_version)
    .bind(token_hash)
    .fetch_one(pool)
    .await?;

    Ok(id)
}
