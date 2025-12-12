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

    // Create organization
    let org = Organization::create(
        &state.pool,
        CreateOrganization {
            name: req.organization_name,
            max_agents: Some(10),
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
