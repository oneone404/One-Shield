//! Role-Based Access Control Module (Phase 6)
//!
//! Mục đích: Quản lý users và permissions
//!
//! Features:
//! - User management
//! - Session management
//! - Permission checking

use std::collections::HashMap;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use chrono::Utc;
use uuid::Uuid;
use sha2::{Sha256, Digest};

use super::types::{User, UserRole, Session, Permission, Resource, Action};

// ============================================================================
// CONSTANTS
// ============================================================================

const SESSION_DURATION_HOURS: i64 = 24;
const MAX_SESSIONS_PER_USER: usize = 5;
const MIN_PASSWORD_LENGTH: usize = 8;

// ============================================================================
// STATE
// ============================================================================

static RBAC_MANAGER: Lazy<RwLock<RbacManager>> =
    Lazy::new(|| RwLock::new(RbacManager::new()));

// ============================================================================
// RBAC MANAGER
// ============================================================================

pub struct RbacManager {
    users: HashMap<String, UserRecord>,
    sessions: HashMap<String, Session>,
    api_keys: HashMap<String, String>,  // api_key -> user_id
}

struct UserRecord {
    user: User,
    password_hash: String,
    salt: String,
}

impl RbacManager {
    pub fn new() -> Self {
        let mut manager = Self {
            users: HashMap::new(),
            sessions: HashMap::new(),
            api_keys: HashMap::new(),
        };

        // TODO: SECURITY - Remove hardcoded default password in production!
        // Default admin user for development/testing only
        // In production, this should be configured via environment variable or first-run setup
        let _ = manager.create_user("admin", "admin@localhost", "admin123", UserRole::Admin);
        log::warn!("⚠️  Default admin user created with temporary password. Change immediately in production!");

        manager
    }

    /// Create a new user
    pub fn create_user(&mut self, username: &str, email: &str, password: &str, role: UserRole)
        -> Result<User, RbacError>
    {
        // Validate
        if username.is_empty() {
            return Err(RbacError::InvalidInput("Username cannot be empty".to_string()));
        }
        if password.len() < MIN_PASSWORD_LENGTH {
            return Err(RbacError::InvalidInput(format!(
                "Password must be at least {} characters", MIN_PASSWORD_LENGTH
            )));
        }

        // Check uniqueness
        if self.users.values().any(|r| r.user.username == username) {
            return Err(RbacError::AlreadyExists("Username already exists".to_string()));
        }

        let id = Uuid::new_v4().to_string();
        let salt = Uuid::new_v4().to_string();
        let password_hash = hash_password(password, &salt);

        let user = User {
            id: id.clone(),
            username: username.to_string(),
            email: Some(email.to_string()),
            role,
            permissions: role.default_permissions(),
            created_at: Utc::now().timestamp(),
            last_login: None,
            enabled: true,
            api_key: None,
            mfa_enabled: false,
        };

        self.users.insert(id.clone(), UserRecord {
            user: user.clone(),
            password_hash,
            salt,
        });

        log::info!("Created user: {} ({})", username, role.as_str());
        Ok(user)
    }

    /// Authenticate user with username and password
    pub fn authenticate(&mut self, username: &str, password: &str)
        -> Result<Session, RbacError>
    {
        // Find user and verify credentials
        let user_id = {
            let record = self.users.values_mut()
                .find(|r| r.user.username == username)
                .ok_or(RbacError::InvalidCredentials)?;

            if !record.user.enabled {
                return Err(RbacError::UserDisabled);
            }

            let hash = hash_password(password, &record.salt);
            if hash != record.password_hash {
                return Err(RbacError::InvalidCredentials);
            }

            // Update last login
            record.user.last_login = Some(Utc::now().timestamp());
            record.user.id.clone()
        };

        // Create session
        let session = self.create_session_for_user(&user_id)?;

        log::info!("User authenticated: {}", username);
        Ok(session)
    }

    /// Authenticate with API key
    pub fn authenticate_api_key(&self, api_key: &str) -> Result<User, RbacError> {
        let user_id = self.api_keys.get(api_key)
            .ok_or(RbacError::InvalidCredentials)?;

        let record = self.users.get(user_id)
            .ok_or(RbacError::UserNotFound)?;

        if !record.user.enabled {
            return Err(RbacError::UserDisabled);
        }

        Ok(record.user.clone())
    }

    /// Create a session for a user
    fn create_session_for_user(&mut self, user_id: &str) -> Result<Session, RbacError> {
        // Clean up old sessions
        self.cleanup_user_sessions(user_id);

        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            token: generate_token(),
            created_at: Utc::now().timestamp(),
            expires_at: Utc::now().timestamp() + (SESSION_DURATION_HOURS * 3600),
            ip_address: None,
            user_agent: None,
        };

        self.sessions.insert(session.token.clone(), session.clone());
        Ok(session)
    }

    /// Clean up old sessions for a user
    fn cleanup_user_sessions(&mut self, user_id: &str) {
        // Remove expired sessions
        self.sessions.retain(|_, s| !s.is_expired());

        // Check session limit
        let user_sessions: Vec<_> = self.sessions.iter()
            .filter(|(_, s)| s.user_id == user_id)
            .map(|(k, s)| (k.clone(), s.created_at))
            .collect();

        if user_sessions.len() >= MAX_SESSIONS_PER_USER {
            // Remove oldest
            let mut sorted = user_sessions;
            sorted.sort_by(|a, b| a.1.cmp(&b.1));

            let to_remove = sorted.len().saturating_sub(MAX_SESSIONS_PER_USER - 1);
            for (token, _) in sorted.into_iter().take(to_remove) {
                self.sessions.remove(&token);
            }
        }
    }

    /// Validate a session token
    pub fn validate_session(&self, token: &str) -> Result<User, RbacError> {
        let session = self.sessions.get(token)
            .ok_or(RbacError::InvalidSession)?;

        if session.is_expired() {
            return Err(RbacError::SessionExpired);
        }

        let record = self.users.get(&session.user_id)
            .ok_or(RbacError::UserNotFound)?;

        if !record.user.enabled {
            return Err(RbacError::UserDisabled);
        }

        Ok(record.user.clone())
    }

    /// Check if user has permission
    pub fn authorize(&self, user_id: &str, resource: Resource, action: Action) -> bool {
        if let Some(record) = self.users.get(user_id) {
            return record.user.has_permission(resource, action);
        }
        false
    }

    /// Get user by ID
    pub fn get_user(&self, user_id: &str) -> Option<User> {
        self.users.get(user_id).map(|r| r.user.clone())
    }

    /// Get user by username
    pub fn get_user_by_username(&self, username: &str) -> Option<User> {
        self.users.values()
            .find(|r| r.user.username == username)
            .map(|r| r.user.clone())
    }

    /// List all users
    pub fn list_users(&self) -> Vec<User> {
        self.users.values().map(|r| r.user.clone()).collect()
    }

    /// Update user role
    pub fn update_role(&mut self, user_id: &str, role: UserRole) -> Result<(), RbacError> {
        let record = self.users.get_mut(user_id)
            .ok_or(RbacError::UserNotFound)?;

        record.user.role = role;
        record.user.permissions = role.default_permissions();

        log::info!("Updated user {} role to {}", record.user.username, role.as_str());
        Ok(())
    }

    /// Enable/disable user
    pub fn set_enabled(&mut self, user_id: &str, enabled: bool) -> Result<(), RbacError> {
        let record = self.users.get_mut(user_id)
            .ok_or(RbacError::UserNotFound)?;

        record.user.enabled = enabled;

        if !enabled {
            // Revoke all sessions
            self.sessions.retain(|_, s| s.user_id != user_id);
        }

        log::info!("User {} {}", record.user.username, if enabled { "enabled" } else { "disabled" });
        Ok(())
    }

    /// Generate API key for user
    pub fn generate_api_key(&mut self, user_id: &str) -> Result<String, RbacError> {
        let record = self.users.get_mut(user_id)
            .ok_or(RbacError::UserNotFound)?;

        // Revoke old key
        if let Some(old_key) = &record.user.api_key {
            self.api_keys.remove(old_key);
        }

        let api_key = format!("os_{}_{}", user_id[..8].to_string(), generate_token()[..24].to_string());
        record.user.api_key = Some(api_key.clone());
        self.api_keys.insert(api_key.clone(), user_id.to_string());

        log::info!("Generated API key for user {}", record.user.username);
        Ok(api_key)
    }

    /// Revoke session
    pub fn revoke_session(&mut self, token: &str) {
        self.sessions.remove(token);
    }

    /// Revoke all sessions for user
    pub fn revoke_all_sessions(&mut self, user_id: &str) {
        self.sessions.retain(|_, s| s.user_id != user_id);
    }

    /// Delete user
    pub fn delete_user(&mut self, user_id: &str) -> Result<(), RbacError> {
        let record = self.users.remove(user_id)
            .ok_or(RbacError::UserNotFound)?;

        // Revoke sessions and API key
        self.sessions.retain(|_, s| s.user_id != user_id);
        if let Some(api_key) = &record.user.api_key {
            self.api_keys.remove(api_key);
        }

        log::info!("Deleted user: {}", record.user.username);
        Ok(())
    }

    /// Get stats
    pub fn stats(&self) -> RbacStats {
        let now = Utc::now().timestamp();

        RbacStats {
            total_users: self.users.len(),
            enabled_users: self.users.values().filter(|r| r.user.enabled).count(),
            active_sessions: self.sessions.values().filter(|s| !s.is_expired()).count(),
            by_role: self.users.values()
                .fold(HashMap::new(), |mut acc, r| {
                    *acc.entry(r.user.role.as_str().to_string()).or_insert(0) += 1;
                    acc
                }),
        }
    }
}

impl Default for RbacManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum RbacError {
    InvalidCredentials,
    InvalidSession,
    SessionExpired,
    UserNotFound,
    UserDisabled,
    AlreadyExists(String),
    InvalidInput(String),
    PermissionDenied,
}

impl std::fmt::Display for RbacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RbacError::InvalidCredentials => write!(f, "Invalid credentials"),
            RbacError::InvalidSession => write!(f, "Invalid session"),
            RbacError::SessionExpired => write!(f, "Session expired"),
            RbacError::UserNotFound => write!(f, "User not found"),
            RbacError::UserDisabled => write!(f, "User is disabled"),
            RbacError::AlreadyExists(msg) => write!(f, "Already exists: {}", msg),
            RbacError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            RbacError::PermissionDenied => write!(f, "Permission denied"),
        }
    }
}

impl std::error::Error for RbacError {}

// ============================================================================
// UTILITIES
// ============================================================================

fn hash_password(password: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", password, salt));
    format!("{:x}", hasher.finalize())
}

fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..64)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            chars[idx] as char
        })
        .collect()
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Create a new user
pub fn create_user(username: &str, email: &str, password: &str, role: UserRole)
    -> Result<User, RbacError>
{
    RBAC_MANAGER.write().create_user(username, email, password, role)
}

/// Authenticate with username/password
pub fn authenticate(username: &str, password: &str) -> Result<Session, RbacError> {
    RBAC_MANAGER.write().authenticate(username, password)
}

/// Authenticate with API key
pub fn authenticate_api_key(api_key: &str) -> Result<User, RbacError> {
    RBAC_MANAGER.read().authenticate_api_key(api_key)
}

/// Validate session token
pub fn validate_session(token: &str) -> Result<User, RbacError> {
    RBAC_MANAGER.read().validate_session(token)
}

/// Create session (internal use)
pub fn create_session(user_id: &str) -> Result<Session, RbacError> {
    RBAC_MANAGER.write().create_session_for_user(user_id)
}

/// Check authorization
pub fn authorize(user_id: &str, resource: Resource, action: Action) -> bool {
    RBAC_MANAGER.read().authorize(user_id, resource, action)
}

/// Check if user has permission
pub fn has_permission(user_id: &str, resource: Resource, action: Action) -> bool {
    authorize(user_id, resource, action)
}

/// Get user permissions
pub fn get_user_permissions(user_id: &str) -> Vec<Permission> {
    RBAC_MANAGER.read()
        .get_user(user_id)
        .map(|u| u.permissions)
        .unwrap_or_default()
}

/// Get user by ID
pub fn get_user(user_id: &str) -> Option<User> {
    RBAC_MANAGER.read().get_user(user_id)
}

/// List all users
pub fn list_users() -> Vec<User> {
    RBAC_MANAGER.read().list_users()
}

/// Revoke session
pub fn revoke_session(token: &str) {
    RBAC_MANAGER.write().revoke_session(token);
}

/// Get stats
pub fn get_stats() -> RbacStats {
    RBAC_MANAGER.read().stats()
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct RbacStats {
    pub total_users: usize,
    pub enabled_users: usize,
    pub active_sessions: usize,
    pub by_role: HashMap<String, usize>,
}
