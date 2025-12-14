//! Cloud Sync API Commands
//!
//! Tauri commands for cloud synchronization.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::logic::cloud_sync;

/// Cloud sync status for frontend
#[derive(Debug, Clone, Serialize)]
pub struct CloudSyncStatus {
    pub enabled: bool,
    pub is_connected: bool,
    pub is_registered: bool,
    pub agent_id: Option<String>,
    pub org_id: Option<String>,
    pub server_url: String,
    pub last_heartbeat: Option<String>,
    pub last_sync: Option<String>,
    pub heartbeat_count: u64,
    pub incident_sync_count: u64,
    pub server_version: Option<String>,
    pub errors: Vec<String>,
}

/// Cloud sync configuration for frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSyncConfig {
    pub enabled: bool,
    pub server_url: String,
    pub registration_key: String,
    pub heartbeat_interval_secs: u64,
}

impl Default for CloudSyncConfig {
    fn default() -> Self {
        use crate::constants;

        Self {
            enabled: constants::is_cloud_sync_enabled(),
            server_url: constants::get_cloud_url(),
            registration_key: constants::get_registration_key(),
            heartbeat_interval_secs: constants::get_heartbeat_interval(),
        }
    }
}

/// Get cloud sync status
#[tauri::command]
pub fn get_cloud_sync_status() -> CloudSyncStatus {
    let status = cloud_sync::get_status();

    CloudSyncStatus {
        enabled: true,
        is_connected: status.is_connected,
        is_registered: status.is_registered,
        agent_id: status.agent_id.map(|id| id.to_string()),
        org_id: status.org_id.map(|id| id.to_string()),
        server_url: crate::constants::get_cloud_url(),
        last_heartbeat: status.last_heartbeat.map(|dt| dt.to_rfc3339()),
        last_sync: status.last_sync.map(|dt| dt.to_rfc3339()),
        heartbeat_count: status.heartbeat_count,
        incident_sync_count: status.incident_sync_count,
        server_version: status.server_version,
        errors: status.errors,
    }
}

/// Check if cloud is connected
#[tauri::command]
pub fn is_cloud_connected() -> bool {
    cloud_sync::is_connected()
}

/// Get cloud sync configuration
#[tauri::command]
pub fn get_cloud_sync_config() -> CloudSyncConfig {
    // TODO: Load from persistent storage
    CloudSyncConfig::default()
}

/// Update cloud sync configuration
#[tauri::command]
pub fn update_cloud_sync_config(config: CloudSyncConfig) -> Result<bool, String> {
    // TODO: Save to persistent storage and restart sync loop
    log::info!("Cloud sync config updated: {}", config.server_url);
    Ok(true)
}

/// Queue incident for cloud sync
#[tauri::command]
pub fn queue_incident_for_sync(
    severity: String,
    title: String,
    description: Option<String>,
    mitre_techniques: Option<Vec<String>>,
    threat_class: Option<String>,
    confidence: Option<f32>,
) -> String {
    let id = Uuid::new_v4();

    cloud_sync::sync::queue_incident(
        id,
        severity,
        title,
        description,
        mitre_techniques,
        threat_class,
        confidence,
    );

    id.to_string()
}

/// Get pending incidents count
#[tauri::command]
pub fn get_pending_incidents_count() -> usize {
    cloud_sync::sync::pending_incidents_count()
}

// ==========================================
// Phase 13: Agent Mode & Personal Auth
// ==========================================

/// Agent mode response
#[derive(Debug, Clone, Serialize)]
pub struct AgentModeResponse {
    pub mode: String,
    pub needs_login: bool,
    pub has_identity: bool,
}

/// Get agent operating mode
/// Returns "organization" (has token) or "personal" (needs login)
#[tauri::command]
pub fn get_agent_mode() -> AgentModeResponse {
    let mode = cloud_sync::detect_mode();
    let has_identity = crate::logic::identity::get_identity_manager()
        .read()
        .current()
        .is_some();

    AgentModeResponse {
        mode: mode.as_str().to_string(),
        needs_login: mode == cloud_sync::AgentMode::Personal && !has_identity,
        has_identity,
    }
}

/// Personal enroll request from frontend
#[derive(Debug, Deserialize)]
pub struct PersonalEnrollRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

/// Personal enroll response
#[derive(Debug, Serialize)]
pub struct PersonalEnrollResult {
    pub success: bool,
    pub user_id: Option<String>,
    pub agent_id: Option<String>,
    pub org_name: Option<String>,
    pub tier: Option<String>,
    pub is_new_user: bool,
    pub error: Option<String>,
}

/// Personal enrollment for desktop app
/// Handles login/register + agent attachment
#[tauri::command]
pub async fn personal_enroll(
    email: String,
    password: String,
    name: Option<String>,
) -> PersonalEnrollResult {
    use crate::constants;
    use crate::logic::identity;

    // Get device info
    let hwid = identity::get_hwid();
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let os_version = crate::logic::cloud_sync::client::get_os_version();

    // Build request
    let url = format!("{}/api/v1/personal/enroll", constants::get_cloud_url());

    let request_body = serde_json::json!({
        "email": email,
        "password": password,
        "name": name,
        "hwid": hwid,
        "hostname": hostname,
        "os_type": "Windows",
        "os_version": os_version,
        "agent_version": env!("CARGO_PKG_VERSION"),
    });

    log::info!("Personal enroll: {} (HWID: {}...)", email, &hwid[..8.min(hwid.len())]);

    // Make request
    let client = reqwest::Client::new();
    let response = match client
        .post(&url)
        .json(&request_body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::error!("Personal enroll network error: {}", e);
            return PersonalEnrollResult {
                success: false,
                user_id: None,
                agent_id: None,
                org_name: None,
                tier: None,
                is_new_user: false,
                error: Some(format!("Network error: {}", e)),
            };
        }
    };

    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        log::error!("Personal enroll failed: {} - {}", status, body);
        return PersonalEnrollResult {
            success: false,
            user_id: None,
            agent_id: None,
            org_name: None,
            tier: None,
            is_new_user: false,
            error: Some(format!("Server error: {}", body)),
        };
    }

    // Parse response
    #[derive(Deserialize)]
    struct ServerResponse {
        user_id: uuid::Uuid,
        jwt_token: String,
        agent_id: uuid::Uuid,
        agent_token: String,
        org_id: uuid::Uuid,
        org_name: String,
        tier: String,
        is_new_user: bool,
    }

    let server_response: ServerResponse = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            log::error!("Personal enroll parse error: {}", e);
            return PersonalEnrollResult {
                success: false,
                user_id: None,
                agent_id: None,
                org_name: None,
                tier: None,
                is_new_user: false,
                error: Some(format!("Parse error: {}", e)),
            };
        }
    };

    // Save identity
    {
        let mut identity_mgr = identity::get_identity_manager().write();
        if let Err(e) = identity_mgr.save_identity(
            server_response.agent_id,
            server_response.agent_token.clone(),
            server_response.org_id,
            &constants::get_cloud_url(),
        ) {
            log::error!("Failed to save identity: {}", e);
            return PersonalEnrollResult {
                success: false,
                user_id: None,
                agent_id: None,
                org_name: None,
                tier: None,
                is_new_user: false,
                error: Some(format!("Failed to save identity: {}", e)),
            };
        }
    }

    // Save JWT for dashboard access (optional - store in secure location)
    if let Err(e) = save_user_jwt(&server_response.jwt_token) {
        log::warn!("Failed to save JWT: {}", e);
        // Non-fatal, continue
    }

    log::info!(
        "Personal enroll success: {} → {} ({})",
        email,
        server_response.agent_id,
        if server_response.is_new_user { "new user" } else { "existing user" }
    );

    // Reload cloud client credentials for sync loop
    crate::logic::cloud_sync::sync::reload_credentials();

    PersonalEnrollResult {
        success: true,
        user_id: Some(server_response.user_id.to_string()),
        agent_id: Some(server_response.agent_id.to_string()),
        org_name: Some(server_response.org_name),
        tier: Some(server_response.tier),
        is_new_user: server_response.is_new_user,
        error: None,
    }
}

/// Save user JWT for dashboard access
fn save_user_jwt(jwt: &str) -> Result<(), std::io::Error> {
    let data_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ai-security");

    std::fs::create_dir_all(&data_dir)?;

    let jwt_file = data_dir.join("user_jwt.txt");
    std::fs::write(jwt_file, jwt)?;

    Ok(())
}

/// Check if user has saved JWT
#[tauri::command]
pub fn has_user_jwt() -> bool {
    let data_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ai-security");

    let jwt_file = data_dir.join("user_jwt.txt");
    jwt_file.exists()
}

/// Get saved JWT for dashboard auto-login
#[tauri::command]
pub fn get_user_jwt() -> Option<String> {
    let data_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ai-security");

    let jwt_file = data_dir.join("user_jwt.txt");
    std::fs::read_to_string(jwt_file).ok()
}
