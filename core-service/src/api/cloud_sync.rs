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
        Self {
            enabled: std::env::var("CLOUD_SYNC_ENABLED")
                .map(|s| s.to_lowercase() != "false" && s != "0")
                .unwrap_or(true),
            server_url: std::env::var("CLOUD_SERVER_URL")
                .unwrap_or_else(|_| "https://api.accone.vn".to_string()),
            registration_key: std::env::var("CLOUD_REGISTRATION_KEY")
                .unwrap_or_else(|_| "dev-agent-secret-change-in-production-789012".to_string()),
            heartbeat_interval_secs: std::env::var("CLOUD_HEARTBEAT_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
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
        server_url: std::env::var("CLOUD_SERVER_URL")
            .unwrap_or_else(|_| "https://api.accone.vn".to_string()),
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
