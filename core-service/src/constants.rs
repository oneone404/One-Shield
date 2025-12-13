//! Central Configuration Constants
//!
//! Single source of truth for all configuration defaults.
//! To change default API server, only edit this file.

/// Default Cloud Server URL
///
/// This is the fallback URL when no environment variable is set.
/// For development: http://localhost:8080
/// For production: https://api.accone.vn
pub const DEFAULT_CLOUD_URL: &str = "https://api.accone.vn";

/// Default registration key
pub const DEFAULT_REGISTRATION_KEY: &str = "dev-agent-secret-change-in-production-789012";

/// Default heartbeat interval (seconds)
pub const DEFAULT_HEARTBEAT_INTERVAL: u64 = 30;

/// Default incident sync interval (seconds)
pub const DEFAULT_INCIDENT_SYNC_INTERVAL: u64 = 60;

/// App version
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// App name
pub const APP_NAME: &str = "One-Shield";

// ============================================
// Helper functions to read from env with fallback
// ============================================

/// Get cloud server URL from environment or use default
pub fn get_cloud_url() -> String {
    std::env::var("CLOUD_SERVER_URL")
        .unwrap_or_else(|_| DEFAULT_CLOUD_URL.to_string())
}

/// Get registration key from environment or use default
pub fn get_registration_key() -> String {
    std::env::var("CLOUD_REGISTRATION_KEY")
        .unwrap_or_else(|_| DEFAULT_REGISTRATION_KEY.to_string())
}

/// Get heartbeat interval from environment or use default
pub fn get_heartbeat_interval() -> u64 {
    std::env::var("CLOUD_HEARTBEAT_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL)
}

/// Get incident sync interval from environment or use default
pub fn get_incident_sync_interval() -> u64 {
    std::env::var("CLOUD_INCIDENT_SYNC_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_INCIDENT_SYNC_INTERVAL)
}

/// Check if cloud sync is enabled
pub fn is_cloud_sync_enabled() -> bool {
    std::env::var("CLOUD_SYNC_ENABLED")
        .map(|s| s.to_lowercase() != "false" && s != "0")
        .unwrap_or(true)
}
