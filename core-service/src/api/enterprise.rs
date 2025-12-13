//! Enterprise API Commands (Phase 7: UI Integration)
//!
//! Tauri commands để expose Enterprise Features cho Frontend:
//! - RBAC (Users, Roles, Sessions)
//! - Policy Management
//! - File Quarantine
//! - Webhook Alerts
//! - Executive Reports

use serde::{Deserialize, Serialize};
use crate::logic::enterprise::{rbac, policy_sync, reporting};
use crate::logic::response::{file_quarantine, webhook};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// User info for frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub created_at: String,
    pub is_active: bool,
}

/// Session info for frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub token: String,
    pub user_id: String,
    pub created_at: String,
    pub expires_at: String,
}

/// Policy info for frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInfo {
    pub id: String,
    pub name: String,
    pub version: u32,
    pub enabled: bool,
    pub description: String,
    pub rules_count: usize,
}

/// Quarantine entry for frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntryInfo {
    pub id: String,
    pub original_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub sha256: String,
    pub reason: String,
    pub quarantined_at: String,
    pub can_restore: bool,
}

/// Webhook config for frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookInfo {
    pub name: String,
    pub url: String,
    pub platform: String,
    pub enabled: bool,
}

/// Executive report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveReportInfo {
    pub security_score: f32,
    pub risk_level: String,
    pub total_incidents: u64,
    pub critical_incidents: u64,
    pub high_incidents: u64,
    pub medium_incidents: u64,
    pub low_incidents: u64,
    pub endpoints_protected: u64,
    pub threats_blocked: u64,
    pub key_findings: Vec<String>,
    pub recommendations: Vec<String>,
    pub generated_at: String,
}

// ============================================================================
// AUTHENTICATION COMMANDS
// ============================================================================

/// Login và nhận session token
#[tauri::command]
pub async fn enterprise_login(username: String, password: String) -> Result<SessionInfo, String> {
    match rbac::authenticate(&username, &password) {
        Ok(session) => Ok(SessionInfo {
            token: session.token.clone(),
            user_id: session.user_id.clone(),
            created_at: chrono::DateTime::from_timestamp(session.created_at, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default(),
            expires_at: chrono::DateTime::from_timestamp(session.expires_at, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default(),
        }),
        Err(e) => Err(format!("Login failed: {:?}", e)),
    }
}

/// Logout và invalidate session
#[tauri::command]
pub async fn enterprise_logout(token: String) -> Result<bool, String> {
    rbac::revoke_session(&token);
    Ok(true)
}

/// Validate session token
#[tauri::command]
pub async fn validate_session(token: String) -> Result<bool, String> {
    Ok(rbac::validate_session(&token).is_ok())
}

/// Get current user from session
#[tauri::command]
pub async fn get_current_user(token: String) -> Result<Option<UserInfo>, String> {
    match rbac::validate_session(&token) {
        Ok(user) => Ok(Some(UserInfo {
            id: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone().unwrap_or_default(),
            role: format!("{:?}", user.role),
            created_at: chrono::DateTime::from_timestamp(user.created_at, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default(),
            is_active: user.enabled,
        })),
        Err(_) => Ok(None),
    }
}

// ============================================================================
// USER MANAGEMENT COMMANDS
// ============================================================================

/// Get all users (Admin only)
#[tauri::command]
pub async fn get_users() -> Result<Vec<UserInfo>, String> {
    let users = rbac::list_users();

    Ok(users.iter().map(|user| UserInfo {
        id: user.id.clone(),
        username: user.username.clone(),
        email: user.email.clone().unwrap_or_default(),
        role: format!("{:?}", user.role),
        created_at: chrono::DateTime::from_timestamp(user.created_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default(),
        is_active: user.enabled,
    }).collect())
}

/// Create new user (Admin only)
#[tauri::command]
pub async fn create_user(
    username: String,
    email: String,
    password: String,
    role: String,
) -> Result<UserInfo, String> {
    let user_role = match role.to_lowercase().as_str() {
        "admin" => crate::logic::enterprise::types::UserRole::Admin,
        "analyst" => crate::logic::enterprise::types::UserRole::Analyst,
        "viewer" => crate::logic::enterprise::types::UserRole::Viewer,
        "apiclient" => crate::logic::enterprise::types::UserRole::ApiClient,
        _ => return Err("Invalid role".to_string()),
    };

    match rbac::create_user(&username, &email, &password, user_role) {
        Ok(user) => Ok(UserInfo {
            id: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone().unwrap_or_default(),
            role: format!("{:?}", user.role),
            created_at: chrono::DateTime::from_timestamp(user.created_at, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default(),
            is_active: user.enabled,
        }),
        Err(e) => Err(format!("Failed to create user: {:?}", e)),
    }
}

/// Get RBAC statistics
#[tauri::command]
pub async fn get_rbac_stats() -> Result<serde_json::Value, String> {
    let stats = rbac::get_stats();
    Ok(serde_json::json!({
        "total_users": stats.total_users,
        "active_sessions": stats.active_sessions,
    }))
}

// ============================================================================
// POLICY MANAGEMENT COMMANDS
// ============================================================================

/// Get all policies
#[tauri::command]
pub async fn get_policies() -> Result<Vec<PolicyInfo>, String> {
    let policies = policy_sync::get_active_policies();

    Ok(policies.iter().map(|p| PolicyInfo {
        id: p.id.clone(),
        name: p.name.clone(),
        version: p.version,
        enabled: p.enabled,
        description: p.description.clone(),
        rules_count: p.rules.len(),
    }).collect())
}

/// Get policy by ID
#[tauri::command]
pub async fn get_policy(policy_id: String) -> Result<Option<serde_json::Value>, String> {
    match policy_sync::get_policy(&policy_id) {
        Some(policy) => Ok(Some(serde_json::json!({
            "id": policy.id,
            "name": policy.name,
            "version": policy.version,
            "enabled": policy.enabled,
            "description": policy.description,
            "rules": policy.rules.len(),
        }))),
        None => Ok(None),
    }
}

/// Sync policies from server
#[tauri::command]
pub async fn sync_policies() -> Result<serde_json::Value, String> {
    match policy_sync::sync_policies() {
        Ok(result) => Ok(serde_json::json!({
            "success": true,
            "added": result.added,
            "updated": result.updated,
            "synced_at": chrono::Utc::now().to_rfc3339(),
        })),
        Err(e) => Err(format!("Sync failed: {:?}", e)),
    }
}

/// Get policy sync status
#[tauri::command]
pub async fn get_policy_sync_status() -> Result<serde_json::Value, String> {
    let stats = policy_sync::get_stats();

    Ok(serde_json::json!({
        "total_policies": stats.total_policies,
        "enabled_policies": stats.enabled_policies,
        "last_sync": stats.last_sync.map(|t|
            chrono::DateTime::from_timestamp(t, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default()
        ),
    }))
}

// ============================================================================
// FILE QUARANTINE COMMANDS
// ============================================================================

/// Get all quarantined files
#[tauri::command]
pub async fn get_quarantined_files() -> Result<Vec<QuarantineEntryInfo>, String> {
    let entries = file_quarantine::get_quarantine_list();

    Ok(entries.iter().map(|e| QuarantineEntryInfo {
        id: e.id.clone(),
        original_path: e.original_path.to_string_lossy().to_string(),
        file_name: e.file_name.clone(),
        file_size: e.file_size,
        sha256: e.sha256.clone(),
        reason: e.reason.clone(),
        quarantined_at: chrono::DateTime::from_timestamp(e.quarantine_time, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default(),
        can_restore: e.can_restore,
    }).collect())
}

/// Quarantine a file
#[tauri::command]
pub async fn quarantine_file(file_path: String, reason: String) -> Result<serde_json::Value, String> {
    let path = std::path::Path::new(&file_path);

    match file_quarantine::quarantine_file(path, &reason, None) {
        Ok(entry) => Ok(serde_json::json!({
            "success": true,
            "id": entry.id,
            "sha256": entry.sha256,
            "message": format!("File quarantined: {}", file_path),
        })),
        Err(e) => Err(format!("Quarantine failed: {:?}", e)),
    }
}

/// Restore a quarantined file
#[tauri::command]
pub async fn restore_quarantined_file(entry_id: String) -> Result<serde_json::Value, String> {
    match file_quarantine::restore_file(&entry_id) {
        Ok(path) => Ok(serde_json::json!({
            "success": true,
            "restored_to": path.to_string_lossy().to_string(),
            "message": "File restored successfully",
        })),
        Err(e) => Err(format!("Restore failed: {:?}", e)),
    }
}

/// Delete a quarantined file permanently
#[tauri::command]
pub async fn delete_quarantined_file(entry_id: String) -> Result<bool, String> {
    file_quarantine::delete_quarantined(&entry_id)
        .map_err(|e| format!("Delete failed: {:?}", e))?;
    Ok(true)
}

/// Get quarantine statistics
#[tauri::command]
pub async fn get_quarantine_stats() -> Result<serde_json::Value, String> {
    let stats = file_quarantine::get_stats();

    Ok(serde_json::json!({
        "total_files": stats.total_files,
        "oldest_entry": stats.oldest_entry.map(|t|
            chrono::DateTime::from_timestamp(t, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default()
        ),
    }))
}

// ============================================================================
// WEBHOOK COMMANDS
// ============================================================================

/// Get all webhooks
#[tauri::command]
pub async fn get_webhooks() -> Result<Vec<WebhookInfo>, String> {
    let webhooks = webhook::get_webhooks();

    Ok(webhooks.iter().map(|w| WebhookInfo {
        name: w.name.clone(),
        url: mask_url(&w.url),  // Mask sensitive URL parts
        platform: format!("{:?}", w.platform),
        enabled: w.enabled,
    }).collect())
}

/// Add a webhook
#[tauri::command]
pub async fn add_webhook(
    name: String,
    url: String,
    platform: String,
) -> Result<bool, String> {
    use crate::logic::response::types::{WebhookConfig, WebhookPlatform, AlertSeverity};

    let webhook_platform = match platform.to_lowercase().as_str() {
        "slack" => WebhookPlatform::Slack,
        "discord" => WebhookPlatform::Discord,
        "telegram" => WebhookPlatform::Telegram,
        "teams" => WebhookPlatform::MicrosoftTeams,
        _ => WebhookPlatform::Generic,
    };

    let config = WebhookConfig {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        url,
        platform: webhook_platform,
        enabled: true,
        min_severity: AlertSeverity::Medium,
        include_details: true,
        created_at: chrono::Utc::now().timestamp(),
    };

    webhook::add_webhook(config);
    Ok(true)
}

/// Remove a webhook
#[tauri::command]
pub async fn remove_webhook(name: String) -> Result<bool, String> {
    webhook::remove_webhook(&name);
    Ok(true)
}

/// Test webhook (send test message)
#[tauri::command]
pub async fn test_webhook(name: String) -> Result<serde_json::Value, String> {
    match webhook::test_webhook(&name) {
        Ok(_) => Ok(serde_json::json!({
            "success": true,
            "message": "Test message sent successfully",
        })),
        Err(e) => Err(format!("Webhook test failed: {:?}", e)),
    }
}

// ============================================================================
// REPORTING COMMANDS
// ============================================================================

/// Get executive report
#[tauri::command]
pub async fn get_executive_report() -> Result<ExecutiveReportInfo, String> {
    let report = reporting::generate_executive_report();

    Ok(ExecutiveReportInfo {
        security_score: report.security_score,
        risk_level: report.risk_level.clone(),
        total_incidents: report.total_incidents,
        critical_incidents: report.critical_incidents,
        high_incidents: report.high_incidents,
        medium_incidents: report.medium_incidents,
        low_incidents: report.low_incidents,
        endpoints_protected: report.endpoints_protected,
        threats_blocked: report.threats_blocked,
        key_findings: report.key_findings.clone(),
        recommendations: report.recommendations.clone(),
        generated_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// Get incident summary for a period
#[tauri::command]
pub async fn get_incident_summary(period: String) -> Result<serde_json::Value, String> {
    let report_period = match period.to_lowercase().as_str() {
        "daily" => crate::logic::enterprise::types::ReportPeriod::Daily,
        "weekly" => crate::logic::enterprise::types::ReportPeriod::Weekly,
        "monthly" => crate::logic::enterprise::types::ReportPeriod::Monthly,
        _ => crate::logic::enterprise::types::ReportPeriod::Daily,
    };

    let summary = reporting::get_incident_summary(report_period);

    Ok(serde_json::json!({
        "period": period,
        "total_incidents": summary.total,
        "by_severity": {
            "critical": summary.critical,
            "high": summary.high,
            "medium": summary.medium,
            "low": summary.low,
        },
        "trend": format!("{:?}", summary.trend.direction),
        "trend_percent": summary.trend.percentage_change,
        "top_threats": summary.top_threats,
    }))
}

/// Get endpoint statistics
#[tauri::command]
pub async fn get_endpoint_stats() -> Result<serde_json::Value, String> {
    let stats = reporting::get_endpoint_stats_ui();

    Ok(serde_json::json!({
        "total_endpoints": stats.total,
        "online": stats.online,
        "offline": stats.offline,
        "critical": stats.critical,
        "warning": stats.warning,
        "healthy": stats.healthy,
        "compliance_rate": stats.compliance_rate,
    }))
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Mask sensitive parts of URL (for display)
fn mask_url(url: &str) -> String {
    if url.contains("hooks.slack.com") {
        "https://hooks.slack.com/services/***".to_string()
    } else if url.contains("discord.com/api/webhooks") {
        "https://discord.com/api/webhooks/***".to_string()
    } else if url.contains("outlook.office.com/webhook") {
        "https://outlook.office.com/webhook/***".to_string()
    } else if url.contains("api.telegram.org") {
        "https://api.telegram.org/bot***/***".to_string()
    } else if url.len() > 30 {
        format!("{}...{}", &url[..20], &url[url.len()-10..])
    } else {
        url.to_string()
    }
}

// ============================================================================
// PERSONAL USER LOGOUT
// ============================================================================

/// Logout current user (clear identity)
/// Returns true if identity was cleared, app needs restart
#[tauri::command]
pub async fn user_logout() -> Result<serde_json::Value, String> {
    use crate::logic::identity::get_identity_manager;

    // Clear identity
    match get_identity_manager().write().clear_identity() {
        Ok(_) => {
            log::info!("User logged out - identity cleared");

            // Reset cloud sync status
            let mut status = crate::logic::cloud_sync::get_status();
            status.is_registered = false;
            status.is_connected = false;
            status.agent_id = None;
            status.org_id = None;
            crate::logic::cloud_sync::set_status(status);

            Ok(serde_json::json!({
                "success": true,
                "message": "Logged out successfully. Please restart the app.",
                "needs_restart": true
            }))
        }
        Err(e) => {
            log::error!("Failed to logout: {:?}", e);
            Err(format!("Failed to logout: {:?}", e))
        }
    }
}
