//! Response Types (Phase 5)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ============================================================================
// RESPONSE ACTION TYPES
// ============================================================================

/// Response action to execute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    /// Suspend a process (pausable)
    SuspendProcess { pid: u32 },

    /// Resume a suspended process
    ResumeProcess { pid: u32 },

    /// Kill a process
    KillProcess { pid: u32, force: bool },

    /// Block network for a process
    BlockNetwork { pid: u32, exe_path: Option<PathBuf> },

    /// Unblock network for a process
    UnblockNetwork { pid: u32 },

    /// Quarantine a file
    QuarantineFile { path: PathBuf },

    /// Restore a quarantined file
    RestoreFile { quarantine_id: String },

    /// Delete a quarantined file permanently
    DeleteQuarantined { quarantine_id: String },

    /// Send webhook alert
    SendAlert { webhook_id: String, message: String },

    /// Custom action (for extensibility)
    Custom { name: String, params: std::collections::HashMap<String, String> },
}

impl ResponseAction {
    pub fn action_type(&self) -> &'static str {
        match self {
            ResponseAction::SuspendProcess { .. } => "suspend_process",
            ResponseAction::ResumeProcess { .. } => "resume_process",
            ResponseAction::KillProcess { .. } => "kill_process",
            ResponseAction::BlockNetwork { .. } => "block_network",
            ResponseAction::UnblockNetwork { .. } => "unblock_network",
            ResponseAction::QuarantineFile { .. } => "quarantine_file",
            ResponseAction::RestoreFile { .. } => "restore_file",
            ResponseAction::DeleteQuarantined { .. } => "delete_quarantined",
            ResponseAction::SendAlert { .. } => "send_alert",
            ResponseAction::Custom { name, .. } => "custom",
        }
    }

    pub fn description(&self) -> String {
        match self {
            ResponseAction::SuspendProcess { pid } => format!("Suspend process {}", pid),
            ResponseAction::ResumeProcess { pid } => format!("Resume process {}", pid),
            ResponseAction::KillProcess { pid, force } => {
                if *force {
                    format!("Force kill process {}", pid)
                } else {
                    format!("Kill process {}", pid)
                }
            }
            ResponseAction::BlockNetwork { pid, .. } => format!("Block network for PID {}", pid),
            ResponseAction::UnblockNetwork { pid } => format!("Unblock network for PID {}", pid),
            ResponseAction::QuarantineFile { path } => format!("Quarantine {}", path.display()),
            ResponseAction::RestoreFile { quarantine_id } => format!("Restore {}", quarantine_id),
            ResponseAction::DeleteQuarantined { quarantine_id } => format!("Delete {}", quarantine_id),
            ResponseAction::SendAlert { webhook_id, .. } => format!("Send alert to {}", webhook_id),
            ResponseAction::Custom { name, .. } => format!("Custom: {}", name),
        }
    }
}

/// Result of an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action: ResponseAction,
    pub status: ActionStatus,
    pub message: String,
    pub timestamp: i64,
    pub duration_ms: u64,
}

/// Status of an action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionStatus {
    Success,
    Failed,
    PartialSuccess,
    Pending,
    Cancelled,
}

impl ActionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionStatus::Success => "success",
            ActionStatus::Failed => "failed",
            ActionStatus::PartialSuccess => "partial",
            ActionStatus::Pending => "pending",
            ActionStatus::Cancelled => "cancelled",
        }
    }
}

/// Action error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionError {
    /// Process not found
    ProcessNotFound { pid: u32 },
    /// Access denied
    AccessDenied { reason: String },
    /// File not found
    FileNotFound { path: String },
    /// Network error
    NetworkError { message: String },
    /// Command failed
    CommandFailed { command: String, exit_code: i32, stderr: String },
    /// Invalid action
    InvalidAction { reason: String },
    /// Other error
    Other { message: String },
}

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionError::ProcessNotFound { pid } => write!(f, "Process {} not found", pid),
            ActionError::AccessDenied { reason } => write!(f, "Access denied: {}", reason),
            ActionError::FileNotFound { path } => write!(f, "File not found: {}", path),
            ActionError::NetworkError { message } => write!(f, "Network error: {}", message),
            ActionError::CommandFailed { command, exit_code, stderr } => {
                write!(f, "Command '{}' failed ({}): {}", command, exit_code, stderr)
            }
            ActionError::InvalidAction { reason } => write!(f, "Invalid action: {}", reason),
            ActionError::Other { message } => write!(f, "Error: {}", message),
        }
    }
}

impl std::error::Error for ActionError {}

// ============================================================================
// QUARANTINE TYPES
// ============================================================================

/// Quarantine entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub file_name: String,
    pub file_size: u64,
    pub sha256: String,
    pub quarantine_time: i64,
    pub reason: String,
    pub source_incident: Option<String>,
    pub can_restore: bool,
}

// ============================================================================
// WEBHOOK TYPES
// ============================================================================

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub platform: WebhookPlatform,
    pub enabled: bool,
    pub min_severity: AlertSeverity,
    pub include_details: bool,
    pub created_at: i64,
}

/// Webhook platform
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookPlatform {
    Slack,
    Discord,
    MicrosoftTeams,
    Telegram,
    Generic,
}

impl WebhookPlatform {
    pub fn as_str(&self) -> &'static str {
        match self {
            WebhookPlatform::Slack => "slack",
            WebhookPlatform::Discord => "discord",
            WebhookPlatform::MicrosoftTeams => "teams",
            WebhookPlatform::Telegram => "telegram",
            WebhookPlatform::Generic => "generic",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "slack" => WebhookPlatform::Slack,
            "discord" => WebhookPlatform::Discord,
            "teams" | "msteams" | "microsoft_teams" => WebhookPlatform::MicrosoftTeams,
            "telegram" => WebhookPlatform::Telegram,
            _ => WebhookPlatform::Generic,
        }
    }
}

/// Alert severity for webhooks
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "Info",
            AlertSeverity::Low => "Low",
            AlertSeverity::Medium => "Medium",
            AlertSeverity::High => "High",
            AlertSeverity::Critical => "Critical",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "[INFO]",
            AlertSeverity::Low => "[LOW]",
            AlertSeverity::Medium => "[MEDIUM]",
            AlertSeverity::High => "[HIGH]",
            AlertSeverity::Critical => "[CRITICAL]",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "#3498db",
            AlertSeverity::Low => "#2ecc71",
            AlertSeverity::Medium => "#f1c40f",
            AlertSeverity::High => "#e67e22",
            AlertSeverity::Critical => "#e74c3c",
        }
    }
}

/// Alert payload to send
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPayload {
    pub title: String,
    pub message: String,
    pub severity: AlertSeverity,
    pub timestamp: i64,
    pub hostname: Option<String>,
    pub incident_id: Option<String>,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub mitre_techniques: Vec<String>,
    pub tags: Vec<String>,
    pub extra: std::collections::HashMap<String, String>,
}

impl AlertPayload {
    pub fn new(title: &str, message: &str, severity: AlertSeverity) -> Self {
        Self {
            title: title.to_string(),
            message: message.to_string(),
            severity,
            timestamp: chrono::Utc::now().timestamp(),
            hostname: hostname::get().ok().map(|h| h.to_string_lossy().to_string()),
            incident_id: None,
            process_name: None,
            process_pid: None,
            mitre_techniques: Vec::new(),
            tags: Vec::new(),
            extra: std::collections::HashMap::new(),
        }
    }
}

// ============================================================================
// AUTO-RESPONSE CONFIG
// ============================================================================

/// Auto-response configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoResponseConfig {
    pub enabled: bool,

    /// Minimum severity to trigger auto-response
    pub min_severity: AlertSeverity,

    /// Actions to take automatically
    pub auto_actions: Vec<AutoAction>,

    /// Cooldown between actions (seconds)
    pub cooldown_seconds: u64,

    /// Maximum actions per hour
    pub max_actions_per_hour: u32,
}

/// Auto action rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoAction {
    pub name: String,
    pub trigger_severity: AlertSeverity,
    pub action_type: AutoActionType,
    pub enabled: bool,
}

/// Type of auto action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutoActionType {
    /// Kill the offending process
    KillProcess,
    /// Suspend the process
    SuspendProcess,
    /// Block network for the process
    BlockNetwork,
    /// Quarantine the executable
    QuarantineExecutable,
    /// Send alert
    SendAlert { webhook_ids: Vec<String> },
}

impl Default for AutoResponseConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for safety
            min_severity: AlertSeverity::High,
            auto_actions: vec![
                AutoAction {
                    name: "Alert on High".to_string(),
                    trigger_severity: AlertSeverity::High,
                    action_type: AutoActionType::SendAlert { webhook_ids: vec![] },
                    enabled: true,
                },
                AutoAction {
                    name: "Kill on Critical".to_string(),
                    trigger_severity: AlertSeverity::Critical,
                    action_type: AutoActionType::KillProcess,
                    enabled: false,
                },
            ],
            cooldown_seconds: 60,
            max_actions_per_hour: 10,
        }
    }
}
