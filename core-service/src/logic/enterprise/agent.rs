//! Endpoint Agent Module (Phase 6)
//!
//! Mục đích: Quản lý thông tin agent và gửi reports đến central server
//!
//! Features:
//! - Agent registration
//! - Heartbeat mechanism
//! - Report sending

use std::collections::HashMap;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use chrono::Utc;
use uuid::Uuid;

use super::types::{
    AgentInfo, AgentStatus, HeartbeatData, EndpointReport,
    ReportType, ThreatSummaryData, IncidentData, ActionData,
};

// ============================================================================
// CONSTANTS
// ============================================================================

const HEARTBEAT_INTERVAL_SECONDS: u64 = 60;
const REPORT_INTERVAL_SECONDS: u64 = 300;

// ============================================================================
// STATE
// ============================================================================

static AGENT_STATE: Lazy<RwLock<AgentState>> =
    Lazy::new(|| RwLock::new(AgentState::new()));

// ============================================================================
// AGENT STATE
// ============================================================================

struct AgentState {
    agent_info: Option<AgentInfo>,
    server_url: Option<String>,
    api_token: Option<String>,
    last_heartbeat: Option<i64>,
    last_report: Option<i64>,
    pending_reports: Vec<EndpointReport>,
    connected: bool,
}

impl AgentState {
    fn new() -> Self {
        Self {
            agent_info: None,
            server_url: None,
            api_token: None,
            last_heartbeat: None,
            last_report: None,
            pending_reports: Vec::new(),
            connected: false,
        }
    }

    /// Initialize agent with local info
    fn init_local(&mut self) -> AgentInfo {
        let id = get_or_create_agent_id();
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let info = AgentInfo {
            id,
            hostname,
            os_version: get_os_version(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            status: AgentStatus::Online,
            ip_address: get_local_ip(),
            mac_address: None,
            registered_at: Utc::now().timestamp(),
            last_seen: Utc::now().timestamp(),
            tags: Vec::new(),
            group: None,
        };

        self.agent_info = Some(info.clone());
        info
    }

    /// Configure connection to central server
    fn configure_server(&mut self, url: &str, token: &str) {
        self.server_url = Some(url.to_string());
        self.api_token = Some(token.to_string());
    }

    /// Create heartbeat data
    fn create_heartbeat(&self) -> Option<HeartbeatData> {
        let info = self.agent_info.as_ref()?;

        let (cpu, mem, disk) = get_system_usage();

        Some(HeartbeatData {
            agent_id: info.id.clone(),
            timestamp: Utc::now().timestamp(),
            status: info.status,
            cpu_usage: cpu,
            memory_usage: mem,
            disk_usage: disk,
            active_incidents: 0, // TODO: get from incident manager
            baseline_state: "normal".to_string(),
            version: info.agent_version.clone(),
        })
    }

    /// Send heartbeat to server
    fn send_heartbeat(&mut self) -> Result<(), AgentError> {
        let server_url = self.server_url.as_ref()
            .ok_or(AgentError::NotConfigured)?;
        let token = self.api_token.as_ref()
            .ok_or(AgentError::NotConfigured)?;

        let heartbeat = self.create_heartbeat()
            .ok_or(AgentError::NotInitialized)?;

        let url = format!("{}/api/v1/agents/heartbeat", server_url);

        let response = ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Content-Type", "application/json")
            .send_string(&serde_json::to_string(&heartbeat).unwrap_or_default());

        match response {
            Ok(_) => {
                self.last_heartbeat = Some(Utc::now().timestamp());
                self.connected = true;
                if let Some(ref mut info) = self.agent_info {
                    info.last_seen = Utc::now().timestamp();
                }
                Ok(())
            }
            Err(e) => {
                self.connected = false;
                Err(AgentError::NetworkError(e.to_string()))
            }
        }
    }

    /// Queue a report for sending
    fn queue_report(&mut self, report: EndpointReport) {
        self.pending_reports.push(report);

        // Limit queue size
        if self.pending_reports.len() > 100 {
            self.pending_reports.remove(0);
        }
    }

    /// Send pending reports
    fn send_pending_reports(&mut self) -> Vec<Result<(), AgentError>> {
        let server_url = match &self.server_url {
            Some(url) => url.clone(),
            None => return vec![Err(AgentError::NotConfigured)],
        };
        let token = match &self.api_token {
            Some(t) => t.clone(),
            None => return vec![Err(AgentError::NotConfigured)],
        };

        let url = format!("{}/api/v1/agents/reports", server_url);
        let mut results = Vec::new();

        let reports = std::mem::take(&mut self.pending_reports);

        for report in reports {
            let response = ureq::post(&url)
                .set("Authorization", &format!("Bearer {}", token))
                .set("Content-Type", "application/json")
                .send_string(&serde_json::to_string(&report).unwrap_or_default());

            match response {
                Ok(_) => {
                    results.push(Ok(()));
                }
                Err(e) => {
                    // Re-queue failed report
                    self.pending_reports.push(report);
                    results.push(Err(AgentError::NetworkError(e.to_string())));
                }
            }
        }

        self.last_report = Some(Utc::now().timestamp());
        results
    }
}

// ============================================================================
// UTILITIES
// ============================================================================

fn get_or_create_agent_id() -> String {
    // Try to read from file first
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("OneShield");

    let id_file = config_dir.join("agent_id");

    if id_file.exists() {
        if let Ok(id) = std::fs::read_to_string(&id_file) {
            let id = id.trim();
            if !id.is_empty() {
                return id.to_string();
            }
        }
    }

    // Generate new ID
    let id = Uuid::new_v4().to_string();

    // Save to file
    let _ = std::fs::create_dir_all(&config_dir);
    let _ = std::fs::write(&id_file, &id);

    id
}

fn get_os_version() -> String {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("cmd")
            .args(["/C", "ver"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "Windows".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    {
        "Unknown".to_string()
    }
}

fn get_local_ip() -> Option<String> {
    // Simple approach - get first non-loopback IPv4
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } | Select-Object -First 1).IPAddress"])
            .output()
            .ok()?;

        let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if ip.is_empty() { None } else { Some(ip) }
    }

    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

fn get_system_usage() -> (f32, f32, f32) {
    // TODO: Get actual system metrics
    (0.0, 0.0, 0.0)
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum AgentError {
    NotInitialized,
    NotConfigured,
    NetworkError(String),
    ServerError(String),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::NotInitialized => write!(f, "Agent not initialized"),
            AgentError::NotConfigured => write!(f, "Server not configured"),
            AgentError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            AgentError::ServerError(msg) => write!(f, "Server error: {}", msg),
        }
    }
}

impl std::error::Error for AgentError {}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Get agent ID (generate if needed)
pub fn get_agent_id() -> String {
    get_or_create_agent_id()
}

/// Initialize agent locally
pub fn init_agent() -> AgentInfo {
    AGENT_STATE.write().init_local()
}

/// Register agent with central server
pub fn register_agent(server_url: &str, token: &str) -> Result<(), AgentError> {
    let mut state = AGENT_STATE.write();

    // Initialize if needed
    if state.agent_info.is_none() {
        state.init_local();
    }

    state.configure_server(server_url, token);

    // Send initial heartbeat
    state.send_heartbeat()?;

    log::info!("Agent registered with {}", server_url);
    Ok(())
}

/// Send heartbeat to central server
pub fn send_heartbeat() -> Result<(), AgentError> {
    AGENT_STATE.write().send_heartbeat()
}

/// Create and queue a report
pub fn send_report(
    report_type: ReportType,
    incidents: Vec<IncidentData>,
    actions: Vec<ActionData>,
    threat_summary: ThreatSummaryData,
) {
    let state = AGENT_STATE.read();
    let agent_id = state.agent_info.as_ref()
        .map(|i| i.id.clone())
        .unwrap_or_else(get_agent_id);
    drop(state);

    let report = EndpointReport {
        agent_id,
        report_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().timestamp(),
        report_type,
        incidents,
        actions_taken: actions,
        threat_summary,
    };

    AGENT_STATE.write().queue_report(report);
}

/// Get current agent info
pub fn get_agent_info() -> Option<AgentInfo> {
    AGENT_STATE.read().agent_info.clone()
}

/// Check if connected to central server
pub fn is_connected() -> bool {
    AGENT_STATE.read().connected
}

/// Get pending reports count
pub fn pending_reports_count() -> usize {
    AGENT_STATE.read().pending_reports.len()
}

/// Flush pending reports
pub fn flush_reports() -> Vec<Result<(), AgentError>> {
    AGENT_STATE.write().send_pending_reports()
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentStats {
    pub agent_id: String,
    pub hostname: String,
    pub status: String,
    pub connected: bool,
    pub last_heartbeat: Option<i64>,
    pub last_report: Option<i64>,
    pub pending_reports: usize,
}

pub fn get_stats() -> AgentStats {
    let state = AGENT_STATE.read();

    AgentStats {
        agent_id: state.agent_info.as_ref().map(|i| i.id.clone()).unwrap_or_default(),
        hostname: state.agent_info.as_ref().map(|i| i.hostname.clone()).unwrap_or_default(),
        status: state.agent_info.as_ref()
            .map(|i| i.status.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        connected: state.connected,
        last_heartbeat: state.last_heartbeat,
        last_report: state.last_report,
        pending_reports: state.pending_reports.len(),
    }
}
