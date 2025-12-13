//! Cloud API Client
//!
//! HTTP client for communicating with One-Shield Cloud Server.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

/// Cloud server configuration
#[derive(Debug, Clone)]
pub struct CloudConfig {
    pub server_url: String,
    pub registration_key: String,
    pub timeout_seconds: u64,
}

impl Default for CloudConfig {
    fn default() -> Self {
        use crate::constants;

        Self {
            server_url: constants::get_cloud_url(),
            registration_key: constants::get_registration_key(),
            timeout_seconds: 30,
        }
    }
}

/// Cloud API client
pub struct CloudClient {
    config: CloudConfig,
    agent_id: Option<Uuid>,
    agent_token: Option<String>,
    org_id: Option<Uuid>,
    http_client: reqwest::Client,
}

// Request/Response types

#[derive(Debug, Serialize)]
pub struct RegisterAgentRequest {
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub agent_version: String,
    pub registration_key: String,
    /// Hardware ID for machine-bound identity (optional for backwards compat)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hwid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterAgentResponse {
    pub agent_id: Uuid,
    pub token: String,
    pub org_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatRequest {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: Option<f32>,
    pub incident_count: i32,
    pub process_count: Option<i32>,
    pub agent_version: String,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatResponse {
    pub server_time: i64,
    pub policy_version: i32,
    pub has_policy_update: bool,
    pub commands: Vec<AgentCommand>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum AgentCommand {
    UpdatePolicy { version: i32 },
    CollectDiagnostics,
    RestartService,
    UpdateAgent { url: String, checksum: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncIncidentRequest {
    pub id: Uuid,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub mitre_techniques: Option<Vec<String>>,
    pub threat_class: Option<String>,
    pub confidence: Option<f32>,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct SyncIncidentsRequest {
    pub incidents: Vec<SyncIncidentRequest>,
}

#[derive(Debug, Deserialize)]
pub struct SyncIncidentsResponse {
    pub synced_count: usize,
    pub server_time: i64,
}

#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub timestamp: i64,
}

#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub status: u16,
}

/// Enrollment request (Phase 12 - uses org token)
#[derive(Debug, Serialize)]
pub struct EnrollAgentRequest {
    pub enrollment_token: String,
    pub hwid: String,
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub agent_version: String,
}

/// Enrollment response
#[derive(Debug, Deserialize)]
pub struct EnrollAgentResponse {
    pub agent_id: Uuid,
    pub agent_token: String,
    pub org_id: Uuid,
    pub org_name: String,
}

impl CloudClient {
    /// Create new cloud client
    pub fn new(config: CloudConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            agent_id: None,
            agent_token: None,
            org_id: None,
            http_client,
        }
    }

    /// Check if agent is registered
    pub fn is_registered(&self) -> bool {
        self.agent_token.is_some()
    }

    /// Get agent ID
    pub fn agent_id(&self) -> Option<Uuid> {
        self.agent_id
    }

    /// Get organization ID
    pub fn org_id(&self) -> Option<Uuid> {
        self.org_id
    }

    /// Set credentials (for loading from saved state)
    pub fn set_credentials(&mut self, agent_id: Uuid, token: String, org_id: Uuid) {
        self.agent_id = Some(agent_id);
        self.agent_token = Some(token);
        self.org_id = Some(org_id);
    }

    /// Set token only (for identity loading)
    pub fn set_token(&mut self, token: String) {
        self.agent_token = Some(token);
    }

    /// Check server health
    pub async fn health_check(&self) -> Result<HealthResponse, CloudError> {
        let url = format!("{}/health", self.config.server_url);

        let response = self.http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| CloudError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            response.json().await
                .map_err(|e| CloudError::ParseError(e.to_string()))
        } else {
            Err(CloudError::ServerError(response.status().as_u16()))
        }
    }

    /// Register agent with cloud server (legacy, no HWID)
    pub async fn register(&mut self) -> Result<RegisterAgentResponse, CloudError> {
        self.register_with_hwid_opt(None).await
    }

    /// Register agent with cloud server using HWID (Enterprise)
    pub async fn register_with_hwid(&mut self, hwid: &str) -> Result<RegisterAgentResponse, CloudError> {
        self.register_with_hwid_opt(Some(hwid.to_string())).await
    }

    /// Internal registration with optional HWID
    async fn register_with_hwid_opt(&mut self, hwid: Option<String>) -> Result<RegisterAgentResponse, CloudError> {
        let url = format!("{}/api/v1/agent/register", self.config.server_url);

        // Get system info
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let request = RegisterAgentRequest {
            hostname,
            os_type: "Windows".to_string(),
            os_version: get_os_version(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            registration_key: self.config.registration_key.clone(),
            hwid,
        };

        log::info!("Registering agent with cloud server: {}", self.config.server_url);

        let response = self.http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| CloudError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            let result: RegisterAgentResponse = response.json().await
                .map_err(|e| CloudError::ParseError(e.to_string()))?;

            // Save credentials
            self.agent_id = Some(result.agent_id);
            self.agent_token = Some(result.token.clone());
            self.org_id = Some(result.org_id);

            log::info!("Agent registered successfully: {}", result.agent_id);
            Ok(result)
        } else {
            let status = response.status().as_u16();
            let error_text = response.text().await.unwrap_or_default();
            log::error!("Registration failed ({}): {}", status, error_text);
            Err(CloudError::RegistrationFailed(error_text))
        }
    }

    /// Enroll agent using organization enrollment token (Phase 12)
    /// This is the new, preferred method for registration
    pub async fn enroll(&mut self, enrollment_token: &str, hwid: &str) -> Result<EnrollAgentResponse, CloudError> {
        let url = format!("{}/api/v1/agent/enroll", self.config.server_url);

        // Get system info
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let request = EnrollAgentRequest {
            enrollment_token: enrollment_token.to_string(),
            hwid: hwid.to_string(),
            hostname,
            os_type: "Windows".to_string(),
            os_version: get_os_version(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        };

        log::info!("Enrolling agent with token: {}...", &enrollment_token[..enrollment_token.len().min(15)]);

        let response = self.http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| CloudError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            let result: EnrollAgentResponse = response.json().await
                .map_err(|e| CloudError::ParseError(e.to_string()))?;

            // Save credentials
            self.agent_id = Some(result.agent_id);
            self.agent_token = Some(result.agent_token.clone());
            self.org_id = Some(result.org_id);

            log::info!("Agent enrolled successfully: {} (org: {})", result.agent_id, result.org_name);
            Ok(result)
        } else {
            let status = response.status().as_u16();
            let error_text = response.text().await.unwrap_or_default();
            log::error!("Enrollment failed ({}): {}", status, error_text);
            Err(CloudError::RegistrationFailed(format!("Enrollment failed: {}", error_text)))
        }
    }

    /// Send heartbeat to cloud server
    pub async fn heartbeat(&self, cpu_usage: f32, memory_usage: f32, incident_count: i32) -> Result<HeartbeatResponse, CloudError> {
        let token = self.agent_token.as_ref()
            .ok_or(CloudError::NotRegistered)?;

        let url = format!("{}/api/v1/agent/heartbeat", self.config.server_url);

        let request = HeartbeatRequest {
            cpu_usage,
            memory_usage,
            disk_usage: None,
            incident_count,
            process_count: None,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        };

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request)
            .send()
            .await
            .map_err(|e| CloudError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            response.json().await
                .map_err(|e| CloudError::ParseError(e.to_string()))
        } else {
            Err(CloudError::ServerError(response.status().as_u16()))
        }
    }

    /// Sync incidents to cloud server
    pub async fn sync_incidents(&self, incidents: Vec<SyncIncidentRequest>) -> Result<SyncIncidentsResponse, CloudError> {
        let token = self.agent_token.as_ref()
            .ok_or(CloudError::NotRegistered)?;

        let url = format!("{}/api/v1/agent/sync/incidents", self.config.server_url);

        let request = SyncIncidentsRequest { incidents };

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request)
            .send()
            .await
            .map_err(|e| CloudError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            response.json().await
                .map_err(|e| CloudError::ParseError(e.to_string()))
        } else {
            Err(CloudError::ServerError(response.status().as_u16()))
        }
    }
}

/// Cloud client errors
#[derive(Debug, Clone)]
pub enum CloudError {
    NetworkError(String),
    ServerError(u16),
    ParseError(String),
    NotRegistered,
    RegistrationFailed(String),
    Unauthorized,
}

impl std::fmt::Display for CloudError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError(e) => write!(f, "Network error: {}", e),
            Self::ServerError(code) => write!(f, "Server error: {}", code),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::NotRegistered => write!(f, "Agent not registered"),
            Self::RegistrationFailed(e) => write!(f, "Registration failed: {}", e),
            Self::Unauthorized => write!(f, "Unauthorized"),
        }
    }
}

impl std::error::Error for CloudError {}

/// Get OS version string
fn get_os_version() -> String {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        Command::new("cmd")
            .args(["/c", "ver"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "Windows".to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        "Unknown OS".to_string()
    }
}
