//! Enterprise Types (Phase 6)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// RBAC - ROLE BASED ACCESS CONTROL
// ============================================================================

/// User roles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    /// Full access - all permissions
    Admin,
    /// Security analyst - view + acknowledge + limited actions
    Analyst,
    /// Read-only access
    Viewer,
    /// API client - programmatic access
    ApiClient,
    /// No access (disabled)
    Disabled,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::Analyst => "analyst",
            UserRole::Viewer => "viewer",
            UserRole::ApiClient => "api_client",
            UserRole::Disabled => "disabled",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "admin" => UserRole::Admin,
            "analyst" => UserRole::Analyst,
            "viewer" => UserRole::Viewer,
            "api_client" | "apiclient" => UserRole::ApiClient,
            _ => UserRole::Disabled,
        }
    }

    /// Get default permissions for this role
    pub fn default_permissions(&self) -> Vec<Permission> {
        match self {
            UserRole::Admin => vec![
                Permission::new(Resource::All, vec![Action::Read, Action::Write, Action::Delete, Action::Execute]),
            ],
            UserRole::Analyst => vec![
                Permission::new(Resource::Incidents, vec![Action::Read, Action::Write]),
                Permission::new(Resource::Endpoints, vec![Action::Read]),
                Permission::new(Resource::Policies, vec![Action::Read]),
                Permission::new(Resource::Reports, vec![Action::Read]),
                Permission::new(Resource::Actions, vec![Action::Execute]),
            ],
            UserRole::Viewer => vec![
                Permission::new(Resource::Incidents, vec![Action::Read]),
                Permission::new(Resource::Endpoints, vec![Action::Read]),
                Permission::new(Resource::Policies, vec![Action::Read]),
                Permission::new(Resource::Reports, vec![Action::Read]),
            ],
            UserRole::ApiClient => vec![
                Permission::new(Resource::Incidents, vec![Action::Read]),
                Permission::new(Resource::Endpoints, vec![Action::Read]),
                Permission::new(Resource::Reports, vec![Action::Read]),
            ],
            UserRole::Disabled => vec![],
        }
    }
}

/// Resources that can be accessed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Resource {
    All,
    Incidents,
    Policies,
    Endpoints,
    Settings,
    Users,
    Reports,
    Actions,
    Quarantine,
    Baseline,
}

impl Resource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Resource::All => "all",
            Resource::Incidents => "incidents",
            Resource::Policies => "policies",
            Resource::Endpoints => "endpoints",
            Resource::Settings => "settings",
            Resource::Users => "users",
            Resource::Reports => "reports",
            Resource::Actions => "actions",
            Resource::Quarantine => "quarantine",
            Resource::Baseline => "baseline",
        }
    }
}

/// Actions that can be performed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Read,
    Write,
    Delete,
    Execute,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Delete => "delete",
            Action::Execute => "execute",
        }
    }
}

/// Permission entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub resource: Resource,
    pub actions: Vec<Action>,
}

impl Permission {
    pub fn new(resource: Resource, actions: Vec<Action>) -> Self {
        Self { resource, actions }
    }

    pub fn can(&self, action: Action) -> bool {
        self.actions.contains(&action)
    }
}

/// User account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub role: UserRole,
    pub permissions: Vec<Permission>,
    pub created_at: i64,
    pub last_login: Option<i64>,
    pub enabled: bool,
    pub api_key: Option<String>,
    pub mfa_enabled: bool,
}

impl User {
    pub fn new(id: &str, username: &str, role: UserRole) -> Self {
        Self {
            id: id.to_string(),
            username: username.to_string(),
            email: None,
            role,
            permissions: role.default_permissions(),
            created_at: chrono::Utc::now().timestamp(),
            last_login: None,
            enabled: true,
            api_key: None,
            mfa_enabled: false,
        }
    }

    pub fn has_permission(&self, resource: Resource, action: Action) -> bool {
        if !self.enabled || self.role == UserRole::Disabled {
            return false;
        }

        for perm in &self.permissions {
            if perm.resource == Resource::All || perm.resource == resource {
                if perm.can(action) {
                    return true;
                }
            }
        }
        false
    }
}

/// Session token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl Session {
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() > self.expires_at
    }
}

// ============================================================================
// AGENT - ENDPOINT AGENT
// ============================================================================

/// Agent information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub hostname: String,
    pub os_version: String,
    pub agent_version: String,
    pub status: AgentStatus,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub registered_at: i64,
    pub last_seen: i64,
    pub tags: Vec<String>,
    pub group: Option<String>,
}

/// Agent status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Online,
    Offline,
    Degraded,
    Updating,
    Error,
}

impl AgentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentStatus::Online => "online",
            AgentStatus::Offline => "offline",
            AgentStatus::Degraded => "degraded",
            AgentStatus::Updating => "updating",
            AgentStatus::Error => "error",
        }
    }
}

/// Heartbeat data sent to central server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatData {
    pub agent_id: String,
    pub timestamp: i64,
    pub status: AgentStatus,
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: f32,
    pub active_incidents: u32,
    pub baseline_state: String,
    pub version: String,
}

/// Endpoint report sent to central server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointReport {
    pub agent_id: String,
    pub report_id: String,
    pub timestamp: i64,
    pub report_type: ReportType,
    pub incidents: Vec<IncidentData>,
    pub actions_taken: Vec<ActionData>,
    pub threat_summary: ThreatSummaryData,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ReportType {
    Periodic,
    Incident,
    OnDemand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentData {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub timestamp: i64,
    pub status: String,
    pub process_name: Option<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionData {
    pub action_type: String,
    pub target: String,
    pub timestamp: i64,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSummaryData {
    pub total_incidents: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub resolved_count: u32,
}

// ============================================================================
// POLICY - POLICY SYNC
// ============================================================================

/// Policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: u32,
    pub enabled: bool,
    pub priority: i32,
    pub rules: Vec<PolicyRule>,
    pub created_at: i64,
    pub updated_at: i64,
    pub created_by: String,
}

/// Policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub condition: PolicyCondition,
    pub actions: Vec<PolicyAction>,
    pub enabled: bool,
}

/// Policy condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub condition_type: String,
    pub operator: String,
    pub value: serde_json::Value,
}

/// Policy action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Alert { severity: String },
    Block,
    Quarantine,
    Log,
    Notify { channels: Vec<String> },
    Custom { name: String, params: HashMap<String, String> },
}

// ============================================================================
// REPORTING - ANALYTICS
// ============================================================================

/// Incident summary for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentSummary {
    pub period_start: i64,
    pub period_end: i64,
    pub total_incidents: u32,
    pub by_severity: HashMap<String, u32>,
    pub by_status: HashMap<String, u32>,
    pub by_mitre: HashMap<String, u32>,
    pub top_processes: Vec<(String, u32)>,
    pub trend: TrendData,
}

/// Trend data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendData {
    pub direction: TrendDirection,
    pub percentage_change: f32,
    pub previous_count: u32,
    pub current_count: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TrendDirection {
    Up,
    Down,
    Stable,
}

/// Report period for analytics
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ReportPeriod {
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Yearly,
}

/// Endpoint statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointStats {
    pub total_endpoints: u32,
    pub online_count: u32,
    pub offline_count: u32,
    pub degraded_count: u32,
    pub by_os: HashMap<String, u32>,
    pub by_group: HashMap<String, u32>,
    pub avg_cpu_usage: f32,
    pub avg_memory_usage: f32,
}

/// Threat overview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatOverview {
    pub active_threats: u32,
    pub threats_today: u32,
    pub threats_this_week: u32,
    pub top_threat_types: Vec<(String, u32)>,
    pub top_affected_endpoints: Vec<(String, u32)>,
    pub mitre_coverage: Vec<MitreCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreCoverage {
    pub tactic: String,
    pub technique_count: u32,
    pub incident_count: u32,
}

// ============================================================================
// API TYPES
// ============================================================================

/// API request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<serde_json::Value>,
}

/// API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse {
    pub status: u16,
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub timestamp: i64,
}

impl ApiResponse {
    pub fn success(data: serde_json::Value) -> Self {
        Self {
            status: 200,
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn error(status: u16, message: &str) -> Self {
        Self {
            status,
            success: false,
            data: None,
            error: Some(message.to_string()),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
}
