//! Security Event Types
//!
//! Immutable, timestamped security events for audit trail.
//! These events are the core data structure for logging & analytics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::logic::threat::ThreatClass;
use crate::logic::policy::{Decision, Severity};
use crate::logic::action_guard::ActionType;

// ============================================================================
// EVENT TYPES
// ============================================================================

/// Categories of security events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// AI detected anomaly and classified threat
    ThreatDetected,
    /// Policy engine made a decision
    PolicyDecision,
    /// Action was created (pending or executed)
    ActionCreated,
    /// Action was executed (approved)
    ActionExecuted,
    /// User approved a pending action
    UserApproved,
    /// User denied/cancelled an action
    UserDenied,
    /// Action expired without user response
    ActionExpired,
    /// User override - disagreed with AI
    UserOverride,
    /// Process was added to whitelist
    WhitelistAdded,
    /// Process was removed from whitelist
    WhitelistRemoved,
    /// System started
    SystemStart,
    /// System stopped
    SystemStop,
    /// AI model loaded/unloaded
    ModelEvent,
    /// Baseline learned/updated
    BaselineEvent,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::ThreatDetected => "threat_detected",
            EventType::PolicyDecision => "policy_decision",
            EventType::ActionCreated => "action_created",
            EventType::ActionExecuted => "action_executed",
            EventType::UserApproved => "user_approved",
            EventType::UserDenied => "user_denied",
            EventType::ActionExpired => "action_expired",
            EventType::UserOverride => "user_override",
            EventType::WhitelistAdded => "whitelist_added",
            EventType::WhitelistRemoved => "whitelist_removed",
            EventType::SystemStart => "system_start",
            EventType::SystemStop => "system_stop",
            EventType::ModelEvent => "model_event",
            EventType::BaselineEvent => "baseline_event",
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            EventType::SystemStart | EventType::SystemStop => 0,
            EventType::ModelEvent | EventType::BaselineEvent => 1,
            EventType::WhitelistAdded | EventType::WhitelistRemoved => 2,
            EventType::ThreatDetected | EventType::PolicyDecision => 3,
            EventType::ActionCreated | EventType::ActionExpired => 4,
            EventType::UserApproved | EventType::UserDenied => 5,
            EventType::ActionExecuted | EventType::UserOverride => 6,
        }
    }
}

// ============================================================================
// PROCESS INFO
// ============================================================================

/// Information about the process involved in the event
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: Option<u32>,
    pub name: String,
    pub path: Option<String>,
    pub parent_pid: Option<u32>,
    pub command_line: Option<String>,
}

impl ProcessInfo {
    pub fn new(pid: u32, name: &str) -> Self {
        Self {
            pid: Some(pid),
            name: name.to_string(),
            ..Default::default()
        }
    }

    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }

    pub fn with_parent(mut self, parent_pid: u32) -> Self {
        self.parent_pid = Some(parent_pid);
        self
    }
}

// ============================================================================
// USER OVERRIDE
// ============================================================================

/// Information about user override (when user disagrees with AI)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOverride {
    /// What the AI recommended
    pub ai_recommendation: String,
    /// What the user chose instead
    pub user_choice: String,
    /// User's reason (optional feedback)
    pub reason: Option<String>,
    /// Time between recommendation and override
    pub response_time_ms: u64,
}

// ============================================================================
// AI CONTEXT
// ============================================================================

/// AI-related context for the event
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiContext {
    /// Raw anomaly score from AI model
    pub anomaly_score: f32,
    /// Confidence of the prediction
    pub confidence: f32,
    /// Inference method used
    pub method: String,
    /// Baseline deviation score
    pub baseline_deviation: f32,
    /// Final weighted score
    pub final_score: f32,
    /// Detection tags
    pub tags: Vec<String>,
    /// Reasons for classification
    pub reasons: Vec<String>,
}

// ============================================================================
// SECURITY EVENT (Main struct)
// ============================================================================

/// Immutable security event for audit trail
///
/// Each event represents a single point in time in the security pipeline.
/// Events are append-only and should never be modified after creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event ID
    pub id: String,
    /// When the event occurred (UTC)
    pub timestamp: DateTime<Utc>,
    /// Type of event
    pub event_type: EventType,
    /// Session ID (for correlating events in same session)
    pub session_id: String,
    /// Process information (if applicable)
    pub process: Option<ProcessInfo>,
    /// Threat classification (if applicable)
    pub threat_class: Option<ThreatClass>,
    /// Policy decision (if applicable)
    pub decision: Option<Decision>,
    /// Severity level (if applicable)
    pub severity: Option<Severity>,
    /// Action type (if applicable)
    pub action: Option<ActionType>,
    /// AI context (scores, confidence, etc.)
    pub ai_context: Option<AiContext>,
    /// User override information (if user disagreed with AI)
    pub user_override: Option<UserOverride>,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
    /// Human-readable description
    pub description: String,
}

impl SecurityEvent {
    /// Create a new security event
    pub fn new(event_type: EventType, description: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            session_id: get_session_id(),
            process: None,
            threat_class: None,
            decision: None,
            severity: None,
            action: None,
            ai_context: None,
            user_override: None,
            metadata: None,
            description: description.to_string(),
        }
    }

    // Builder pattern methods
    pub fn with_process(mut self, process: ProcessInfo) -> Self {
        self.process = Some(process);
        self
    }

    pub fn with_threat_class(mut self, threat_class: ThreatClass) -> Self {
        self.threat_class = Some(threat_class);
        self
    }

    pub fn with_decision(mut self, decision: Decision) -> Self {
        self.decision = Some(decision);
        self
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    pub fn with_action(mut self, action: ActionType) -> Self {
        self.action = Some(action);
        self
    }

    pub fn with_ai_context(mut self, ai_context: AiContext) -> Self {
        self.ai_context = Some(ai_context);
        self
    }

    pub fn with_user_override(mut self, user_override: UserOverride) -> Self {
        self.user_override = Some(user_override);
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Convert to JSONL line (for append-only log)
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Check if this event represents a user override
    pub fn is_override(&self) -> bool {
        self.user_override.is_some()
    }

    /// Check if this event is actionable (requires attention)
    pub fn is_actionable(&self) -> bool {
        matches!(
            self.event_type,
            EventType::ThreatDetected
                | EventType::ActionCreated
                | EventType::UserOverride
        )
    }
}

// ============================================================================
// SESSION ID
// ============================================================================

use std::sync::OnceLock;

static SESSION_ID: OnceLock<String> = OnceLock::new();

/// Get the current session ID (generated once per app run)
pub fn get_session_id() -> String {
    SESSION_ID
        .get_or_init(|| Uuid::new_v4().to_string())
        .clone()
}

// ============================================================================
// CONVENIENCE CONSTRUCTORS
// ============================================================================

impl SecurityEvent {
    /// Create threat detected event
    pub fn threat_detected(process: ProcessInfo, threat_class: ThreatClass, ai: AiContext) -> Self {
        Self::new(
            EventType::ThreatDetected,
            &format!("Threat detected: {} classified as {:?}", process.name, threat_class),
        )
        .with_process(process)
        .with_threat_class(threat_class)
        .with_ai_context(ai)
    }

    /// Create policy decision event
    pub fn policy_decision(
        process: ProcessInfo,
        threat_class: ThreatClass,
        decision: Decision,
        severity: Severity,
    ) -> Self {
        Self::new(
            EventType::PolicyDecision,
            &format!(
                "Policy decision for {}: {:?} -> {:?}",
                process.name, threat_class, decision
            ),
        )
        .with_process(process)
        .with_threat_class(threat_class)
        .with_decision(decision)
        .with_severity(severity)
    }

    /// Create action created event
    pub fn action_created(process: ProcessInfo, action: ActionType, auto_execute: bool) -> Self {
        Self::new(
            EventType::ActionCreated,
            &format!(
                "Action created for {}: {:?} (auto: {})",
                process.name, action, auto_execute
            ),
        )
        .with_process(process)
        .with_action(action)
    }

    /// Create user approved event
    pub fn user_approved(process: ProcessInfo, action: ActionType) -> Self {
        Self::new(
            EventType::UserApproved,
            &format!("User approved {:?} for {}", action, process.name),
        )
        .with_process(process)
        .with_action(action)
    }

    /// Create user denied event
    pub fn user_denied(process: ProcessInfo, action: ActionType) -> Self {
        Self::new(
            EventType::UserDenied,
            &format!("User denied {:?} for {}", action, process.name),
        )
        .with_process(process)
        .with_action(action)
    }

    /// Create user override event (IMPORTANT for training!)
    pub fn user_override_event(
        process: ProcessInfo,
        ai_recommendation: &str,
        user_choice: &str,
        reason: Option<String>,
        response_time_ms: u64,
    ) -> Self {
        Self::new(
            EventType::UserOverride,
            &format!(
                "User override for {}: AI said '{}', user chose '{}'",
                process.name, ai_recommendation, user_choice
            ),
        )
        .with_process(process)
        .with_user_override(UserOverride {
            ai_recommendation: ai_recommendation.to_string(),
            user_choice: user_choice.to_string(),
            reason,
            response_time_ms,
        })
    }

    /// Create system start event
    pub fn system_start(version: &str) -> Self {
        Self::new(
            EventType::SystemStart,
            &format!("AI Security started (v{})", version),
        )
        .with_metadata(serde_json::json!({
            "version": version,
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        }))
    }

    /// Create system stop event
    pub fn system_stop(uptime_secs: u64) -> Self {
        Self::new(
            EventType::SystemStop,
            &format!("AI Security stopped (uptime: {}s)", uptime_secs),
        )
        .with_metadata(serde_json::json!({
            "uptime_secs": uptime_secs,
        }))
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_creation() {
        let event = SecurityEvent::new(EventType::ThreatDetected, "Test threat");
        assert!(!event.id.is_empty());
        assert_eq!(event.event_type, EventType::ThreatDetected);
        assert_eq!(event.description, "Test threat");
    }

    #[test]
    fn test_event_builder() {
        let process = ProcessInfo::new(1234, "malware.exe");
        let event = SecurityEvent::new(EventType::ActionCreated, "Action created")
            .with_process(process)
            .with_action(ActionType::KillProcess)
            .with_threat_class(ThreatClass::Malicious);

        assert!(event.process.is_some());
        assert_eq!(event.action, Some(ActionType::KillProcess));
        assert_eq!(event.threat_class, Some(ThreatClass::Malicious));
    }

    #[test]
    fn test_event_to_jsonl() {
        let event = SecurityEvent::new(EventType::SystemStart, "Started");
        let jsonl = event.to_jsonl();
        // Serde serializes enum as PascalCase by default
        assert!(jsonl.contains("SystemStart"));
        assert!(!jsonl.contains('\n')); // JSONL = single line
    }

    #[test]
    fn test_session_id_consistency() {
        let id1 = get_session_id();
        let id2 = get_session_id();
        assert_eq!(id1, id2); // Same session = same ID
    }

    #[test]
    fn test_threat_detected_convenience() {
        let process = ProcessInfo::new(5678, "suspicious.exe");
        let ai = AiContext {
            anomaly_score: 0.85,
            confidence: 0.9,
            ..Default::default()
        };
        let event = SecurityEvent::threat_detected(process, ThreatClass::Suspicious, ai);

        assert_eq!(event.event_type, EventType::ThreatDetected);
        assert!(event.description.contains("suspicious.exe"));
        assert!(event.ai_context.is_some());
    }
}
