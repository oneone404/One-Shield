//! Policy Types
//!
//! Core types cho policy decisions.
//! KHÔNG chứa logic - chỉ data structures.

use serde::{Deserialize, Serialize};

// ============================================================================
// DECISION TYPES
// ============================================================================

/// Policy decision - what to do with a threat
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Log silently, no user notification
    SilentLog,
    /// Notify user via toast/notification
    Notify,
    /// Require user approval before action
    RequireApproval,
    /// Auto-execute action (kill/block)
    AutoBlock,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::SilentLog => "silent_log",
            Decision::Notify => "notify",
            Decision::RequireApproval => "require_approval",
            Decision::AutoBlock => "auto_block",
        }
    }

    pub fn severity_level(&self) -> u8 {
        match self {
            Decision::SilentLog => 0,
            Decision::Notify => 1,
            Decision::RequireApproval => 2,
            Decision::AutoBlock => 3,
        }
    }

    pub fn requires_user_action(&self) -> bool {
        matches!(self, Decision::RequireApproval)
    }

    pub fn is_destructive(&self) -> bool {
        matches!(self, Decision::AutoBlock)
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// SEVERITY LEVELS
// ============================================================================

/// Severity of the threat (separate from classification)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: f32) -> Self {
        if score >= 0.9 {
            Severity::Critical
        } else if score >= 0.7 {
            Severity::High
        } else if score >= 0.4 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            Severity::Low => "#10b981",     // Green
            Severity::Medium => "#f59e0b",  // Yellow
            Severity::High => "#f97316",    // Orange
            Severity::Critical => "#ef4444", // Red
        }
    }

    pub fn is_high(&self) -> bool {
        matches!(self, Severity::High | Severity::Critical)
    }
}

// ============================================================================
// ACTION TYPES
// ============================================================================

/// Specific action to take
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    /// No action needed
    None,
    /// Kill the process
    KillProcess,
    /// Suspend the process
    SuspendProcess,
    /// Block network for process
    BlockNetwork,
    /// Isolate user session
    IsolateSession,
    /// Alert only
    AlertOnly,
}

impl ActionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionType::None => "none",
            ActionType::KillProcess => "kill_process",
            ActionType::SuspendProcess => "suspend_process",
            ActionType::BlockNetwork => "block_network",
            ActionType::IsolateSession => "isolate_session",
            ActionType::AlertOnly => "alert_only",
        }
    }

    pub fn is_destructive(&self) -> bool {
        matches!(self, ActionType::KillProcess | ActionType::IsolateSession)
    }
}

// ============================================================================
// POLICY RESULT
// ============================================================================

/// Complete policy decision result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub decision: Decision,
    pub severity: Severity,
    pub action: ActionType,
    pub reasons: Vec<String>,
    pub auto_execute: bool,
    pub expires_in_secs: Option<u64>,
}

impl Default for PolicyResult {
    fn default() -> Self {
        Self {
            decision: Decision::SilentLog,
            severity: Severity::Low,
            action: ActionType::None,
            reasons: vec![],
            auto_execute: false,
            expires_in_secs: None,
        }
    }
}
