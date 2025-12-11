//! Policy Synchronization Module (Phase 6)
//!
//! Mục đích: Đồng bộ policies từ central server
//!
//! Features:
//! - Policy download and caching
//! - Policy version management
//! - Policy application

use std::collections::HashMap;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use chrono::Utc;

use super::types::{PolicyDefinition, PolicyRule, PolicyAction, PolicyCondition};

// ============================================================================
// STATE
// ============================================================================

static POLICY_MANAGER: Lazy<RwLock<PolicyManager>> =
    Lazy::new(|| RwLock::new(PolicyManager::new()));

// ============================================================================
// POLICY MANAGER
// ============================================================================

pub struct PolicyManager {
    policies: HashMap<String, PolicyDefinition>,
    server_url: Option<String>,
    api_token: Option<String>,
    last_sync: Option<i64>,
    sync_interval_seconds: u64,
}

impl PolicyManager {
    pub fn new() -> Self {
        let mut manager = Self {
            policies: HashMap::new(),
            server_url: None,
            api_token: None,
            last_sync: None,
            sync_interval_seconds: 300,
        };

        // Add default policies
        manager.add_default_policies();
        manager
    }

    /// Add default built-in policies
    fn add_default_policies(&mut self) {
        // Critical severity policy
        let critical_policy = PolicyDefinition {
            id: "default_critical".to_string(),
            name: "Critical Threat Response".to_string(),
            description: "Automatic response for critical threats".to_string(),
            version: 1,
            enabled: true,
            priority: 100,
            rules: vec![
                PolicyRule {
                    id: "crit_1".to_string(),
                    name: "Kill on LSASS dump".to_string(),
                    condition: PolicyCondition {
                        condition_type: "mitre".to_string(),
                        operator: "equals".to_string(),
                        value: serde_json::json!("T1003.001"),
                    },
                    actions: vec![
                        PolicyAction::Alert { severity: "critical".to_string() },
                        PolicyAction::Block,
                        PolicyAction::Quarantine,
                    ],
                    enabled: true,
                },
            ],
            created_at: Utc::now().timestamp(),
            updated_at: Utc::now().timestamp(),
            created_by: "system".to_string(),
        };

        // High severity policy
        let high_policy = PolicyDefinition {
            id: "default_high".to_string(),
            name: "High Threat Alert".to_string(),
            description: "Alert on high severity threats".to_string(),
            version: 1,
            enabled: true,
            priority: 90,
            rules: vec![
                PolicyRule {
                    id: "high_1".to_string(),
                    name: "Alert on suspicious spawn".to_string(),
                    condition: PolicyCondition {
                        condition_type: "severity".to_string(),
                        operator: "gte".to_string(),
                        value: serde_json::json!("high"),
                    },
                    actions: vec![
                        PolicyAction::Alert { severity: "high".to_string() },
                        PolicyAction::Log,
                        PolicyAction::Notify { channels: vec!["security".to_string()] },
                    ],
                    enabled: true,
                },
            ],
            created_at: Utc::now().timestamp(),
            updated_at: Utc::now().timestamp(),
            created_by: "system".to_string(),
        };

        // Beaconing detection policy
        let beacon_policy = PolicyDefinition {
            id: "default_beacon".to_string(),
            name: "C2 Beaconing Detection".to_string(),
            description: "Detect and alert on C2 beaconing".to_string(),
            version: 1,
            enabled: true,
            priority: 80,
            rules: vec![
                PolicyRule {
                    id: "beacon_1".to_string(),
                    name: "Block on beaconing".to_string(),
                    condition: PolicyCondition {
                        condition_type: "detection".to_string(),
                        operator: "equals".to_string(),
                        value: serde_json::json!("beaconing"),
                    },
                    actions: vec![
                        PolicyAction::Alert { severity: "high".to_string() },
                        PolicyAction::Block,
                    ],
                    enabled: true,
                },
            ],
            created_at: Utc::now().timestamp(),
            updated_at: Utc::now().timestamp(),
            created_by: "system".to_string(),
        };

        self.policies.insert(critical_policy.id.clone(), critical_policy);
        self.policies.insert(high_policy.id.clone(), high_policy);
        self.policies.insert(beacon_policy.id.clone(), beacon_policy);
    }

    /// Configure server connection
    pub fn configure(&mut self, server_url: &str, token: &str) {
        self.server_url = Some(server_url.to_string());
        self.api_token = Some(token.to_string());
    }

    /// Sync policies from server
    pub fn sync(&mut self) -> Result<SyncResult, PolicyError> {
        let server_url = self.server_url.as_ref()
            .ok_or(PolicyError::NotConfigured)?;
        let token = self.api_token.as_ref()
            .ok_or(PolicyError::NotConfigured)?;

        let url = format!("{}/api/v1/policies", server_url);

        let response = ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .call();

        match response {
            Ok(resp) => {
                let body = resp.into_string()
                    .map_err(|e| PolicyError::ParseError(e.to_string()))?;

                let policies: Vec<PolicyDefinition> = serde_json::from_str(&body)
                    .map_err(|e| PolicyError::ParseError(e.to_string()))?;

                let mut added = 0;
                let mut updated = 0;

                for policy in policies {
                    if let Some(existing) = self.policies.get(&policy.id) {
                        if policy.version > existing.version {
                            self.policies.insert(policy.id.clone(), policy);
                            updated += 1;
                        }
                    } else {
                        self.policies.insert(policy.id.clone(), policy);
                        added += 1;
                    }
                }

                self.last_sync = Some(Utc::now().timestamp());

                log::info!("Policy sync complete: {} added, {} updated", added, updated);

                Ok(SyncResult {
                    success: true,
                    added,
                    updated,
                    total: self.policies.len(),
                })
            }
            Err(e) => Err(PolicyError::NetworkError(e.to_string())),
        }
    }

    /// Get all active policies
    pub fn get_active(&self) -> Vec<PolicyDefinition> {
        self.policies.values()
            .filter(|p| p.enabled)
            .cloned()
            .collect()
    }

    /// Get policy by ID
    pub fn get(&self, id: &str) -> Option<PolicyDefinition> {
        self.policies.get(id).cloned()
    }

    /// Add or update a policy
    pub fn add_policy(&mut self, policy: PolicyDefinition) {
        self.policies.insert(policy.id.clone(), policy);
    }

    /// Remove a policy
    pub fn remove_policy(&mut self, id: &str) -> bool {
        self.policies.remove(id).is_some()
    }

    /// Enable/disable a policy
    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<(), PolicyError> {
        let policy = self.policies.get_mut(id)
            .ok_or(PolicyError::NotFound)?;
        policy.enabled = enabled;
        Ok(())
    }

    /// Evaluate policies against a context
    pub fn evaluate(&self, context: &PolicyContext) -> Vec<PolicyMatch> {
        let mut matches = Vec::new();

        let mut policies: Vec<_> = self.policies.values()
            .filter(|p| p.enabled)
            .collect();

        // Sort by priority (highest first)
        policies.sort_by(|a, b| b.priority.cmp(&a.priority));

        for policy in policies {
            for rule in &policy.rules {
                if !rule.enabled {
                    continue;
                }

                if self.evaluate_condition(&rule.condition, context) {
                    matches.push(PolicyMatch {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        actions: rule.actions.clone(),
                    });
                }
            }
        }

        matches
    }

    /// Evaluate a single condition
    fn evaluate_condition(&self, condition: &PolicyCondition, context: &PolicyContext) -> bool {
        match condition.condition_type.as_str() {
            "severity" => {
                if let Some(ref severity) = context.severity {
                    let target = condition.value.as_str().unwrap_or("");
                    match condition.operator.as_str() {
                        "equals" => severity == target,
                        "gte" => severity_to_num(severity) >= severity_to_num(target),
                        "gt" => severity_to_num(severity) > severity_to_num(target),
                        _ => false,
                    }
                } else {
                    false
                }
            }
            "mitre" => {
                if let Some(ref techniques) = context.mitre_techniques {
                    let target = condition.value.as_str().unwrap_or("");
                    techniques.contains(&target.to_string())
                } else {
                    false
                }
            }
            "detection" => {
                if let Some(ref detection) = context.detection_type {
                    let target = condition.value.as_str().unwrap_or("");
                    detection == target
                } else {
                    false
                }
            }
            "process" => {
                if let Some(ref name) = context.process_name {
                    let target = condition.value.as_str().unwrap_or("");
                    match condition.operator.as_str() {
                        "equals" => name.to_lowercase() == target.to_lowercase(),
                        "contains" => name.to_lowercase().contains(&target.to_lowercase()),
                        _ => false,
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Get stats
    pub fn stats(&self) -> PolicyStats {
        PolicyStats {
            total_policies: self.policies.len(),
            enabled_policies: self.policies.values().filter(|p| p.enabled).count(),
            total_rules: self.policies.values().map(|p| p.rules.len()).sum(),
            last_sync: self.last_sync,
        }
    }
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TYPES
// ============================================================================

/// Context for policy evaluation
#[derive(Debug, Clone, Default)]
pub struct PolicyContext {
    pub severity: Option<String>,
    pub mitre_techniques: Option<Vec<String>>,
    pub detection_type: Option<String>,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub file_path: Option<String>,
    pub extra: HashMap<String, String>,
}

/// Policy match result
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyMatch {
    pub policy_id: String,
    pub policy_name: String,
    pub rule_id: String,
    pub rule_name: String,
    pub actions: Vec<PolicyAction>,
}

/// Sync result
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncResult {
    pub success: bool,
    pub added: usize,
    pub updated: usize,
    pub total: usize,
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum PolicyError {
    NotConfigured,
    NotFound,
    NetworkError(String),
    ParseError(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::NotConfigured => write!(f, "Server not configured"),
            PolicyError::NotFound => write!(f, "Policy not found"),
            PolicyError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            PolicyError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for PolicyError {}

// ============================================================================
// UTILITIES
// ============================================================================

fn severity_to_num(s: &str) -> i32 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        "info" => 0,
        _ => -1,
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Configure server connection
pub fn configure(server_url: &str, token: &str) {
    POLICY_MANAGER.write().configure(server_url, token);
}

/// Sync policies from server
pub fn sync_policies() -> Result<SyncResult, PolicyError> {
    POLICY_MANAGER.write().sync()
}

/// Get all active policies
pub fn get_active_policies() -> Vec<PolicyDefinition> {
    POLICY_MANAGER.read().get_active()
}

/// Get policy by ID
pub fn get_policy(id: &str) -> Option<PolicyDefinition> {
    POLICY_MANAGER.read().get(id)
}

/// Add a policy
pub fn add_policy(policy: PolicyDefinition) {
    POLICY_MANAGER.write().add_policy(policy);
}

/// Apply policy evaluation
pub fn apply_policy(context: &PolicyContext) -> Vec<PolicyMatch> {
    POLICY_MANAGER.read().evaluate(context)
}

/// Enable/disable policy
pub fn set_policy_enabled(id: &str, enabled: bool) -> Result<(), PolicyError> {
    POLICY_MANAGER.write().set_enabled(id, enabled)
}

/// Get stats
pub fn get_stats() -> PolicyStats {
    POLICY_MANAGER.read().stats()
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyStats {
    pub total_policies: usize,
    pub enabled_policies: usize,
    pub total_rules: usize,
    pub last_sync: Option<i64>,
}
