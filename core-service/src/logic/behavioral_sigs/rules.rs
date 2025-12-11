//! Behavioral Rules Engine Module (Phase 3)
//!
//! Mục đích: Custom behavioral detection rules
//!
//! Features:
//! - YARA-like pattern matching
//! - Condition-based rules
//! - Custom severity and actions

use std::collections::HashMap;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use chrono::Utc;
use regex::Regex;

use super::types::{
    BehavioralRuleDefinition, RuleCondition, RuleAction, RuleSeverity,
    RuleMatch, MatchContext, SampleContext,
};

// ============================================================================
// STATE
// ============================================================================

static ENGINE: Lazy<RwLock<RuleEngine>> =
    Lazy::new(|| RwLock::new(RuleEngine::new()));

// ============================================================================
// BUILT-IN RULES
// ============================================================================

fn get_builtin_rules() -> Vec<BehavioralRuleDefinition> {
    vec![
        // Rule 1: Office spawning shell
        BehavioralRuleDefinition {
            id: "OFFICE_SHELL".to_string(),
            name: "Office Application Spawning Shell".to_string(),
            description: "Detects Office applications spawning command shells".to_string(),
            enabled: true,
            severity: RuleSeverity::High,
            mitre_technique: Some("T1059".to_string()),
            conditions: vec![
                RuleCondition::Or(vec![
                    RuleCondition::ParentProcessName {
                        pattern: "winword.exe".to_string(),
                        is_regex: false
                    },
                    RuleCondition::ParentProcessName {
                        pattern: "excel.exe".to_string(),
                        is_regex: false
                    },
                    RuleCondition::ParentProcessName {
                        pattern: "powerpnt.exe".to_string(),
                        is_regex: false
                    },
                ]),
                RuleCondition::Or(vec![
                    RuleCondition::ProcessName {
                        pattern: "cmd.exe".to_string(),
                        is_regex: false
                    },
                    RuleCondition::ProcessName {
                        pattern: "powershell.exe".to_string(),
                        is_regex: false
                    },
                ]),
            ],
            action: RuleAction::Alert,
        },

        // Rule 2: Encoded PowerShell
        BehavioralRuleDefinition {
            id: "ENCODED_PS".to_string(),
            name: "Encoded PowerShell Execution".to_string(),
            description: "Detects PowerShell running with encoded commands".to_string(),
            enabled: true,
            severity: RuleSeverity::High,
            mitre_technique: Some("T1059.001".to_string()),
            conditions: vec![
                RuleCondition::ProcessName {
                    pattern: "powershell.exe".to_string(),
                    is_regex: false
                },
                RuleCondition::ProcessCmdline {
                    pattern: r"(?i)-enc|-encodedcommand".to_string(),
                    is_regex: true
                },
            ],
            action: RuleAction::Alert,
        },

        // Rule 3: Suspicious network + high CPU
        BehavioralRuleDefinition {
            id: "CRYPTO_MINER".to_string(),
            name: "Potential Cryptominer".to_string(),
            description: "High CPU with network activity (potential miner)".to_string(),
            enabled: true,
            severity: RuleSeverity::Medium,
            mitre_technique: Some("T1496".to_string()),
            conditions: vec![
                RuleCondition::CpuUsageAbove { threshold: 70.0 },
                RuleCondition::NetworkBytes { min_bytes: 1000 },
            ],
            action: RuleAction::Alert,
        },

        // Rule 4: LSASS memory dump
        BehavioralRuleDefinition {
            id: "LSASS_DUMP".to_string(),
            name: "LSASS Memory Dump Attempt".to_string(),
            description: "Detects tools that dump LSASS memory".to_string(),
            enabled: true,
            severity: RuleSeverity::Critical,
            mitre_technique: Some("T1003.001".to_string()),
            conditions: vec![
                RuleCondition::Or(vec![
                    RuleCondition::ProcessName {
                        pattern: "procdump.exe".to_string(),
                        is_regex: false
                    },
                    RuleCondition::ProcessName {
                        pattern: "mimikatz.exe".to_string(),
                        is_regex: false
                    },
                    RuleCondition::ProcessCmdline {
                        pattern: r"(?i)lsass".to_string(),
                        is_regex: true
                    },
                ]),
            ],
            action: RuleAction::NeverLearn,
        },

        // Rule 5: Suspicious temp execution
        BehavioralRuleDefinition {
            id: "TEMP_EXEC".to_string(),
            name: "Execution from Temp Directory".to_string(),
            description: "Executable running from temp directory".to_string(),
            enabled: true,
            severity: RuleSeverity::Low,
            mitre_technique: Some("T1204".to_string()),
            conditions: vec![
                RuleCondition::ProcessPath {
                    pattern: r"(?i)\\temp\\".to_string(),
                    is_regex: true
                },
                RuleCondition::ProcessUnsigned,
            ],
            action: RuleAction::Alert,
        },

        // Rule 6: Certutil download
        BehavioralRuleDefinition {
            id: "CERTUTIL_DL".to_string(),
            name: "Certutil File Download".to_string(),
            description: "Certutil used to download file (LOLBin abuse)".to_string(),
            enabled: true,
            severity: RuleSeverity::High,
            mitre_technique: Some("T1105".to_string()),
            conditions: vec![
                RuleCondition::ProcessName {
                    pattern: "certutil.exe".to_string(),
                    is_regex: false
                },
                RuleCondition::ProcessCmdline {
                    pattern: r"(?i)-urlcache|-split".to_string(),
                    is_regex: true
                },
            ],
            action: RuleAction::Alert,
        },
    ]
}

// ============================================================================
// RULE ENGINE
// ============================================================================

pub struct RuleEngine {
    /// All rules (built-in + custom)
    rules: HashMap<String, BehavioralRuleDefinition>,

    /// Rule matches history
    matches: Vec<RuleMatch>,

    /// Max matches to keep
    max_matches: usize,

    /// Enabled
    enabled: bool,

    /// Compiled regexes cache
    regex_cache: HashMap<String, Regex>,
}

impl RuleEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: HashMap::new(),
            matches: Vec::new(),
            max_matches: 1000,
            enabled: true,
            regex_cache: HashMap::new(),
        };

        // Load built-in rules
        for rule in get_builtin_rules() {
            engine.rules.insert(rule.id.clone(), rule);
        }

        engine
    }

    /// Evaluate all rules against a sample
    pub fn evaluate(&mut self, ctx: &SampleContext) -> Vec<RuleMatch> {
        if !self.enabled {
            return Vec::new();
        }

        let mut results = Vec::new();

        // Clone rules to avoid borrow conflict with regex_cache
        let rules: Vec<_> = self.rules.values().cloned().collect();

        for rule in rules {
            if !rule.enabled {
                continue;
            }

            if let Some(matched_conditions) = self.evaluate_conditions(&rule.conditions, ctx) {
                let rule_match = RuleMatch {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    mitre_technique: rule.mitre_technique.clone(),
                    matched_conditions,
                    context: MatchContext {
                        process_name: ctx.process_name.clone(),
                        process_pid: ctx.process_pid,
                        process_path: ctx.process_path.clone(),
                        parent_process_name: ctx.parent_name.clone(),
                        parent_pid: ctx.parent_pid,
                        extra: HashMap::new(),
                    },
                    timestamp: Utc::now().timestamp(),
                    action: rule.action.clone(),
                };

                results.push(rule_match.clone());
                self.matches.push(rule_match);
            }
        }

        // Trim if needed
        let current_len = self.matches.len();
        if current_len > self.max_matches {
            self.matches.drain(0..current_len - self.max_matches);
        }

        results
    }

    /// Evaluate conditions recursively
    fn evaluate_conditions(&mut self, conditions: &[RuleCondition], ctx: &SampleContext) -> Option<Vec<String>> {
        let mut matched = Vec::new();

        for condition in conditions {
            match self.evaluate_single_condition(condition, ctx) {
                Some(desc) => matched.push(desc),
                None => return None, // All conditions must match (AND)
            }
        }

        if matched.is_empty() {
            None
        } else {
            Some(matched)
        }
    }

    /// Evaluate a single condition
    fn evaluate_single_condition(&mut self, condition: &RuleCondition, ctx: &SampleContext) -> Option<String> {
        match condition {
            RuleCondition::ProcessName { pattern, is_regex } => {
                let name = ctx.process_name.as_ref()?;
                if self.matches_pattern(name, pattern, *is_regex) {
                    Some(format!("ProcessName matches '{}'", pattern))
                } else {
                    None
                }
            }

            RuleCondition::ProcessPath { pattern, is_regex } => {
                let path = ctx.process_path.as_ref()?.to_string_lossy();
                if self.matches_pattern(&path, pattern, *is_regex) {
                    Some(format!("ProcessPath matches '{}'", pattern))
                } else {
                    None
                }
            }

            RuleCondition::ProcessCmdline { pattern, is_regex } => {
                let cmdline = ctx.process_cmdline.as_ref()?;
                if self.matches_pattern(cmdline, pattern, *is_regex) {
                    Some(format!("ProcessCmdline matches '{}'", pattern))
                } else {
                    None
                }
            }

            RuleCondition::ParentProcessName { pattern, is_regex } => {
                let name = ctx.parent_name.as_ref()?;
                if self.matches_pattern(name, pattern, *is_regex) {
                    Some(format!("ParentProcessName matches '{}'", pattern))
                } else {
                    None
                }
            }

            RuleCondition::ProcessUnsigned => {
                if matches!(ctx.process_signed, Some(false)) {
                    Some("Process is unsigned".to_string())
                } else {
                    None
                }
            }

            RuleCondition::NetworkConnection { dest_pattern } => {
                if ctx.network_destinations.iter().any(|d| d.contains(dest_pattern)) {
                    Some(format!("Network connection to '{}'", dest_pattern))
                } else {
                    None
                }
            }

            RuleCondition::NetworkPort { port } => {
                // Would need port info in context
                None
            }

            RuleCondition::NetworkBytes { min_bytes } => {
                let total = ctx.network_bytes_sent + ctx.network_bytes_recv;
                if total >= *min_bytes {
                    Some(format!("Network bytes {} >= {}", total, min_bytes))
                } else {
                    None
                }
            }

            RuleCondition::CpuUsageAbove { threshold } => {
                if ctx.cpu_usage >= *threshold {
                    Some(format!("CPU usage {:.1}% >= {:.1}%", ctx.cpu_usage, threshold))
                } else {
                    None
                }
            }

            RuleCondition::MemoryUsageAbove { threshold } => {
                if ctx.memory_usage >= *threshold {
                    Some(format!("Memory usage {:.1}% >= {:.1}%", ctx.memory_usage, threshold))
                } else {
                    None
                }
            }

            RuleCondition::NetworkRateAbove { threshold } => {
                if ctx.network_rate >= *threshold {
                    Some(format!("Network rate {:.1} >= {:.1}", ctx.network_rate, threshold))
                } else {
                    None
                }
            }

            RuleCondition::RegistryWrite { key_pattern } => {
                if ctx.registry_writes.iter().any(|k| k.contains(key_pattern)) {
                    Some(format!("Registry write to '{}'", key_pattern))
                } else {
                    None
                }
            }

            RuleCondition::FileWrite { path_pattern } => {
                if ctx.files_written.iter().any(|p| p.to_string_lossy().contains(path_pattern)) {
                    Some(format!("File write to '{}'", path_pattern))
                } else {
                    None
                }
            }

            RuleCondition::And(sub_conditions) => {
                self.evaluate_conditions(sub_conditions, ctx)
                    .map(|_| "AND condition matched".to_string())
            }

            RuleCondition::Or(sub_conditions) => {
                for sub in sub_conditions {
                    if self.evaluate_single_condition(sub, ctx).is_some() {
                        return Some("OR condition matched".to_string());
                    }
                }
                None
            }

            RuleCondition::Not(sub_condition) => {
                if self.evaluate_single_condition(sub_condition, ctx).is_none() {
                    Some("NOT condition matched".to_string())
                } else {
                    None
                }
            }

            _ => None,
        }
    }

    /// Match string against pattern (literal or regex)
    fn matches_pattern(&mut self, text: &str, pattern: &str, is_regex: bool) -> bool {
        if is_regex {
            // Get or compile regex
            if !self.regex_cache.contains_key(pattern) {
                if let Ok(re) = Regex::new(pattern) {
                    self.regex_cache.insert(pattern.to_string(), re);
                } else {
                    return false;
                }
            }

            if let Some(re) = self.regex_cache.get(pattern) {
                re.is_match(text)
            } else {
                false
            }
        } else {
            text.to_lowercase().contains(&pattern.to_lowercase())
        }
    }

    /// Add a custom rule
    pub fn add_rule(&mut self, rule: BehavioralRuleDefinition) {
        self.rules.insert(rule.id.clone(), rule);
    }

    /// Remove a rule
    pub fn remove_rule(&mut self, rule_id: &str) {
        self.rules.remove(rule_id);
    }

    /// Enable/disable a rule
    pub fn set_rule_enabled(&mut self, rule_id: &str, enabled: bool) {
        if let Some(rule) = self.rules.get_mut(rule_id) {
            rule.enabled = enabled;
        }
    }

    /// Get recent matches
    pub fn get_matches(&self, limit: usize) -> Vec<RuleMatch> {
        let start = self.matches.len().saturating_sub(limit);
        self.matches[start..].to_vec()
    }

    /// Clear matches
    pub fn clear_matches(&mut self) {
        self.matches.clear();
    }

    /// Enable/disable engine
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Evaluate all rules against a sample
pub fn evaluate(ctx: &SampleContext) -> Vec<RuleMatch> {
    ENGINE.write().evaluate(ctx)
}

/// Add a custom rule
pub fn add_rule(rule: BehavioralRuleDefinition) {
    ENGINE.write().add_rule(rule);
}

/// Remove a rule
pub fn remove_rule(rule_id: &str) {
    ENGINE.write().remove_rule(rule_id);
}

/// Enable/disable a rule
pub fn set_rule_enabled(rule_id: &str, enabled: bool) {
    ENGINE.write().set_rule_enabled(rule_id, enabled);
}

/// Get recent matches
pub fn get_matches(limit: usize) -> Vec<RuleMatch> {
    ENGINE.read().get_matches(limit)
}

/// Clear all matches
pub fn clear_matches() {
    ENGINE.write().clear_matches();
}

/// Enable/disable engine
pub fn set_enabled(enabled: bool) {
    ENGINE.write().set_enabled(enabled);
}

/// Get all rules
pub fn get_all_rules() -> Vec<BehavioralRuleDefinition> {
    ENGINE.read().rules.values().cloned().collect()
}

/// Get a specific rule
pub fn get_rule(rule_id: &str) -> Option<BehavioralRuleDefinition> {
    ENGINE.read().rules.get(rule_id).cloned()
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleEngineStats {
    pub enabled: bool,
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub total_matches: usize,
    pub matches_by_severity: HashMap<String, usize>,
    pub top_triggered_rules: Vec<(String, usize)>,
}

pub fn get_stats() -> RuleEngineStats {
    let engine = ENGINE.read();

    let mut by_severity: HashMap<String, usize> = HashMap::new();
    let mut by_rule: HashMap<String, usize> = HashMap::new();

    for m in &engine.matches {
        *by_severity.entry(m.severity.as_str().to_string()).or_insert(0) += 1;
        *by_rule.entry(m.rule_id.clone()).or_insert(0) += 1;
    }

    let mut top_rules: Vec<_> = by_rule.into_iter().collect();
    top_rules.sort_by(|a, b| b.1.cmp(&a.1));
    top_rules.truncate(10);

    RuleEngineStats {
        enabled: engine.enabled,
        total_rules: engine.rules.len(),
        enabled_rules: engine.rules.values().filter(|r| r.enabled).count(),
        total_matches: engine.matches.len(),
        matches_by_severity: by_severity,
        top_triggered_rules: top_rules,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoded_ps_rule() {
        let mut engine = RuleEngine::new();

        let ctx = SampleContext {
            process_name: Some("powershell.exe".to_string()),
            process_cmdline: Some("powershell.exe -enc SGVsbG8=".to_string()),
            ..Default::default()
        };

        let matches = engine.evaluate(&ctx);
        assert!(matches.iter().any(|m| m.rule_id == "ENCODED_PS"));
    }

    #[test]
    fn test_crypto_miner_rule() {
        let mut engine = RuleEngine::new();

        let ctx = SampleContext {
            process_name: Some("miner.exe".to_string()),
            cpu_usage: 95.0,
            network_bytes_sent: 5000,
            ..Default::default()
        };

        let matches = engine.evaluate(&ctx);
        assert!(matches.iter().any(|m| m.rule_id == "CRYPTO_MINER"));
    }

    #[test]
    fn test_clean_sample() {
        let mut engine = RuleEngine::new();

        let ctx = SampleContext {
            process_name: Some("notepad.exe".to_string()),
            process_cmdline: Some("notepad.exe test.txt".to_string()),
            cpu_usage: 5.0,
            ..Default::default()
        };

        let matches = engine.evaluate(&ctx);
        assert!(matches.is_empty() || matches.iter().all(|m| m.severity <= RuleSeverity::Low));
    }
}
