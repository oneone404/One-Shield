//! Policy Engine
//!
//! CHỈ chứa logic quyết định - không có types definitions.
//! Input: ClassificationResult + PolicyConfig
//! Output: PolicyResult

use crate::logic::threat::{ThreatClass, ClassificationResult};
use super::types::*;
use super::config::PolicyConfig;

// ============================================================================
// MAIN DECISION FUNCTION
// ============================================================================

/// Main policy decision function
pub fn decide(classification: &ClassificationResult) -> PolicyResult {
    decide_with_config(classification, &PolicyConfig::default())
}

/// Policy decision with custom config
pub fn decide_with_config(
    classification: &ClassificationResult,
    config: &PolicyConfig,
) -> PolicyResult {
    let mut result = PolicyResult::default();
    let final_score = classification.score_breakdown.final_score;

    // Set severity based on score
    result.severity = Severity::from_score(final_score);

    match classification.threat_class {
        ThreatClass::Benign => {
            // Benign = log only
            result.decision = if config.silent_benign {
                Decision::SilentLog
            } else {
                Decision::Notify
            };
            result.action = ActionType::None;
            result.reasons.push("Classified as benign".to_string());
        }

        ThreatClass::Suspicious => {
            // Suspicious = notify + optional approval
            result.decision = Decision::Notify;
            result.action = ActionType::AlertOnly;
            result.reasons.push("Classified as suspicious".to_string());

            // If high severity, escalate to require approval
            if result.severity.is_high() {
                result.decision = Decision::RequireApproval;
                result.action = ActionType::SuspendProcess;
                result.expires_in_secs = Some(config.approval_timeout_secs);
                result.reasons.push("High severity - requires approval".to_string());
            }
        }

        ThreatClass::Malicious => {
            // Malicious = require approval or auto-block
            result.action = ActionType::KillProcess;
            result.reasons.push("Classified as malicious".to_string());

            if config.enable_auto_block && final_score >= config.auto_block_threshold {
                result.decision = Decision::AutoBlock;
                result.auto_execute = true;
                result.reasons.push(format!(
                    "Auto-block: score {:.2} >= threshold {:.2}",
                    final_score, config.auto_block_threshold
                ));
            } else {
                result.decision = Decision::RequireApproval;
                result.expires_in_secs = Some(config.approval_timeout_secs);
                result.reasons.push("Requires user approval".to_string());
            }
        }
    }

    // Check if action requires approval regardless of decision
    if config.requires_approval(&result.action) && result.decision == Decision::AutoBlock {
        result.decision = Decision::RequireApproval;
        result.auto_execute = false;
        result.expires_in_secs = Some(config.approval_timeout_secs);
        result.reasons.push("Action type requires approval".to_string());
    }

    result
}

/// Quick decision from just threat class
pub fn decide_simple(threat: ThreatClass) -> Decision {
    match threat {
        ThreatClass::Benign => Decision::SilentLog,
        ThreatClass::Suspicious => Decision::Notify,
        ThreatClass::Malicious => Decision::RequireApproval,
    }
}

/// Get recommended action for threat class
pub fn get_recommended_action(threat: ThreatClass, severity: Severity) -> ActionType {
    match (threat, severity) {
        (ThreatClass::Benign, _) => ActionType::None,
        (ThreatClass::Suspicious, Severity::Low | Severity::Medium) => ActionType::AlertOnly,
        (ThreatClass::Suspicious, Severity::High | Severity::Critical) => ActionType::SuspendProcess,
        (ThreatClass::Malicious, Severity::Low | Severity::Medium) => ActionType::SuspendProcess,
        (ThreatClass::Malicious, Severity::High | Severity::Critical) => ActionType::KillProcess,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logic::threat::ScoreBreakdown;

    fn make_result(threat: ThreatClass, score: f32) -> ClassificationResult {
        ClassificationResult {
            threat_class: threat,
            confidence: 0.9,
            reasons: vec![],
            score_breakdown: ScoreBreakdown {
                anomaly_contribution: score * 0.5,
                baseline_contribution: score * 0.3,
                context_contribution: score * 0.2,
                final_score: score,
            },
        }
    }

    #[test]
    fn test_benign_policy() {
        let result = decide(&make_result(ThreatClass::Benign, 0.2));
        assert_eq!(result.decision, Decision::SilentLog);
        assert_eq!(result.action, ActionType::None);
    }

    #[test]
    fn test_suspicious_policy() {
        let result = decide(&make_result(ThreatClass::Suspicious, 0.5));
        assert_eq!(result.decision, Decision::Notify);
    }

    #[test]
    fn test_malicious_policy() {
        let result = decide(&make_result(ThreatClass::Malicious, 0.9));
        assert_eq!(result.decision, Decision::RequireApproval);
        assert_eq!(result.action, ActionType::KillProcess);
    }

    #[test]
    fn test_auto_block_disabled_by_default() {
        let result = decide(&make_result(ThreatClass::Malicious, 0.99));
        // Auto-block disabled by default, should require approval
        assert_eq!(result.decision, Decision::RequireApproval);
        assert!(!result.auto_execute);
    }

    #[test]
    fn test_auto_block_enabled() {
        let config = PolicyConfig {
            enable_auto_block: true,
            auto_block_threshold: 0.95,
            require_approval_actions: vec![], // Clear so auto-block works
            ..Default::default()
        };
        let result = decide_with_config(
            &make_result(ThreatClass::Malicious, 0.96),
            &config,
        );
        assert_eq!(result.decision, Decision::AutoBlock);
        assert!(result.auto_execute);
    }
}
