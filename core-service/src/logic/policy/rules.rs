//! Policy Rules (Extensible)
//!
//! Rule-based policy overrides.
//! Cho phép thêm rules custom mà không sửa core logic.

use super::types::*;
use crate::logic::threat::ClassificationResult;

// ============================================================================
// POLICY RULE TRAIT
// ============================================================================

/// Rule-based policy override
pub trait PolicyRule: Send + Sync {
    fn name(&self) -> &str;
    fn applies(&self, classification: &ClassificationResult) -> bool;
    fn override_decision(&self, current: &PolicyResult) -> Option<PolicyResult>;
}

// ============================================================================
// BUILT-IN RULES
// ============================================================================

/// Always require approval for crypto-mining patterns
pub struct CryptoMiningRule;

impl PolicyRule for CryptoMiningRule {
    fn name(&self) -> &str {
        "CryptoMiningRule"
    }

    fn applies(&self, classification: &ClassificationResult) -> bool {
        classification.reasons.iter().any(|r| r.contains("CRYPTO"))
    }

    fn override_decision(&self, _current: &PolicyResult) -> Option<PolicyResult> {
        Some(PolicyResult {
            decision: Decision::RequireApproval,
            severity: Severity::High,
            action: ActionType::KillProcess,
            reasons: vec!["Crypto-mining pattern detected".to_string()],
            auto_execute: false,
            expires_in_secs: Some(60), // 1 minute timeout
        })
    }
}

/// Block ransomware-like behavior immediately
pub struct RansomwareRule;

impl PolicyRule for RansomwareRule {
    fn name(&self) -> &str {
        "RansomwareRule"
    }

    fn applies(&self, classification: &ClassificationResult) -> bool {
        classification.reasons.iter().any(|r|
            r.contains("RANSOMWARE") || r.contains("ENCRYPT_MASS")
        )
    }

    fn override_decision(&self, _current: &PolicyResult) -> Option<PolicyResult> {
        Some(PolicyResult {
            decision: Decision::AutoBlock,
            severity: Severity::Critical,
            action: ActionType::KillProcess,
            reasons: vec!["Ransomware behavior detected - auto blocking".to_string()],
            auto_execute: true,
            expires_in_secs: None,
        })
    }
}

// ============================================================================
// RULE ENGINE
// ============================================================================

/// Apply rules in order, return first matching override
pub fn apply_rules(
    rules: &[Box<dyn PolicyRule>],
    classification: &ClassificationResult,
    current: &PolicyResult,
) -> PolicyResult {
    for rule in rules {
        if rule.applies(classification) {
            if let Some(overridden) = rule.override_decision(current) {
                return overridden;
            }
        }
    }
    current.clone()
}
