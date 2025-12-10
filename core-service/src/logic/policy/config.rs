//! Policy Configuration
//!
//! Configuration for policy decisions.
//! Can be loaded from config file or set at runtime.

use serde::{Deserialize, Serialize};
use super::types::ActionType;

// ============================================================================
// POLICY CONFIG
// ============================================================================

/// Policy configuration (can be loaded from config file)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Auto-block threats above this score
    pub auto_block_threshold: f32,
    /// Always require approval for these action types
    pub require_approval_actions: Vec<ActionType>,
    /// Timeout for approval requests (seconds)
    pub approval_timeout_secs: u64,
    /// Enable auto-block (if false, always require approval)
    pub enable_auto_block: bool,
    /// Silent log for benign threats
    pub silent_benign: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            auto_block_threshold: 0.95,
            require_approval_actions: vec![
                ActionType::KillProcess,
                ActionType::IsolateSession,
            ],
            approval_timeout_secs: 300, // 5 minutes
            enable_auto_block: false,   // Default: require approval
            silent_benign: true,
        }
    }
}

impl PolicyConfig {
    /// Strict mode - always require approval, no auto-block
    pub fn strict() -> Self {
        Self {
            enable_auto_block: false,
            auto_block_threshold: 1.0, // Never auto-block
            ..Default::default()
        }
    }

    /// Aggressive mode - auto-block high threats
    pub fn aggressive() -> Self {
        Self {
            enable_auto_block: true,
            auto_block_threshold: 0.9,
            silent_benign: true,
            ..Default::default()
        }
    }

    /// Check if action requires approval
    pub fn requires_approval(&self, action: &ActionType) -> bool {
        self.require_approval_actions.contains(action)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PolicyConfig::default();
        assert!(!config.enable_auto_block);
        assert_eq!(config.auto_block_threshold, 0.95);
        assert!(config.silent_benign);
    }

    #[test]
    fn test_strict_config() {
        let config = PolicyConfig::strict();
        assert!(!config.enable_auto_block);
        assert_eq!(config.auto_block_threshold, 1.0);
    }

    #[test]
    fn test_aggressive_config() {
        let config = PolicyConfig::aggressive();
        assert!(config.enable_auto_block);
        assert_eq!(config.auto_block_threshold, 0.9);
    }
}
