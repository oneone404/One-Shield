//! Policy Module
//!
//! Quyết định action dựa trên ThreatClass và Severity.
//! ĐÂY là nơi làm Security - không phải AI, không phải UI.
//!
//! ## Structure
//! - `types`: Core types (Decision, Severity, ActionType, PolicyResult)
//! - `config`: Policy configuration
//! - `engine`: Decision logic
//! - `rules`: Extensible policy rules
//!
//! ## Usage
//! ```ignore
//! use crate::logic::policy::{decide, PolicyConfig};
//! use crate::logic::threat::ClassificationResult;
//!
//! let result = decide(&classification);
//! match result.decision {
//!     Decision::SilentLog => log_only(),
//!     Decision::Notify => show_notification(),
//!     Decision::RequireApproval => await_user_approval(),
//!     Decision::AutoBlock => execute_block(),
//! }
//! ```

pub mod types;
pub mod config;
pub mod engine;
pub mod rules;

// Re-export main types for convenience
pub use types::{
    Decision,
    Severity,
    ActionType,
    PolicyResult,
};

pub use config::PolicyConfig;

pub use engine::{decide, decide_with_config, decide_simple, get_recommended_action};

pub use rules::{PolicyRule, CryptoMiningRule, RansomwareRule, apply_rules};
