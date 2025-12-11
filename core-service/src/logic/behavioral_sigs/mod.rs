//! Behavioral Signatures Module - Hardcoded Detection Rules (Phase 3)
//!
//! Mục đích: Hardcoded rules cho các hành vi KHÔNG BAO GIỜ chấp nhận, bất kể ML score.
//!
//! # Components
//! - `beaconing.rs`: Phát hiện C2 beaconing patterns
//! - `persistence.rs`: Monitor registry persistence locations
//! - `never_learn.rs`: Blacklist patterns không bao giờ học
//! - `rules.rs`: Custom behavioral rules engine

// Allow unused for now - will be fully integrated in future phases
#![allow(unused)]

pub mod beaconing;
pub mod persistence;
pub mod never_learn;
pub mod rules;
pub mod types;

// Re-exports from types
pub use types::{
    BeaconAlert, BeaconSeverity, PersistenceAlert, PersistenceMechanism, PersistenceSeverity,
    BehavioralRuleDefinition, RuleCondition, RuleAction, RuleSeverity, RuleMatch, MatchContext,
    NeverLearnReason, SampleContext,
};

// Re-exports from submodules
pub use beaconing::{BeaconingDetector, check_beaconing, record_connection, get_all_beacons};
pub use persistence::{PersistenceMonitor, PERSISTENCE_KEYS, record_registry_write, is_persistence_key};
pub use never_learn::{NeverLearnBlacklist, should_never_learn, is_process_blacklisted};
pub use rules::{RuleEngine, evaluate, add_rule, get_matches, get_all_rules};
