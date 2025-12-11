//! Threat Module
//!
//! Phân loại threat dựa trên anomaly score, baseline diff, và context.
//! Đây là CORE STEP - nơi quyết định Benign/Suspicious/Malicious.
//!
//! ## Structure
//! - `types`: Core types (ThreatClass, AnomalyScore, BaselineDiff, etc.)
//! - `context`: Context information for classification
//! - `rules`: Thresholds and constants
//! - `classifier`: Classification logic
//!
//! ## Usage
//! ```ignore
//! use crate::logic::threat::{classify, AnomalyScore, BaselineDiff, ThreatContext};
//!
//! let result = classify(&anomaly, &baseline, &context);
//! match result.threat_class {
//!     ThreatClass::Benign => println!("Safe"),
//!     ThreatClass::Suspicious => println!("Monitor"),
//!     ThreatClass::Malicious => println!("Action needed"),
//! }
//! ```

// Allow unused - some exports for future use
#![allow(unused)]

pub mod types;
pub mod context;
pub mod rules;
pub mod classifier;

// Re-export main types for convenience
pub use types::{
    ThreatClass,
    AnomalyScore,
    BaselineDiff,
    ScoreBreakdown,
    ClassificationResult,
};

pub use context::ThreatContext;

pub use rules::{
    ClassificationThresholds,
    BENIGN_THRESHOLD,
    MALICIOUS_THRESHOLD,
    MALICIOUS_CONFIDENCE_MIN,
};

pub use classifier::{classify, classify_with_thresholds, classify_simple};
