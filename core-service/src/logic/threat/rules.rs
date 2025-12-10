//! Threat Classification Rules & Thresholds
//!
//! Định nghĩa các threshold cho phân loại threat.
//! KHÔNG chứa logic classify - chỉ constants và config.

use serde::{Deserialize, Serialize};

// ============================================================================
// THRESHOLDS (Constants - không đổi lúc runtime)
// ============================================================================

/// Below this score = Benign
pub const BENIGN_THRESHOLD: f32 = 0.4;

/// At or above this score = Malicious (if confidence also high)
pub const MALICIOUS_THRESHOLD: f32 = 0.8;

/// Minimum confidence required for Malicious classification
/// This is the CONFIDENCE GUARD - prevents false positives
pub const MALICIOUS_CONFIDENCE_MIN: f32 = 0.7;

// ============================================================================
// WEIGHTS (How much each component contributes to final score)
// ============================================================================

/// Weight of AI anomaly score (50%)
pub const ANOMALY_WEIGHT: f32 = 0.5;

/// Weight of baseline deviation (30%)
pub const BASELINE_WEIGHT: f32 = 0.3;

/// Weight of context factors (20%)
pub const CONTEXT_WEIGHT: f32 = 0.2;

// ============================================================================
// MULTIPLIERS
// ============================================================================

/// Score multiplier when spike behavior detected
pub const SPIKE_MULTIPLIER: f32 = 1.2;

/// Score multiplier for new processes (unknown baseline)
pub const NEW_PROCESS_MULTIPLIER: f32 = 1.1;

/// Score reduction for whitelisted processes
pub const WHITELIST_REDUCTION: f32 = 0.5;

// ============================================================================
// NETWORK THRESHOLDS
// ============================================================================

/// High network activity threshold (bytes per minute)
pub const HIGH_NETWORK_THRESHOLD: u64 = 10 * 1024 * 1024; // 10 MB/min

// ============================================================================
// CONFIGURABLE THRESHOLDS (for runtime adjustment)
// ============================================================================

/// Thresholds for classification (configurable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationThresholds {
    /// Below this = Benign
    pub benign_max: f32,
    /// Above this = Malicious, between = Suspicious
    pub malicious_min: f32,
    /// Minimum confidence for Malicious
    pub malicious_confidence_min: f32,
    /// Multiplier for spike behavior
    pub spike_multiplier: f32,
    /// Multiplier for new process
    pub new_process_multiplier: f32,
    /// Threshold for high network activity (bytes/min)
    pub high_network_threshold: u64,
}

impl Default for ClassificationThresholds {
    fn default() -> Self {
        Self {
            benign_max: BENIGN_THRESHOLD,
            malicious_min: MALICIOUS_THRESHOLD,
            malicious_confidence_min: MALICIOUS_CONFIDENCE_MIN,
            spike_multiplier: SPIKE_MULTIPLIER,
            new_process_multiplier: NEW_PROCESS_MULTIPLIER,
            high_network_threshold: HIGH_NETWORK_THRESHOLD,
        }
    }
}

impl ClassificationThresholds {
    /// High sensitivity - lower thresholds, more alerts
    pub fn high_sensitivity() -> Self {
        Self {
            benign_max: 0.3,
            malicious_min: 0.7,
            malicious_confidence_min: 0.6,
            ..Default::default()
        }
    }

    /// Low sensitivity - higher thresholds, fewer alerts
    pub fn low_sensitivity() -> Self {
        Self {
            benign_max: 0.5,
            malicious_min: 0.9,
            malicious_confidence_min: 0.8,
            ..Default::default()
        }
    }
}
