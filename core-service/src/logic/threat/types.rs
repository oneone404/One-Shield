//! Threat Types
//!
//! Core types cho threat classification.
//! KHÔNG chứa logic - chỉ data structures.

use serde::{Deserialize, Serialize};

// ============================================================================
// THREAT CLASSIFICATION
// ============================================================================

/// Threat classification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatClass {
    /// Hành vi bình thường, không cần action
    Benign,
    /// Đáng ngờ, cần monitor thêm hoặc notify
    Suspicious,
    /// Nguy hiểm, cần action ngay
    Malicious,
}

impl ThreatClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatClass::Benign => "benign",
            ThreatClass::Suspicious => "suspicious",
            ThreatClass::Malicious => "malicious",
        }
    }

    pub fn severity_level(&self) -> u8 {
        match self {
            ThreatClass::Benign => 0,
            ThreatClass::Suspicious => 1,
            ThreatClass::Malicious => 2,
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            ThreatClass::Benign => "#10b981",    // Green
            ThreatClass::Suspicious => "#f59e0b", // Yellow
            ThreatClass::Malicious => "#ef4444",  // Red
        }
    }
}

impl std::fmt::Display for ThreatClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// ANOMALY SCORE (from AI)
// ============================================================================

/// Score từ AI inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    /// Raw anomaly score (0.0 - 1.0)
    pub score: f32,
    /// Confidence of the prediction
    pub confidence: f32,
    /// Method used (onnx, fallback)
    pub method: String,
}

impl Default for AnomalyScore {
    fn default() -> Self {
        Self {
            score: 0.0,
            confidence: 0.5,
            method: "unknown".to_string(),
        }
    }
}

// ============================================================================
// BASELINE DIFF (from Baseline Engine)
// ============================================================================

/// Deviation từ baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDiff {
    /// How much it deviates from normal (0.0 - 1.0+)
    pub deviation_score: f32,
    /// How long the deviation has been happening (seconds)
    pub duration_secs: u64,
    /// Which features are deviating
    pub deviating_features: Vec<String>,
    /// Is this a spike (sudden change)?
    pub is_spike: bool,
}

impl Default for BaselineDiff {
    fn default() -> Self {
        Self {
            deviation_score: 0.0,
            duration_secs: 0,
            deviating_features: vec![],
            is_spike: false,
        }
    }
}

// ============================================================================
// SCORE BREAKDOWN
// ============================================================================

/// Breakdown of how final score was calculated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub anomaly_contribution: f32,
    pub baseline_contribution: f32,
    pub context_contribution: f32,
    pub final_score: f32,
}

impl Default for ScoreBreakdown {
    fn default() -> Self {
        Self {
            anomaly_contribution: 0.0,
            baseline_contribution: 0.0,
            context_contribution: 0.0,
            final_score: 0.0,
        }
    }
}

// ============================================================================
// CLASSIFICATION RESULT
// ============================================================================

/// Result of threat classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub threat_class: ThreatClass,
    pub confidence: f32,
    pub reasons: Vec<String>,
    pub score_breakdown: ScoreBreakdown,
}

impl Default for ClassificationResult {
    fn default() -> Self {
        Self {
            threat_class: ThreatClass::Benign,
            confidence: 0.5,
            reasons: vec![],
            score_breakdown: ScoreBreakdown::default(),
        }
    }
}
