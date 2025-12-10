//! Threat Classifier
//!
//! CHỈ chứa logic classify - không có types, không có policy.
//! Input: AnomalyScore, BaselineDiff, ThreatContext
//! Output: ClassificationResult

use super::types::{
    AnomalyScore, BaselineDiff, ClassificationResult, ScoreBreakdown, ThreatClass,
};
use super::context::ThreatContext;
use super::rules::{ClassificationThresholds, ANOMALY_WEIGHT, BASELINE_WEIGHT, CONTEXT_WEIGHT, WHITELIST_REDUCTION};

// ============================================================================
// MAIN CLASSIFICATION FUNCTION
// ============================================================================

/// Main classification function
///
/// CORE LOGIC - Deterministic and Explainable
pub fn classify(
    anomaly: &AnomalyScore,
    baseline: &BaselineDiff,
    context: &ThreatContext,
) -> ClassificationResult {
    classify_with_thresholds(anomaly, baseline, context, &ClassificationThresholds::default())
}

/// Classification with custom thresholds
pub fn classify_with_thresholds(
    anomaly: &AnomalyScore,
    baseline: &BaselineDiff,
    context: &ThreatContext,
    thresholds: &ClassificationThresholds,
) -> ClassificationResult {
    let mut reasons = Vec::new();

    // Calculate weighted score
    // AI anomaly score = 50% weight
    let anomaly_contribution = anomaly.score * ANOMALY_WEIGHT;

    // Baseline deviation = 30% weight
    let baseline_contribution = baseline.deviation_score.min(1.0) * BASELINE_WEIGHT;

    // Context factors = 20% weight
    let mut context_score = 0.0f32;

    // New process = higher risk
    if context.is_new_process {
        context_score += 0.3;
        reasons.push("New process detected".to_string());
    }

    // Many child processes = suspicious
    if context.child_process_count > 5 {
        context_score += 0.2;
        reasons.push(format!("{} child processes spawned", context.child_process_count));
    }

    // High network activity
    if context.network_bytes_sent > thresholds.high_network_threshold {
        context_score += 0.2;
        reasons.push(format!("High network activity: {} MB", context.network_bytes_sent / 1024 / 1024));
    }

    // Spike behavior
    if baseline.is_spike {
        context_score += 0.2;
        reasons.push("Spike behavior detected".to_string());
    }

    // Tags influence
    for tag in &context.tags {
        match tag.as_str() {
            "CPU_ANOMALY" | "MEMORY_ANOMALY" => context_score += 0.1,
            "NETWORK_BURST" => context_score += 0.15,
            "CRYPTO_PATTERN" => context_score += 0.3,
            _ => context_score += 0.05,
        }
    }

    let context_contribution = context_score.min(1.0) * CONTEXT_WEIGHT;

    // Final weighted score
    let mut final_score = anomaly_contribution + baseline_contribution + context_contribution;

    // Apply multipliers
    if baseline.is_spike {
        final_score *= thresholds.spike_multiplier;
    }
    if context.is_new_process && !context.is_whitelisted {
        final_score *= thresholds.new_process_multiplier;
    }

    // Clamp to 0-1
    final_score = final_score.clamp(0.0, 1.0);

    // Whitelisted processes get reduced score
    if context.is_whitelisted {
        final_score *= WHITELIST_REDUCTION;
        reasons.push("Process is whitelisted (score reduced)".to_string());
    }

    // Calculate confidence first (need for classification)
    let confidence = if final_score < 0.3 || final_score > 0.7 {
        0.9 // High confidence at extremes
    } else {
        0.6 // Lower confidence in middle range
    } * anomaly.confidence;

    // Classify based on thresholds
    // ⚠️ CONFIDENCE GUARD: Malicious requires score >= 0.8 AND confidence >= 0.7
    // This prevents false positives in real-world scenarios
    let threat_class = if final_score < thresholds.benign_max {
        ThreatClass::Benign
    } else if final_score >= thresholds.malicious_min && confidence >= thresholds.malicious_confidence_min {
        // High score + high confidence = Malicious
        ThreatClass::Malicious
    } else if final_score >= thresholds.malicious_min {
        // High score but low confidence = downgrade to Suspicious
        reasons.push(format!("Confidence {:.2} < {:.2}, downgraded to Suspicious", confidence, thresholds.malicious_confidence_min));
        ThreatClass::Suspicious
    } else {
        ThreatClass::Suspicious
    };

    // Add score reason
    reasons.push(format!("Final score: {:.2}, confidence: {:.2}", final_score, confidence));

    ClassificationResult {
        threat_class,
        confidence,
        reasons,
        score_breakdown: ScoreBreakdown {
            anomaly_contribution,
            baseline_contribution,
            context_contribution,
            final_score,
        },
    }
}

/// Quick classify from just anomaly score (for simple cases)
pub fn classify_simple(anomaly_score: f32) -> ThreatClass {
    let thresholds = ClassificationThresholds::default();
    if anomaly_score < thresholds.benign_max {
        ThreatClass::Benign
    } else if anomaly_score >= thresholds.malicious_min {
        ThreatClass::Malicious
    } else {
        ThreatClass::Suspicious
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benign_classification() {
        let anomaly = AnomalyScore {
            score: 0.2,
            confidence: 0.9,
            method: "onnx".to_string(),
        };
        let baseline = BaselineDiff::default();
        let context = ThreatContext::default();

        let result = classify(&anomaly, &baseline, &context);
        assert_eq!(result.threat_class, ThreatClass::Benign);
    }

    #[test]
    fn test_malicious_classification() {
        let anomaly = AnomalyScore {
            score: 1.0,
            confidence: 0.95,
            method: "onnx".to_string(),
        };
        let baseline = BaselineDiff {
            deviation_score: 1.0,
            is_spike: true,
            ..Default::default()
        };
        let context = ThreatContext {
            is_new_process: true,
            child_process_count: 10,
            ..Default::default()
        };

        let result = classify(&anomaly, &baseline, &context);
        assert_eq!(result.threat_class, ThreatClass::Malicious);
    }

    #[test]
    fn test_suspicious_classification() {
        // Need final_score between 0.4 and 0.8
        // 0.9 * 0.5 + 0 * 0.3 + 0 * 0.2 = 0.45 (Suspicious)
        let anomaly = AnomalyScore {
            score: 0.9,  // High enough to reach Suspicious threshold
            confidence: 0.8,
            method: "onnx".to_string(),
        };
        let baseline = BaselineDiff::default();
        let context = ThreatContext::default();

        let result = classify(&anomaly, &baseline, &context);
        assert!(result.score_breakdown.final_score >= 0.4);
        assert!(result.score_breakdown.final_score < 0.8);
        assert_eq!(result.threat_class, ThreatClass::Suspicious);
    }

    #[test]
    fn test_whitelisted_reduces_score() {
        let anomaly = AnomalyScore {
            score: 0.7,
            confidence: 0.9,
            method: "onnx".to_string(),
        };
        let baseline = BaselineDiff::default();
        let context = ThreatContext {
            is_whitelisted: true,
            ..Default::default()
        };

        let result = classify(&anomaly, &baseline, &context);
        // Should be reduced from Suspicious to Benign due to whitelist
        assert_eq!(result.threat_class, ThreatClass::Benign);
    }

    #[test]
    fn test_confidence_guard_prevents_false_positive() {
        // Very HIGH anomaly score but LOW confidence
        let anomaly = AnomalyScore {
            score: 1.0,       // Max anomaly
            confidence: 0.3,  // Very low confidence!
            method: "fallback".to_string(),
        };
        let baseline = BaselineDiff {
            deviation_score: 1.0, // Max deviation
            ..Default::default()
        };
        let context = ThreatContext {
            is_new_process: true, // Add context score
            child_process_count: 10,
            ..Default::default()
        };

        let result = classify(&anomaly, &baseline, &context);
        // Final score >= 0.8 but confidence < 0.7, should be Suspicious
        assert!(result.score_breakdown.final_score >= 0.8);
        assert!(result.confidence < 0.7);
        assert_eq!(result.threat_class, ThreatClass::Suspicious);
        assert!(result.reasons.iter().any(|r| r.contains("downgraded")));
    }

    #[test]
    fn test_high_score_high_confidence_is_malicious() {
        // High score AND high confidence = Malicious
        let anomaly = AnomalyScore {
            score: 1.0,        // Max anomaly
            confidence: 0.95,  // High confidence!
            method: "onnx".to_string(),
        };
        let baseline = BaselineDiff {
            deviation_score: 1.0, // Max deviation
            ..Default::default()
        };
        let context = ThreatContext {
            is_new_process: true,
            child_process_count: 10,
            ..Default::default()
        };

        let result = classify(&anomaly, &baseline, &context);
        // Final score >= 0.8 AND confidence >= 0.7 => Malicious
        assert!(result.score_breakdown.final_score >= 0.8);
        assert!(result.confidence >= 0.7);
        assert_eq!(result.threat_class, ThreatClass::Malicious);
    }
}
