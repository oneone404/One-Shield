//! Baseline Module - Behavioral Analysis Engine (P1.2)
//!
//! Manages versioned baseline profiles and detects anomalies based on
//! deviations from learned behavior.
//!
//! # Architecture
//! - `types.rs`: `VersionedBaseline`, `AnomalyTag`
//! - `validate.rs`: Layout/Version validation
//! - `storage.rs`: Persistent storage with validation
//!
//! # Failure Strategy
//! If baseline version/layout mismatches on load -> Reset baseline safely.

pub mod types;
pub mod validate;
pub mod storage;
#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicU32, Ordering};
use parking_lot::RwLock;
use chrono::{DateTime, Utc, Timelike};

use crate::logic::features::FeatureVector;
use crate::logic::features::layout::FEATURE_COUNT;

pub use types::{
    VersionedBaseline, AnomalyTag, AnalysisResult, TagDetail,
    LegacyBaselineProfile as BaselineProfile // Alias for backward compat
};

// ============================================================================
// CONSTANTS
// ============================================================================

const ANOMALY_THRESHOLD: f32 = 0.6;
const BASELINE_UPDATE_THRESHOLD: f32 = 0.5;
const ML_WEIGHT: f32 = 0.6;
const TAG_WEIGHT: f32 = 0.4;
const OUTLIER_STDS: f32 = 2.0;

// ============================================================================
// STATE
// ============================================================================

static GLOBAL_BASELINE: RwLock<Option<VersionedBaseline>> = RwLock::new(None);
static ANALYSIS_HISTORY: RwLock<Vec<AnalysisResult>> = RwLock::new(Vec::new());
static ANOMALY_COUNT: AtomicU32 = AtomicU32::new(0);

// ============================================================================
// INITIALIZATION & MANAGEMENT
// ============================================================================

/// Initialize baseline engine
/// Loads from disk or creates new if missing/invalid
pub fn init() {
    let mut global = GLOBAL_BASELINE.write();
    if global.is_some() {
        return;
    }

    let path = storage::get_default_baseline_path();
    match storage::load_baseline(&path) {
        Ok(b) => {
            log::info!("Loaded baseline '{}' v{} (hash: {:x}, samples: {})",
                b.name, b.feature_version, b.layout_hash, b.samples);
            *global = Some(b);
        },
        Err(e) => {
            log::warn!("Baseline load failed/invalid: {}. Initializing new baseline.", e);
            let new_b = storage::new_baseline("default");

            // Try to save immediately to ensure directory exists
            if let Err(save_err) = storage::save_baseline(&new_b, &path) {
                log::error!("Failed to save new baseline: {}", save_err);
            }

            *global = Some(new_b);
        }
    }
}

/// Reset baseline to empty state
pub fn reset_baseline() {
    let mut global = GLOBAL_BASELINE.write();
    let new_b = storage::new_baseline("default");

    // Persist reset
    let path = storage::get_default_baseline_path();
    if let Err(e) = storage::save_baseline(&new_b, &path) {
        log::error!("Failed to persist baseline reset: {}", e);
    }

    *global = Some(new_b);
    ANOMALY_COUNT.store(0, Ordering::SeqCst);
    ANALYSIS_HISTORY.write().clear();
    log::info!("Baseline has been definitely reset");
}

/// Get snapshot of global baseline (converted to legacy format for UI)
pub fn get_global_baseline() -> Option<BaselineProfile> {
    init(); // Ensure initialized
    GLOBAL_BASELINE.read().as_ref().map(|b| b.into())
}

/// Get raw versioned baseline (internal use)
pub fn get_versioned_baseline() -> Option<VersionedBaseline> {
    init();
    GLOBAL_BASELINE.read().clone()
}

// ============================================================================
// ANALYSIS ENGINE
// ============================================================================

/// Compare feature vector with baseline and return anomaly tags
pub fn compare_with_baseline(features: &FeatureVector) -> Vec<AnomalyTag> {
    init();

    let global = GLOBAL_BASELINE.read();
    let baseline = match global.as_ref() {
        Some(b) => b,
        None => return vec![],
    };

    if baseline.samples < 10 {
        // Not enough samples to judge
        return vec![];
    }

    let values = features.values;
    let mut tags = Vec::new();

    // Helper for threshold calculation
    let get_threshold = |idx: usize, multiplier: f32| -> f32 {
        baseline.mean[idx] + (OUTLIER_STDS * baseline.variance[idx].sqrt() * multiplier)
    };

    // --- FEATURE CHECKS (Using Layout Indices) ---
    // 0: cpu_percent
    // 1: cpu_spike_rate
    // 2: memory_percent
    // 3: memory_spike_rate
    // 4: network_sent_rate
    // 5: network_recv_rate
    // 6: network_ratio
    // 7: disk_read_rate
    // 8: disk_write_rate
    // 9: combined_io
    // 10: unique_processes
    // 11: new_process_rate
    // 12: process_churn_rate
    // 13: cpu_memory_product
    // 14: spike_correlation

    // 1. CPU
    if values[0] > get_threshold(0, 1.0) {
        tags.push(AnomalyTag::HighCpu);
    }

    // 2. Memory
    if values[2] > get_threshold(2, 1.0) {
        tags.push(AnomalyTag::HighMemory);
    }

    // 3. Network
    let net_sent_thresh = get_threshold(4, 1.0);
    let net_recv_thresh = get_threshold(5, 1.0);
    if values[4] > net_sent_thresh || values[5] > net_recv_thresh {
        tags.push(AnomalyTag::UnusualNetwork);
    }

    // Network Spike (3x)
    if values[4] > net_sent_thresh * 3.0 || values[5] > net_recv_thresh * 3.0 {
        tags.push(AnomalyTag::NetworkSpike);
    }

    // 4. Disk
    if values[7] > get_threshold(7, 2.0) || values[8] > get_threshold(8, 2.0) {
        tags.push(AnomalyTag::RapidDiskActivity);
    }

    // 5. Spikes rates
    if values[1] > get_threshold(1, 1.0) {
        tags.push(AnomalyTag::ProcessSpike);
    }

    // Memory leak suspicion (spike rate)
    if values[3] > get_threshold(3, 1.0) {
        tags.push(AnomalyTag::MemoryLeak);
    }

    // 6. Process behaviors
    if values[11] > get_threshold(11, 1.0) {
        tags.push(AnomalyTag::NewProcess);
    }

    if values[12] > get_threshold(12, 1.5) {
        tags.push(AnomalyTag::HighChurnRate);
    }

    // 7. Time check
    let current_hour = Utc::now().hour() as u8;
    if !baseline.typical_hours.contains(&current_hour) {
        tags.push(AnomalyTag::UnusualTime);
    }

    // --- COMPLEX ANALYSIS ---

    // Multiple spikes (CPU spike + Memory spike)
    if values[1] > get_threshold(1, 1.0) && values[3] > get_threshold(3, 1.0) {
        tags.push(AnomalyTag::MultipleSpikes);
    }

    // Suspicious Pattern (Network + Disk + New Process)
    let has_net = values[4] > net_sent_thresh || values[5] > net_recv_thresh;
    let has_disk = values[7] > get_threshold(7, 1.0) || values[8] > get_threshold(8, 1.0);
    let has_new_proc = values[11] > get_threshold(11, 1.0);

    if has_net && has_disk && has_new_proc {
        tags.push(AnomalyTag::SuspiciousPattern);
    }

    // Critical Anomaly
    if tags.len() >= 5 || tags.contains(&AnomalyTag::SuspiciousPattern) {
        tags.push(AnomalyTag::CriticalAnomaly);
    }

    tags
}

use crate::logic::dataset::{self, DatasetRecord};
use crate::logic::threat::ThreatClass;

/// Analyze summary with machine learning score
pub fn analyze_summary(
    summary_id: &str,
    features: &FeatureVector,
    ml_score: f32,
) -> AnalysisResult {
    let tags = compare_with_baseline(features);
    let tag_strings: Vec<String> = tags.iter().map(|t| t.to_string()).collect();

    // Helper calculate score (simplified)
    let tag_score = calculate_tag_score(&tags);
    let final_score = ML_WEIGHT * ml_score + TAG_WEIGHT * tag_score;
    let is_anomaly = final_score >= ANOMALY_THRESHOLD;

    // Update baseline if safe
    if final_score < BASELINE_UPDATE_THRESHOLD {
        update_global_baseline(features);
    }

    if is_anomaly {
        ANOMALY_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    let result = AnalysisResult {
        summary_id: summary_id.to_string(),
        ml_score,
        tag_score,
        final_score,
        is_anomaly,
        tags: tag_strings,
        tag_details: tags.iter().map(|t| TagDetail {
            tag: t.to_string(),
            severity: t.severity(),
            description: t.description().to_string(),
        }).collect(),
        confidence: 1.0 - (ml_score - tag_score).abs(),
        severity_level: if final_score >= 0.8 { "Critical" } else if final_score >= 0.6 { "High" } else { "Medium" }.to_string(),
        analyzed_at: Utc::now().to_rfc3339(),
    };

    // Store history
    let mut history = ANALYSIS_HISTORY.write();
    history.push(result.clone());
    if history.len() > 1000 {
        history.drain(0..500);
    }
    drop(history); // Release lock before logging IO

    // P1.3: LOG DATASET (Training Data)
    if let Some(baseline) = get_versioned_baseline() {
        let diff: Vec<f32> = features.values.iter()
            .zip(baseline.mean.iter())
            .map(|(f, m)| f - m)
            .collect();

        let threat = if final_score >= 0.8 {
            ThreatClass::Malicious
        } else if final_score >= 0.6 {
            ThreatClass::Suspicious
        } else {
            ThreatClass::Benign
        };

        dataset::log(DatasetRecord {
            timestamp: Utc::now().timestamp() as u64,
            feature_version: features.version,
            layout_hash: features.layout_hash,
            features: features.values.to_vec(),
            baseline_diff: diff,
            score: final_score,
            confidence: result.confidence,
            threat,
        });
    }

    result
}

fn calculate_tag_score(tags: &[AnomalyTag]) -> f32 {
    if tags.is_empty() { return 0.0; }
    let max_severity = tags.iter().map(|t| t.severity()).fold(0.0, f32::max);
    let base = max_severity / 5.0; // Normalize 0-1
    let boost = (tags.len() as f32 * 0.05).min(0.2);
    (base + boost).min(1.0)
}

fn update_global_baseline(features: &FeatureVector) {
    let mut global = GLOBAL_BASELINE.write();
    if let Some(baseline) = global.as_mut() {
        let alpha = 0.1;

        // Iterative Mean/Variance update
        for i in 0..FEATURE_COUNT {
            let x = features.values[i];
            let diff = x - baseline.mean[i];

            // Update Mean
            let new_mean = baseline.mean[i] + alpha * diff;
            baseline.mean[i] = new_mean;

            // Update Variance (Welford's approx for EMA)
            // Var_new = (1-alpha)*Var_old + alpha*(diff * (x - new_mean))
            // Note: Diff calculation for variance update usually uses (x - mean_old) * (x - mean_new)
            let diff_new = x - new_mean;
            baseline.variance[i] = (1.0 - alpha) * baseline.variance[i] + alpha * diff * diff_new;
        }

        baseline.samples += 1;
        baseline.last_updated = Utc::now().timestamp();

        // Save periodically (simple check)
        if baseline.samples % 10 == 0 {
            let path = storage::get_default_baseline_path();
            let _ = storage::save_baseline(baseline, &path);
        }
    }
}

pub fn get_analysis_history(limit: usize) -> Vec<AnalysisResult> {
    let history = ANALYSIS_HISTORY.read();
    let start = if history.len() > limit { history.len() - limit } else { 0 };
    history[start..].to_vec()
}

pub fn get_anomaly_count() -> u32 {
    ANOMALY_COUNT.load(Ordering::SeqCst)
}

// ============================================================================
// LEGACY API WRAPPERS (For compatibility)
// ============================================================================

/// Get profile by app name - Stub (New system uses global baseline primarily)
pub async fn get_profile(_app_name: &str) -> Result<Option<crate::api::commands::BaselineProfile>, validate::BaselineError> {
    // Current implementation only uses global baseline.
    // Future P1.x might bring back per-app profiles.
    Ok(None)
}

/// Update profile by app name - Stub
pub async fn update(_app_name: &str) -> Result<bool, validate::BaselineError> {
    Ok(true)
}

/// Get tags for a specific analysis result
pub async fn get_tags(summary_id: &str) -> Result<Vec<String>, validate::BaselineError> {
    let history = ANALYSIS_HISTORY.read();
    if let Some(result) = history.iter().find(|r| r.summary_id == summary_id) {
        Ok(result.tags.clone())
    } else {
        Ok(vec![])
    }
}

/// Get severity matrix
pub fn get_severity_matrix() -> serde_json::Value {
    serde_json::json!({
        "HIGH_CPU": 2.0,
        "HIGH_MEMORY": 2.0,
        "UNUSUAL_NETWORK": 2.5,
        "NEW_PROCESS": 2.5,
        "UNUSUAL_TIME": 2.5,
        "RAPID_DISK_ACTIVITY": 3.0,
        "PROCESS_SPIKE": 3.0,
        "NETWORK_SPIKE": 3.5,
        "MEMORY_LEAK": 3.5,
        "HIGH_CHURN_RATE": 3.5,
        "SUSPICIOUS_PATTERN": 4.0,
        "MULTIPLE_SPIKES": 4.0,
        "NETWORK_PORT_SCAN": 4.5,
        "COORDINATED_ACTIVITY": 4.5,
        "CRITICAL_ANOMALY": 5.0,
    })
}

/// Legacy 15-feature analysis wrapper
pub fn analyze_summary_15(
    summary_id: &str,
    features_array: &[f32; 15],
    ml_score: f32,
) -> AnalysisResult {
    // Create FeatureVector from array (P1.1 Standard)
    let features = FeatureVector::from_values(*features_array);
    analyze_summary(summary_id, &features, ml_score)
}

