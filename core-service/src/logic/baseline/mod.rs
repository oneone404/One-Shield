//! Baseline Module - Behavioral Analysis Engine (P1.2 + v1.1 Anti-Poisoning)
//!
//! Manages versioned baseline profiles and detects anomalies based on
//! deviations from learned behavior.
//!
//! # Architecture
//! - `types.rs`: `VersionedBaseline`, `AnomalyTag`, Anti-Poisoning types
//! - `validate.rs`: Layout/Version validation
//! - `storage.rs`: Persistent storage with validation
//! - `audit.rs`: Audit log for baseline changes (v1.1)
//! - `quarantine.rs`: Quarantine queue for sample validation (v1.1)
//! - `drift.rs`: Drift monitoring (v1.1)
//! - `history.rs`: Baseline snapshots & rollback (v1.1)
//!
//! # Failure Strategy
//! If baseline version/layout mismatches on load -> Reset baseline safely.
//!
//! # Anti-Poisoning (v1.1)
//! - Delayed Learning: Samples must be clean for X hours before learning
//! - Multi-Feature Voting: All 6 feature groups must pass
//! - Drift Monitoring: Alert if baseline shifts too fast
//! - Rollback: Snapshot history allows reverting to clean state

// Allow unused - some exports for future use
#![allow(unused)]

pub mod types;
pub mod validate;
pub mod storage;
pub mod audit;
pub mod quarantine;
pub mod drift;
pub mod history;
#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use parking_lot::RwLock;
use chrono::{DateTime, Utc, Timelike};

use crate::logic::features::FeatureVector;
use crate::logic::features::layout::FEATURE_COUNT;

pub use types::{
    VersionedBaseline, AnomalyTag, AnalysisResult, TagDetail,
    LegacyBaselineProfile as BaselineProfile, // Alias for backward compat
    // v1.1 Anti-Poisoning exports
    PendingSample, QuarantineStats, QueueHealth,
    AuditLogEntry, AuditAction, DriftResult, BaselineSnapshot,
    AntiPoisoningConfig, FeatureVotingResult, SnapshotTrigger,
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
static ANTI_POISONING_ENABLED: AtomicBool = AtomicBool::new(true);

// ============================================================================
// INITIALIZATION & MANAGEMENT
// ============================================================================

/// Initialize baseline engine with Anti-Poisoning (v1.1)
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
            *global = Some(b.clone());

            // v1.1: Initialize Anti-Poisoning modules
            init_anti_poisoning(&b);
        },
        Err(e) => {
            log::warn!("Baseline load failed/invalid: {}. Initializing new baseline.", e);
            let new_b = storage::new_baseline("default");

            // Try to save immediately to ensure directory exists
            if let Err(save_err) = storage::save_baseline(&new_b, &path) {
                log::error!("Failed to save new baseline: {}", save_err);
            }

            *global = Some(new_b.clone());

            // v1.1: Initialize Anti-Poisoning modules
            init_anti_poisoning(&new_b);
        }
    }
}

/// Initialize Anti-Poisoning subsystems (v1.1)
fn init_anti_poisoning(baseline: &VersionedBaseline) {
    let config = AntiPoisoningConfig::default();

    // Initialize quarantine
    quarantine::init(config.clone());

    // Initialize drift monitor
    drift::init(
        config.drift_max_per_hour,
        config.drift_alert_threshold,
        config.drift_alert_threshold * 2.0, // pause threshold = 2x alert
    );
    drift::record_baseline(baseline);

    // Initialize history
    history::init(config.snapshot_interval_minutes, config.snapshot_max_count);

    // Load audit log
    let _ = audit::load_from_disk();

    log::info!("Anti-Poisoning v1.1 initialized");
}

/// Reset baseline to empty state
/// v1.1: Creates snapshot before reset for rollback capability
pub fn reset_baseline() {
    // v1.1: Create snapshot before reset
    if let Some(current) = GLOBAL_BASELINE.read().as_ref() {
        history::create_snapshot(current, SnapshotTrigger::BeforeReset);
        audit::log_action(AuditAction::BaselineReset);
    }

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

    // v1.1: Clear quarantine and reset drift monitor
    quarantine::clear();
    drift::reset();

    log::info!("Baseline has been reset (snapshot created for rollback)");
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

    // HEURISTIC FALLBACK (If Baseline Not Ready)
    // Allows detecting obvious anomalies (like Process Storm) during Learning phase
    if global.is_none() || global.as_ref().map_or(true, |b| b.samples < 10) {
        let mut tags = Vec::new();
        let v = &features.values;

        // Hard-coded Safety Limits
        if v[0] > 90.0 { tags.push(AnomalyTag::HighCpu); } // CPU > 90%
        if v[4] > 10_000_000.0 { tags.push(AnomalyTag::NetworkSpike); } // Sent > 10MB/s
        // Note: feature ranges depend on extractor. Assuming rate is absolute or relative.
        // Let's assume process churn is normalized or count. If it's count per interval:
        // 30 notepad in 10s interval = 3.
        // Correct indices (see features/layout.rs):
        // 11: new_process_rate
        // 12: process_churn_rate
        if v[11] > 2.0 || v[12] > 2.0 { tags.push(AnomalyTag::SuspiciousPattern); }

        return tags;
    }

    let baseline = global.as_ref().unwrap();

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

    let tag_details: Vec<TagDetail> = tags.iter().map(|t| TagDetail {
        tag: t.to_string(),
        severity: t.severity(),
        description: t.description().to_string(),
    }).collect();

    // Update baseline if safe
    if final_score < BASELINE_UPDATE_THRESHOLD {
        update_global_baseline(features);
    }

    if is_anomaly {
        ANOMALY_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    // Tính toán baseline diff nếu có baseline
    let global_baseline_guard = GLOBAL_BASELINE.read();
    let baseline_diff = if let Some(b) = global_baseline_guard.as_ref() {
        features.values.iter().zip(b.mean.iter()).map(|(f, m)| f - m).collect()
    } else {
        vec![0.0; features.values.len()]
    };

    let result = AnalysisResult {
        summary_id: summary_id.to_string(),
        ml_score,
        tag_score,
        final_score,
        is_anomaly,
        tags: tag_strings.clone(),
        tag_details: tag_details.clone(),
        confidence: 1.0 - (ml_score - tag_score).abs(),
        severity_level: if final_score >= 0.8 { "Critical" } else if final_score >= 0.6 { "High" } else { "Medium" }.to_string(),
        analyzed_at: chrono::Utc::now().to_rfc3339(),
        features: features.values.to_vec(),
        baseline_diff: baseline_diff.clone(),
    };

    // Update History (Rolling buffer 1000)
    {
        let mut history = ANALYSIS_HISTORY.write();
        history.push(result.clone());
        if history.len() > 1000 {
            history.drain(0..500);
        }
    }

    // P1.3: Dataset Logging (Automated)
    {
        let threat = if final_score >= 0.8 {
            ThreatClass::Malicious
        } else if final_score >= 0.5 {
            ThreatClass::Suspicious
        } else {
            ThreatClass::Benign
        };

        let record = DatasetRecord {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            feature_version: features.version,
            layout_hash: features.layout_hash,
            features: features.values.to_vec(), // Clone values
            baseline_diff,
            score: final_score,
            confidence: result.confidence,
            threat,
            user_label: None, // Added user_label
        };
        // Log to dataset (ground truth)
        dataset::log(record.clone());

        // P3.1: Correlation Engine
        crate::logic::incident::process_event(&record, &tag_strings);
    }

    result
}

// P2.2.3: Label Override Logic
pub fn override_label(summary_id: &str, user_label: String) -> Result<(), String> {
    let history = ANALYSIS_HISTORY.read();
    if let Some(result) = history.iter().find(|r| r.summary_id == summary_id) {
        let threat = if result.final_score >= 0.8 {
            ThreatClass::Malicious
        } else if result.final_score >= 0.5 {
            ThreatClass::Suspicious
        } else {
            ThreatClass::Benign
        };

        let record = DatasetRecord {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            feature_version: crate::logic::features::layout::FEATURE_VERSION,
            layout_hash: crate::logic::features::layout::layout_hash(),
            features: result.features.clone(),
            baseline_diff: result.baseline_diff.clone(),
            score: result.final_score,
            confidence: result.confidence,
            threat,
            user_label: Some(user_label),
        };

        crate::logic::dataset::log(record);
        Ok(())
    } else {
        Err("Analysis ID not found".to_string())
    }
}

fn calculate_tag_score(tags: &[AnomalyTag]) -> f32 {
    if tags.is_empty() { return 0.0; }
    let max_severity = tags.iter().map(|t| t.severity()).fold(0.0, f32::max);
    let base = max_severity / 5.0; // Normalize 0-1
    let boost = (tags.len() as f32 * 0.05).min(0.2);
    (base + boost).min(1.0)
}

/// Update baseline with new sample (v1.1: Uses Quarantine Queue)
///
/// Flow:
/// 1. Add sample to quarantine queue
/// 2. Check feature voting (all 6 groups must be clean)
/// 3. After delay period, approved samples are learned
/// 4. Monitor drift and pause if abnormal
fn update_global_baseline(features: &FeatureVector) {
    // v1.1: Check if anti-poisoning is enabled
    if ANTI_POISONING_ENABLED.load(Ordering::SeqCst) {
        update_baseline_with_quarantine(features);
    } else {
        update_baseline_direct(features);
    }
}

/// v1.1: Update with quarantine queue protection
fn update_baseline_with_quarantine(features: &FeatureVector) {
    // Check if learning is paused due to drift
    if quarantine::is_learning_paused() {
        log::trace!("Learning paused, skipping baseline update");
        return;
    }

    // Get current baseline for voting check
    let (mean, variance) = {
        let global = GLOBAL_BASELINE.read();
        if let Some(b) = global.as_ref() {
            (b.mean.to_vec(), b.variance.to_vec())
        } else {
            return;
        }
    };

    // Add to quarantine (will be evaluated over time)
    let sample_id = quarantine::add_sample(features);

    // Check feature voting
    let voting = quarantine::check_feature_voting(features, &mean, &variance);

    // Update sample with voting result (score = 0.0 for now, will be updated by analysis)
    quarantine::update_sample(&sample_id, 0.0, &voting);

    // Process approved samples (those that passed quarantine period)
    let approved = quarantine::get_approved_samples();
    for (id, approved_features) in approved {
        // Get changed features for audit
        let changed: Vec<String> = approved_features.iter().enumerate()
            .filter(|(i, &v)| {
                if *i < mean.len() {
                    (v - mean[*i]).abs() > variance[*i].sqrt() * 0.5
                } else {
                    false
                }
            })
            .map(|(i, _)| crate::logic::features::layout::FEATURE_LAYOUT[i].to_string())
            .collect();

        // Actually learn the sample
        learn_sample_direct(&approved_features);

        // Check drift after learning
        if let Some(baseline) = GLOBAL_BASELINE.read().as_ref() {
            let drift_result = drift::check_drift(baseline);
            let drift_value = drift_result.drift_value();

            // Log to audit
            audit::log_baseline_update(&id, changed, drift_value);

            // Handle drift result
            match drift_result {
                DriftResult::PauseLearning { reason, .. } => {
                    quarantine::pause_learning(&reason);
                    // Create snapshot before pause
                    history::create_snapshot(baseline, SnapshotTrigger::DriftAlert);
                }
                DriftResult::Alert { message, .. } => {
                    log::warn!("Drift alert: {}", message);
                }
                _ => {}
            }

            // Record baseline state for drift tracking
            drift::record_baseline(baseline);

            // Maybe create scheduled snapshot
            history::maybe_create_scheduled_snapshot(baseline);
        }
    }
}

/// Direct baseline update (legacy mode, when anti-poisoning is disabled)
fn update_baseline_direct(features: &FeatureVector) {
    learn_sample_direct(&features.values.to_vec());
}

/// Core learning logic (shared by both modes)
fn learn_sample_direct(features: &[f32]) {
    let mut global = GLOBAL_BASELINE.write();
    if let Some(baseline) = global.as_mut() {
        let alpha = 0.1;

        // Iterative Mean/Variance update
        for i in 0..FEATURE_COUNT.min(features.len()) {
            let x = features[i];
            let diff = x - baseline.mean[i];

            // Update Mean
            let new_mean = baseline.mean[i] + alpha * diff;
            baseline.mean[i] = new_mean;

            // Update Variance (Welford's approx for EMA)
            let diff_new = x - new_mean;
            baseline.variance[i] = (1.0 - alpha) * baseline.variance[i] + alpha * diff * diff_new;
        }

        baseline.samples += 1;
        baseline.last_updated = Utc::now().timestamp();

        // Save periodically
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

// ============================================================================
// ANTI-POISONING API (v1.1)
// ============================================================================

/// Get quarantine statistics (for UI)
pub fn get_quarantine_stats() -> QuarantineStats {
    quarantine::get_stats()
}

/// Get drift statistics (for UI)
pub fn get_drift_stats() -> drift::DriftStats {
    drift::get_stats()
}

/// Get baseline history statistics (for UI)
pub fn get_history_stats() -> history::HistoryStats {
    history::get_stats()
}

/// Get audit log statistics
pub fn get_audit_stats() -> audit::AuditStats {
    audit::get_stats()
}

/// Get recent audit entries
pub fn get_recent_audit(limit: usize) -> Vec<AuditLogEntry> {
    audit::get_recent(limit)
}

/// Get all baseline snapshots
pub fn get_snapshots() -> Vec<history::SnapshotInfo> {
    history::get_all_snapshots()
}

/// Rollback baseline to specific snapshot
pub fn rollback_to_snapshot(snapshot_id: &str) -> Result<(), String> {
    let baseline = history::rollback(snapshot_id)?;

    // Replace current baseline
    let mut global = GLOBAL_BASELINE.write();
    *global = Some(baseline.clone());

    // Save to disk
    let path = storage::get_default_baseline_path();
    if let Err(e) = storage::save_baseline(&baseline, &path) {
        return Err(format!("Failed to save rolled back baseline: {}", e));
    }

    // Reset drift monitor with new baseline
    drift::reset();
    drift::record_baseline(&baseline);

    // Resume learning if it was paused
    quarantine::resume_learning();

    log::info!("Baseline rolled back to snapshot {}", snapshot_id);
    Ok(())
}

/// Rollback to N hours ago
pub fn rollback_hours_ago(hours: u32) -> Result<(), String> {
    let baseline = history::rollback_hours_ago(hours)?;

    let mut global = GLOBAL_BASELINE.write();
    *global = Some(baseline.clone());

    let path = storage::get_default_baseline_path();
    storage::save_baseline(&baseline, &path)
        .map_err(|e| format!("Failed to save: {}", e))?;

    drift::reset();
    drift::record_baseline(&baseline);
    quarantine::resume_learning();

    log::info!("Baseline rolled back {} hours", hours);
    Ok(())
}

/// Enable/disable anti-poisoning protection
pub fn set_anti_poisoning_enabled(enabled: bool) {
    ANTI_POISONING_ENABLED.store(enabled, Ordering::SeqCst);
    log::info!("Anti-poisoning {}", if enabled { "enabled" } else { "disabled" });
}

/// Check if anti-poisoning is enabled
pub fn is_anti_poisoning_enabled() -> bool {
    ANTI_POISONING_ENABLED.load(Ordering::SeqCst)
}

/// Manually pause learning (admin action)
pub fn pause_learning(reason: &str) {
    quarantine::pause_learning(reason);
}

/// Resume learning after pause
pub fn resume_learning() {
    quarantine::resume_learning();
}

/// Check if learning is paused
pub fn is_learning_paused() -> bool {
    quarantine::is_learning_paused()
}

/// Get pause reason if paused
pub fn get_learning_pause_reason() -> Option<String> {
    quarantine::get_pause_reason()
}

/// Get top features contributing to drift
pub fn get_top_drifting_features(limit: usize) -> Vec<(String, f32)> {
    drift::get_top_drifting_features(limit)
}

/// Update anti-poisoning configuration
pub fn set_anti_poisoning_config(config: AntiPoisoningConfig) {
    quarantine::set_config(config.clone());
    drift::set_thresholds(
        config.drift_max_per_hour,
        config.drift_alert_threshold,
        config.drift_alert_threshold * 2.0,
    );
    history::set_config(config.snapshot_interval_minutes, config.snapshot_max_count);
}

/// Get current anti-poisoning configuration
pub fn get_anti_poisoning_config() -> AntiPoisoningConfig {
    quarantine::get_config()
}

/// Comprehensive status for Dashboard
#[derive(Debug, Clone, serde::Serialize)]
pub struct AntiPoisoningStatus {
    pub enabled: bool,
    pub learning_paused: bool,
    pub pause_reason: Option<String>,
    pub quarantine: QuarantineStats,
    pub drift: drift::DriftStats,
    pub snapshots_count: usize,
}

pub fn get_anti_poisoning_status() -> AntiPoisoningStatus {
    AntiPoisoningStatus {
        enabled: is_anti_poisoning_enabled(),
        learning_paused: is_learning_paused(),
        pause_reason: get_learning_pause_reason(),
        quarantine: get_quarantine_stats(),
        drift: get_drift_stats(),
        snapshots_count: history::count(),
    }
}
