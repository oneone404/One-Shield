//! Baseline Engine (Tag Engine / Thẩm phán 2) - ENHANCED VERSION
//!
//! So sánh hành vi với baseline profile, gán tags với Severity Scoring.
//! Hỗ trợ 15 Features và Feature Crosses.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use parking_lot::RwLock;
use chrono::{DateTime, Utc, Timelike};

// ============================================================================
// CONSTANTS
// ============================================================================

const ANOMALY_THRESHOLD: f32 = 0.6;
const BASELINE_UPDATE_THRESHOLD: f32 = 0.5;
const ML_WEIGHT: f32 = 0.6;
const TAG_WEIGHT: f32 = 0.4;
const OUTLIER_STDS: f32 = 2.0;

// ============================================================================
// SEVERITY MATRIX - Trọng số nghiêm trọng cho mỗi Tag
// ============================================================================

/// Severity levels từ 1.0 (Low) đến 5.0 (Critical)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeverityLevel(pub f32);

impl SeverityLevel {
    pub const LOW: SeverityLevel = SeverityLevel(1.0);
    pub const MEDIUM: SeverityLevel = SeverityLevel(2.0);
    pub const HIGH: SeverityLevel = SeverityLevel(3.0);
    pub const VERY_HIGH: SeverityLevel = SeverityLevel(4.0);
    pub const CRITICAL: SeverityLevel = SeverityLevel(5.0);
}

/// Anomaly Tags với Severity Scoring
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyTag {
    // Resource tags (Severity: Low-Medium)
    HighCpu,                // 2.0 - CPU cao hơn baseline
    HighMemory,             // 2.0 - Memory cao hơn baseline

    // Network tags (Severity: Medium-High)
    UnusualNetwork,         // 2.5 - Lưu lượng mạng bất thường
    NetworkSpike,           // 3.5 - Network tăng đột biến
    NetworkPortScan,        // 4.5 - Có dấu hiệu port scan

    // Process tags (Severity: Medium-Very High)
    NewProcess,             // 2.5 - Tiến trình chưa từng chạy
    ProcessSpike,           // 3.0 - Nhiều process spike cùng lúc
    SuspiciousPattern,      // 4.0 - Pattern đáng ngờ

    // Disk tags (Severity: Medium-High)
    RapidDiskActivity,      // 3.0 - Hoạt động disk bất thường

    // Time/Behavior tags (Severity: Medium)
    UnusualTime,            // 2.5 - Hoạt động ngoài giờ thường

    // Memory leak (Severity: High)
    MemoryLeak,             // 3.5 - Memory tăng liên tục

    // Combined/Cross-feature tags (Severity: High-Critical)
    HighChurnRate,          // 3.5 - Tỷ lệ thay đổi process cao
    MultipleSpikes,         // 4.0 - Nhiều loại spike cùng lúc
    CoordinatedActivity,    // 4.5 - Hoạt động có vẻ phối hợp
    CriticalAnomaly,        // 5.0 - Anomaly nghiêm trọng nhất
}

impl AnomalyTag {
    /// Lấy severity score (1.0 - 5.0)
    pub fn severity(&self) -> f32 {
        match self {
            // Low (1.0-2.0)
            AnomalyTag::HighCpu => 2.0,
            AnomalyTag::HighMemory => 2.0,

            // Medium (2.5-3.0)
            AnomalyTag::UnusualNetwork => 2.5,
            AnomalyTag::NewProcess => 2.5,
            AnomalyTag::UnusualTime => 2.5,
            AnomalyTag::RapidDiskActivity => 3.0,
            AnomalyTag::ProcessSpike => 3.0,

            // High (3.5-4.0)
            AnomalyTag::NetworkSpike => 3.5,
            AnomalyTag::MemoryLeak => 3.5,
            AnomalyTag::HighChurnRate => 3.5,
            AnomalyTag::SuspiciousPattern => 4.0,
            AnomalyTag::MultipleSpikes => 4.0,

            // Very High - Critical (4.5-5.0)
            AnomalyTag::NetworkPortScan => 4.5,
            AnomalyTag::CoordinatedActivity => 4.5,
            AnomalyTag::CriticalAnomaly => 5.0,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            AnomalyTag::HighCpu => "HIGH_CPU".to_string(),
            AnomalyTag::HighMemory => "HIGH_MEMORY".to_string(),
            AnomalyTag::UnusualNetwork => "UNUSUAL_NETWORK".to_string(),
            AnomalyTag::NetworkSpike => "NETWORK_SPIKE".to_string(),
            AnomalyTag::NetworkPortScan => "NETWORK_PORT_SCAN".to_string(),
            AnomalyTag::NewProcess => "NEW_PROCESS".to_string(),
            AnomalyTag::ProcessSpike => "PROCESS_SPIKE".to_string(),
            AnomalyTag::SuspiciousPattern => "SUSPICIOUS_PATTERN".to_string(),
            AnomalyTag::RapidDiskActivity => "RAPID_DISK_ACTIVITY".to_string(),
            AnomalyTag::UnusualTime => "UNUSUAL_TIME".to_string(),
            AnomalyTag::MemoryLeak => "MEMORY_LEAK".to_string(),
            AnomalyTag::HighChurnRate => "HIGH_CHURN_RATE".to_string(),
            AnomalyTag::MultipleSpikes => "MULTIPLE_SPIKES".to_string(),
            AnomalyTag::CoordinatedActivity => "COORDINATED_ACTIVITY".to_string(),
            AnomalyTag::CriticalAnomaly => "CRITICAL_ANOMALY".to_string(),
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AnomalyTag::HighCpu => "CPU usage vượt ngưỡng baseline",
            AnomalyTag::HighMemory => "Memory usage vượt ngưỡng baseline",
            AnomalyTag::UnusualNetwork => "Lưu lượng mạng bất thường",
            AnomalyTag::NetworkSpike => "Network tăng đột biến (3x baseline)",
            AnomalyTag::NetworkPortScan => "Có dấu hiệu quét port",
            AnomalyTag::NewProcess => "Process mới chưa từng thấy",
            AnomalyTag::ProcessSpike => "Nhiều process tăng CPU/Memory cùng lúc",
            AnomalyTag::SuspiciousPattern => "Pattern hành vi đáng ngờ",
            AnomalyTag::RapidDiskActivity => "Disk I/O cao bất thường",
            AnomalyTag::UnusualTime => "Hoạt động ngoài giờ làm việc",
            AnomalyTag::MemoryLeak => "Memory tăng liên tục (possible leak)",
            AnomalyTag::HighChurnRate => "Nhiều process tạo/hủy liên tục",
            AnomalyTag::MultipleSpikes => "Nhiều loại spike xảy ra đồng thời",
            AnomalyTag::CoordinatedActivity => "Hoạt động có vẻ phối hợp giữa processes",
            AnomalyTag::CriticalAnomaly => "Anomaly cực kỳ nghiêm trọng",
        }
    }
}

/// Maximum possible severity (sum of all tags)
const MAX_SEVERITY: f32 = 5.0;  // Normalize to single highest tag

// ============================================================================
// BASELINE PROFILE - ENHANCED (15 Features)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub id: String,
    pub name: String,

    // Original 10 features
    pub avg_cpu: f32,
    pub std_cpu: f32,
    pub avg_memory: f32,
    pub std_memory: f32,
    pub avg_network_sent: f32,
    pub std_network_sent: f32,
    pub avg_network_recv: f32,
    pub std_network_recv: f32,
    pub avg_disk_read: f32,
    pub std_disk_read: f32,
    pub avg_disk_write: f32,
    pub std_disk_write: f32,
    pub avg_processes: f32,
    pub std_processes: f32,

    // NEW: Feature Crosses baselines
    pub avg_cpu_spike_rate: f32,
    pub std_cpu_spike_rate: f32,
    pub avg_memory_spike_rate: f32,
    pub std_memory_spike_rate: f32,
    pub avg_new_process_rate: f32,
    pub std_new_process_rate: f32,
    pub avg_disk_io_rate: f32,
    pub std_disk_io_rate: f32,
    pub avg_churn_rate: f32,
    pub std_churn_rate: f32,

    // Typical activity hours
    pub typical_hours: Vec<u8>,

    // Metadata
    pub sample_count: u32,
    pub last_updated: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl Default for BaselineProfile {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: "default".to_string(),

            // Original features
            avg_cpu: 15.0,
            std_cpu: 10.0,
            avg_memory: 300.0,
            std_memory: 200.0,
            avg_network_sent: 8.0,
            std_network_sent: 4.0,
            avg_network_recv: 10.0,
            std_network_recv: 5.0,
            avg_disk_read: 5.0,
            std_disk_read: 3.0,
            avg_disk_write: 4.0,
            std_disk_write: 2.0,
            avg_processes: 60.0,
            std_processes: 20.0,

            // Feature Crosses
            avg_cpu_spike_rate: 0.05,
            std_cpu_spike_rate: 0.03,
            avg_memory_spike_rate: 0.03,
            std_memory_spike_rate: 0.02,
            avg_new_process_rate: 0.1,
            std_new_process_rate: 0.05,
            avg_disk_io_rate: 6.0,
            std_disk_io_rate: 3.0,
            avg_churn_rate: 0.5,
            std_churn_rate: 0.2,

            typical_hours: (8..22).collect(),
            sample_count: 0,
            last_updated: Utc::now(),
            created_at: Utc::now(),
        }
    }
}

/// Analysis Result với Severity-weighted scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub summary_id: String,
    pub ml_score: f32,
    pub tag_score: f32,           // Severity-weighted
    pub final_score: f32,
    pub is_anomaly: bool,
    pub tags: Vec<String>,
    pub tag_details: Vec<TagDetail>,
    pub confidence: f32,
    pub severity_level: String,   // "Low", "Medium", "High", "Critical"
    pub analyzed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagDetail {
    pub tag: String,
    pub severity: f32,
    pub description: String,
}

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

static PROFILES: RwLock<Option<HashMap<String, BaselineProfile>>> = RwLock::new(None);
static GLOBAL_BASELINE: RwLock<Option<BaselineProfile>> = RwLock::new(None);
static ANALYSIS_HISTORY: RwLock<Vec<AnalysisResult>> = RwLock::new(Vec::new());
static ANOMALY_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

// ============================================================================
// ERROR HANDLING
// ============================================================================

#[derive(Debug)]
pub struct BaselineError(pub String);

impl std::fmt::Display for BaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BaselineError: {}", self.0)
    }
}

impl std::error::Error for BaselineError {}

// ============================================================================
// INITIALIZATION
// ============================================================================

pub fn init() {
    let mut profiles = PROFILES.write();
    if profiles.is_none() {
        *profiles = Some(HashMap::new());
    }

    let mut global = GLOBAL_BASELINE.write();
    if global.is_none() {
        *global = Some(BaselineProfile::default());
    }
}

// ============================================================================
// PROFILE MANAGEMENT
// ============================================================================

pub async fn get_profile(app_name: &str) -> Result<Option<crate::api::commands::BaselineProfile>, BaselineError> {
    init();

    let profiles = PROFILES.read();
    if let Some(map) = profiles.as_ref() {
        if let Some(profile) = map.get(app_name) {
            return Ok(Some(crate::api::commands::BaselineProfile {
                app_name: profile.name.clone(),
                avg_cpu: profile.avg_cpu,
                avg_memory: profile.avg_memory,
                avg_network: profile.avg_network_sent + profile.avg_network_recv,
                typical_hours: profile.typical_hours.clone(),
                last_updated: profile.last_updated.to_rfc3339(),
            }));
        }
    }

    Ok(None)
}

pub async fn update(app_name: &str) -> Result<bool, BaselineError> {
    init();

    let mut profiles = PROFILES.write();
    if let Some(map) = profiles.as_mut() {
        let profile = map.entry(app_name.to_string())
            .or_insert_with(|| {
                let mut p = BaselineProfile::default();
                p.name = app_name.to_string();
                p
            });
        profile.last_updated = Utc::now();
        profile.sample_count += 1;
    }

    Ok(true)
}

pub async fn get_tags(summary_id: &str) -> Result<Vec<String>, BaselineError> {
    let history = ANALYSIS_HISTORY.read();
    if let Some(result) = history.iter().find(|r| r.summary_id == summary_id) {
        Ok(result.tags.clone())
    } else {
        Ok(vec![])
    }
}

// ============================================================================
// TAG ENGINE - ENHANCED với Feature Crosses
// ============================================================================

/// So sánh 15 Features với baseline và trả về tags
pub fn compare_with_baseline(features: &[f32; 15]) -> Vec<AnomalyTag> {
    init();

    let global = GLOBAL_BASELINE.read();
    let baseline = match global.as_ref() {
        Some(b) => b,
        None => return vec![],
    };

    let mut tags = Vec::new();

    // Feature indices (15 features):
    // 0: avg_cpu, 1: max_cpu, 2: avg_memory, 3: max_memory
    // 4: net_sent, 5: net_recv, 6: disk_read, 7: disk_write
    // 8: unique_procs, 9: network_ratio
    // 10: cpu_spike_rate, 11: memory_spike_rate, 12: new_process_rate
    // 13: avg_disk_io_rate, 14: process_churn_rate

    // === ORIGINAL FEATURE CHECKS ===

    // 1. CPU check
    let cpu_upper = baseline.avg_cpu + OUTLIER_STDS * baseline.std_cpu;
    if features[0] > cpu_upper || features[1] > cpu_upper * 1.5 {
        tags.push(AnomalyTag::HighCpu);
    }

    // 2. Memory check
    let mem_upper = baseline.avg_memory + OUTLIER_STDS * baseline.std_memory;
    if features[2] > mem_upper || features[3] > mem_upper * 1.5 {
        tags.push(AnomalyTag::HighMemory);
    }

    // 3. Network check
    let net_sent_upper = baseline.avg_network_sent + OUTLIER_STDS * baseline.std_network_sent;
    let net_recv_upper = baseline.avg_network_recv + OUTLIER_STDS * baseline.std_network_recv;

    if features[4] > net_sent_upper || features[5] > net_recv_upper {
        tags.push(AnomalyTag::UnusualNetwork);
    }

    // Network spike (3x baseline)
    if features[4] > net_sent_upper * 3.0 || features[5] > net_recv_upper * 3.0 {
        tags.push(AnomalyTag::NetworkSpike);
    }

    // 4. Disk activity check
    let disk_read_upper = baseline.avg_disk_read + OUTLIER_STDS * baseline.std_disk_read;
    let disk_write_upper = baseline.avg_disk_write + OUTLIER_STDS * baseline.std_disk_write;

    if features[6] > disk_read_upper * 2.0 || features[7] > disk_write_upper * 2.0 {
        tags.push(AnomalyTag::RapidDiskActivity);
    }

    // 5. Unusual time check
    let current_hour = Utc::now().hour() as u8;
    if !baseline.typical_hours.contains(&current_hour) {
        tags.push(AnomalyTag::UnusualTime);
    }

    // === NEW FEATURE CROSSES CHECKS ===

    // 6. CPU Spike Rate check
    let cpu_spike_upper = baseline.avg_cpu_spike_rate + OUTLIER_STDS * baseline.std_cpu_spike_rate;
    if features[10] > cpu_spike_upper {
        tags.push(AnomalyTag::ProcessSpike);
    }

    // 7. Memory Spike Rate check (possible memory leak)
    let mem_spike_upper = baseline.avg_memory_spike_rate + OUTLIER_STDS * baseline.std_memory_spike_rate;
    if features[11] > mem_spike_upper {
        tags.push(AnomalyTag::MemoryLeak);
    }

    // 8. New Process Rate check
    let new_proc_upper = baseline.avg_new_process_rate + OUTLIER_STDS * baseline.std_new_process_rate;
    if features[12] > new_proc_upper {
        tags.push(AnomalyTag::NewProcess);
    }

    // 9. Disk I/O Rate check
    let disk_io_upper = baseline.avg_disk_io_rate + OUTLIER_STDS * baseline.std_disk_io_rate;
    if features[13] > disk_io_upper * 2.0 {
        // Already have RapidDiskActivity, but reinforce if needed
        if !tags.contains(&AnomalyTag::RapidDiskActivity) {
            tags.push(AnomalyTag::RapidDiskActivity);
        }
    }

    // 10. Process Churn Rate check
    let churn_upper = baseline.avg_churn_rate + OUTLIER_STDS * baseline.std_churn_rate;
    if features[14] > churn_upper * 1.5 {
        tags.push(AnomalyTag::HighChurnRate);
    }

    // === COMBINED/CROSS-FEATURE TAGS ===

    // Multiple spikes (CPU + Memory spikes together)
    if features[10] > cpu_spike_upper && features[11] > mem_spike_upper {
        tags.push(AnomalyTag::MultipleSpikes);
    }

    // Suspicious pattern (high network + high disk + new processes)
    let has_network_anomaly = features[4] > net_sent_upper || features[5] > net_recv_upper;
    let has_disk_anomaly = features[6] > disk_read_upper || features[7] > disk_write_upper;
    let has_new_procs = features[12] > new_proc_upper;

    if has_network_anomaly && has_disk_anomaly && has_new_procs {
        tags.push(AnomalyTag::SuspiciousPattern);
    }

    // Coordinated activity (high churn + multiple spikes + unusual time)
    let is_unusual_time = !baseline.typical_hours.contains(&current_hour);
    if features[14] > churn_upper * 2.0 && tags.contains(&AnomalyTag::MultipleSpikes) && is_unusual_time {
        tags.push(AnomalyTag::CoordinatedActivity);
    }

    // Critical anomaly (very high severity combination)
    if tags.len() >= 5 || tags.contains(&AnomalyTag::CoordinatedActivity) {
        tags.push(AnomalyTag::CriticalAnomaly);
    }

    tags
}

/// Tính Tag Score với Severity Weighting
/// Formula: Tag Score = Sum(severity of active tags) / MAX_SEVERITY * normalization_factor
pub fn calculate_tag_score(tags: &[AnomalyTag]) -> f32 {
    if tags.is_empty() {
        return 0.0;
    }

    // Sum severity scores
    let total_severity: f32 = tags.iter().map(|t| t.severity()).sum();

    // Get max severity from active tags
    let max_active_severity = tags.iter()
        .map(|t| t.severity())
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap_or(0.0);

    // Weighted calculation:
    // - Base: average severity normalized to 0-1
    // - Boost: if max severity is high, boost the score
    let avg_severity = total_severity / tags.len() as f32;
    let normalized_avg = avg_severity / MAX_SEVERITY;

    // Apply boost for critical tags
    let boost = if max_active_severity >= 4.0 {
        0.2
    } else if max_active_severity >= 3.0 {
        0.1
    } else {
        0.0
    };

    // Also consider number of tags (more tags = higher risk)
    let count_factor = (tags.len() as f32 * 0.05).min(0.2);

    (normalized_avg + boost + count_factor).min(1.0)
}

/// Get severity level string
fn get_severity_level(final_score: f32) -> String {
    if final_score >= 0.8 {
        "Critical".to_string()
    } else if final_score >= 0.6 {
        "High".to_string()
    } else if final_score >= 0.4 {
        "Medium".to_string()
    } else {
        "Low".to_string()
    }
}

// ============================================================================
// DUAL ANALYSIS ENGINE - ENHANCED
// ============================================================================

/// Phân tích Summary Vector với 15 features
pub fn analyze_summary_15(
    summary_id: &str,
    features: &[f32; 15],
    ml_score: f32,
) -> AnalysisResult {
    // 1. Get tags from Tag Engine
    let tags = compare_with_baseline(features);
    let tag_strings: Vec<String> = tags.iter().map(|t| t.to_string()).collect();

    // 2. Create tag details
    let tag_details: Vec<TagDetail> = tags.iter().map(|t| TagDetail {
        tag: t.to_string(),
        severity: t.severity(),
        description: t.description().to_string(),
    }).collect();

    // 3. Calculate Severity-weighted Tag Score
    let tag_score = calculate_tag_score(&tags);

    // 4. Calculate Final Score (ML * 0.6 + Tag * 0.4)
    let final_score = ML_WEIGHT * ml_score + TAG_WEIGHT * tag_score;

    // 5. Determine anomaly
    let is_anomaly = final_score >= ANOMALY_THRESHOLD;

    // 6. Calculate confidence
    let agreement = 1.0 - (ml_score - tag_score).abs();
    let confidence = agreement * 0.7 + if tags.len() >= 3 { 0.3 } else { tags.len() as f32 * 0.1 };

    // 7. Get severity level
    let severity_level = get_severity_level(final_score);

    // 8. Update baseline if safe
    if final_score < BASELINE_UPDATE_THRESHOLD {
        update_global_baseline_15(features);
    }

    // 9. Track anomalies
    if is_anomaly {
        ANOMALY_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    let result = AnalysisResult {
        summary_id: summary_id.to_string(),
        ml_score,
        tag_score,
        final_score,
        is_anomaly,
        tags: tag_strings.clone(),
        tag_details,
        confidence,
        severity_level: severity_level.clone(),
        analyzed_at: Utc::now(),
    };

    // 10. Save to history
    let mut history = ANALYSIS_HISTORY.write();
    history.push(result.clone());
    if history.len() > 1000 {
        history.drain(0..500);
    }
    drop(history);  // Release lock before calling action_guard

    // 11. PHASE III: Check Action Guard threshold
    if final_score >= crate::logic::action_guard::ACTION_THRESHOLD {
        log::warn!(
            "CRITICAL: Final Score {:.3} >= ACTION_THRESHOLD. Evaluating action...",
            final_score
        );

        // Quyết định hành động (không auto-execute, chờ approval)
        if let Some(action_type) = crate::logic::action_guard::decide_action(
            final_score,
            &tag_strings,
            None,  // No specific PID from summary
            "unknown_process",
        ) {
            log::warn!("Action Guard recommends: {:?}", action_type);

            // Thêm vào pending actions (không auto-execute)
            let _ = crate::logic::action_guard::execute_action(
                action_type,
                None,
                "detected_anomaly",
                final_score,
                tag_strings.clone(),
                false,  // Không auto-execute
            );
        }
    } else if final_score >= crate::logic::action_guard::HIGH_ALERT_THRESHOLD {
        log::warn!(
            "HIGH ALERT: Final Score {:.3} >= HIGH_ALERT_THRESHOLD",
            final_score
        );
    }

    result
}

/// Legacy 10-feature analysis (backwards compatible)
pub fn analyze_summary(
    summary_id: &str,
    features: &[f32; 10],
    ml_score: f32,
) -> AnalysisResult {
    // Convert 10 features to 15 by padding with zeros
    let mut features_15 = [0.0f32; 15];
    features_15[..10].copy_from_slice(features);

    analyze_summary_15(summary_id, &features_15, ml_score)
}

/// Update baseline với 15 features
fn update_global_baseline_15(features: &[f32; 15]) {
    let mut global = GLOBAL_BASELINE.write();

    if let Some(baseline) = global.as_mut() {
        let alpha = 0.1; // Learning rate

        // Update original features
        baseline.avg_cpu = baseline.avg_cpu * (1.0 - alpha) + features[0] * alpha;
        baseline.avg_memory = baseline.avg_memory * (1.0 - alpha) + features[2] * alpha;
        baseline.avg_network_sent = baseline.avg_network_sent * (1.0 - alpha) + features[4] * alpha;
        baseline.avg_network_recv = baseline.avg_network_recv * (1.0 - alpha) + features[5] * alpha;
        baseline.avg_disk_read = baseline.avg_disk_read * (1.0 - alpha) + features[6] * alpha;
        baseline.avg_disk_write = baseline.avg_disk_write * (1.0 - alpha) + features[7] * alpha;
        baseline.avg_processes = baseline.avg_processes * (1.0 - alpha) + features[8] * alpha;

        // Update Feature Crosses
        baseline.avg_cpu_spike_rate = baseline.avg_cpu_spike_rate * (1.0 - alpha) + features[10] * alpha;
        baseline.avg_memory_spike_rate = baseline.avg_memory_spike_rate * (1.0 - alpha) + features[11] * alpha;
        baseline.avg_new_process_rate = baseline.avg_new_process_rate * (1.0 - alpha) + features[12] * alpha;
        baseline.avg_disk_io_rate = baseline.avg_disk_io_rate * (1.0 - alpha) + features[13] * alpha;
        baseline.avg_churn_rate = baseline.avg_churn_rate * (1.0 - alpha) + features[14] * alpha;

        // Update std deviations
        let update_std = |old_std: f32, new_val: f32, avg: f32| -> f32 {
            let diff = (new_val - avg).abs();
            old_std * (1.0 - alpha) + diff * alpha
        };

        baseline.std_cpu = update_std(baseline.std_cpu, features[0], baseline.avg_cpu);
        baseline.std_memory = update_std(baseline.std_memory, features[2], baseline.avg_memory);
        baseline.std_cpu_spike_rate = update_std(baseline.std_cpu_spike_rate, features[10], baseline.avg_cpu_spike_rate);
        baseline.std_memory_spike_rate = update_std(baseline.std_memory_spike_rate, features[11], baseline.avg_memory_spike_rate);
        baseline.std_new_process_rate = update_std(baseline.std_new_process_rate, features[12], baseline.avg_new_process_rate);
        baseline.std_disk_io_rate = update_std(baseline.std_disk_io_rate, features[13], baseline.avg_disk_io_rate);
        baseline.std_churn_rate = update_std(baseline.std_churn_rate, features[14], baseline.avg_churn_rate);

        // Update typical hours
        let current_hour = Utc::now().hour() as u8;
        if !baseline.typical_hours.contains(&current_hour) {
            baseline.typical_hours.push(current_hour);
            baseline.typical_hours.sort();
        }

        baseline.sample_count += 1;
        baseline.last_updated = Utc::now();
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

pub fn get_anomaly_count() -> u32 {
    ANOMALY_COUNT.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn get_analysis_history(limit: usize) -> Vec<AnalysisResult> {
    let history = ANALYSIS_HISTORY.read();
    let start = if history.len() > limit { history.len() - limit } else { 0 };
    history[start..].to_vec()
}

pub fn get_global_baseline() -> Option<BaselineProfile> {
    let global = GLOBAL_BASELINE.read();
    global.clone()
}

pub fn reset_baseline() {
    let mut global = GLOBAL_BASELINE.write();
    *global = Some(BaselineProfile::default());

    ANOMALY_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
    ANALYSIS_HISTORY.write().clear();
}

/// Get severity matrix as JSON
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

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_scoring() {
        // Test single high severity tag
        let tags = vec![AnomalyTag::CriticalAnomaly];
        let score = calculate_tag_score(&tags);
        assert!(score > 0.8, "Critical tag should produce high score: {}", score);

        // Test multiple low severity tags
        let tags = vec![AnomalyTag::HighCpu, AnomalyTag::HighMemory];
        let score = calculate_tag_score(&tags);
        assert!(score < 0.6, "Low severity tags should produce lower score: {}", score);

        // Test mixed severity
        let tags = vec![AnomalyTag::HighCpu, AnomalyTag::NetworkSpike, AnomalyTag::MultipleSpikes];
        let score = calculate_tag_score(&tags);
        assert!(score >= 0.5, "Mixed severity should produce medium-high score: {}", score);
    }

    #[test]
    fn test_final_score_threshold() {
        init();

        // Create features that should trigger critical tags
        let mut features = [0.0f32; 15];
        features[0] = 80.0;  // High CPU
        features[2] = 1000.0; // High memory
        features[10] = 0.5;  // High CPU spike rate
        features[11] = 0.5;  // High memory spike rate
        features[14] = 2.0;  // High churn rate

        let ml_score = 0.8;
        let result = analyze_summary_15("test-1", &features, ml_score);

        assert!(result.final_score >= ANOMALY_THRESHOLD,
            "High severity should exceed threshold: {} >= {}", result.final_score, ANOMALY_THRESHOLD);
        assert!(result.is_anomaly, "Should be marked as anomaly");
    }

    #[test]
    fn test_feature_crosses_detection() {
        init();

        // Test that feature crosses (10-14) trigger appropriate tags
        let mut features = [0.0f32; 15];
        features[10] = 0.5; // cpu_spike_rate = 50% (very high)
        features[11] = 0.5; // memory_spike_rate = 50% (very high)

        let tags = compare_with_baseline(&features);

        assert!(tags.contains(&AnomalyTag::ProcessSpike), "Should detect process spike");
        assert!(tags.contains(&AnomalyTag::MemoryLeak), "Should detect memory leak potential");
        assert!(tags.contains(&AnomalyTag::MultipleSpikes), "Should detect multiple spikes");
    }
}
