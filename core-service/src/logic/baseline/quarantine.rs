//! Quarantine Queue Module - Hàng đợi xét duyệt sample (Phase 1: Anti-Poisoning)
//!
//! Mục đích: Ngăn chặn malware "nhiễm độc" baseline bằng cách yêu cầu
//! sample phải "clean" liên tục trong X giờ trước khi được học.
//!
//! Flow:
//! 1. Sample mới → Thêm vào quarantine queue
//! 2. Mỗi analysis cycle → Check sample có pass điều kiện không
//! 3. Nếu clean đủ lâu → Approve để học vào baseline
//! 4. Nếu bị đánh dấu suspicious → Reject và xóa khỏi queue

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::RwLock;
use chrono::Utc;

use super::types::{
    PendingSample, QuarantineStats, QueueHealth,
    AntiPoisoningConfig, FeatureVotingResult, AuditAction
};
use super::audit;
use crate::logic::features::FeatureVector;
use crate::logic::features::layout::FEATURE_LAYOUT;

// ============================================================================
// CONSTANTS (Defaults)
// ============================================================================

const DEFAULT_DELAY_HOURS: u32 = 6;
const DEFAULT_CLEAN_STREAK: u32 = 180;  // 180 * 2 phút = 6 giờ
const DEFAULT_MAX_SIZE: usize = 10_000;
const CLEAN_THRESHOLD: f32 = 0.3;       // Score < này = clean

// ============================================================================
// STATE
// ============================================================================

static QUARANTINE: RwLock<QuarantineQueue> = RwLock::new(QuarantineQueue::new_const());
static TOTAL_ACCEPTED: AtomicUsize = AtomicUsize::new(0);
static TOTAL_REJECTED: AtomicUsize = AtomicUsize::new(0);

// ============================================================================
// QUARANTINE QUEUE STRUCT
// ============================================================================

pub struct QuarantineQueue {
    pending: VecDeque<PendingSample>,
    config: AntiPoisoningConfig,
    learning_paused: bool,
    pause_reason: Option<String>,
}

impl QuarantineQueue {
    /// Constructor cho static initialization
    const fn new_const() -> Self {
        Self {
            pending: VecDeque::new(),
            config: AntiPoisoningConfig {
                quarantine_delay_hours: DEFAULT_DELAY_HOURS,
                quarantine_clean_streak: DEFAULT_CLEAN_STREAK,
                quarantine_max_size: DEFAULT_MAX_SIZE,
                drift_max_per_hour: 0.05,
                drift_alert_threshold: 0.10,
                snapshot_interval_minutes: 60,
                snapshot_max_count: 24,
                require_all_groups_clean: true,
            },
            learning_paused: false,
            pause_reason: None,
        }
    }

    /// Khởi tạo với config
    pub fn new(config: AntiPoisoningConfig) -> Self {
        Self {
            pending: VecDeque::new(),
            config,
            learning_paused: false,
            pause_reason: None,
        }
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Khởi tạo quarantine với config
pub fn init(config: AntiPoisoningConfig) {
    let mut q = QUARANTINE.write();
    q.config = config;
    log::info!("Quarantine initialized: delay={}h, streak={}, max_size={}",
        q.config.quarantine_delay_hours,
        q.config.quarantine_clean_streak,
        q.config.quarantine_max_size
    );
}

/// Thêm sample mới vào quarantine
pub fn add_sample(features: &FeatureVector) -> String {
    let sample = PendingSample::new(features.values.to_vec());
    let sample_id = sample.id.clone();

    let mut q = QUARANTINE.write();

    // Evict oldest nếu queue đầy
    if q.pending.len() >= q.config.quarantine_max_size {
        if let Some(evicted) = q.pending.pop_front() {
            TOTAL_REJECTED.fetch_add(1, Ordering::SeqCst);
            audit::log_sample(AuditAction::SampleRejected, &evicted.id);
            log::debug!("Quarantine full, evicted sample: {}", evicted.id);
        }
    }

    q.pending.push_back(sample);
    log::trace!("Added sample {} to quarantine (queue size: {})", sample_id, q.pending.len());

    sample_id
}

/// Cập nhật sample với score mới
/// Returns: true nếu sample vẫn trong queue, false nếu đã bị xóa
pub fn update_sample(sample_id: &str, score: f32, voting_result: &FeatureVotingResult) -> bool {
    let mut q = QUARANTINE.write();

    if let Some(sample) = q.pending.iter_mut().find(|s| s.id == sample_id) {
        let is_clean = score < CLEAN_THRESHOLD && voting_result.can_learn;
        sample.update_score(score, is_clean);

        // Nếu sample bị đánh dấu suspicious nhiều lần → reject
        if sample.total_checks > 10 && sample.avg_score > 0.6 {
            TOTAL_REJECTED.fetch_add(1, Ordering::SeqCst);
            audit::log_sample(AuditAction::SampleRejected, sample_id);
            log::debug!("Rejected sample {} (avg_score: {:.2})", sample_id, sample.avg_score);

            // Xóa khỏi queue
            q.pending.retain(|s| s.id != sample_id);
            return false;
        }

        true
    } else {
        false
    }
}

/// Lấy samples đủ điều kiện để học
/// Returns: Vec<(sample_id, features)>
pub fn get_approved_samples() -> Vec<(String, Vec<f32>)> {
    let mut q = QUARANTINE.write();

    // Nếu learning đang pause → không approve gì cả
    if q.learning_paused {
        return Vec::new();
    }

    let now = Utc::now().timestamp();
    let delay_seconds = q.config.quarantine_delay_hours as i64 * 3600;
    let required_streak = q.config.quarantine_clean_streak;

    let mut approved = Vec::new();
    let mut ids_to_remove = Vec::new();

    for sample in q.pending.iter() {
        let age = now - sample.first_seen;

        // Điều kiện approve:
        // 1. Đủ thời gian chờ
        // 2. Đủ clean streak
        // 3. Avg score thấp
        if age >= delay_seconds
            && sample.clean_streak >= required_streak
            && sample.avg_score < CLEAN_THRESHOLD
        {
            approved.push((sample.id.clone(), sample.features.clone()));
            ids_to_remove.push(sample.id.clone());

            TOTAL_ACCEPTED.fetch_add(1, Ordering::SeqCst);
            audit::log_sample(AuditAction::SampleAccepted, &sample.id);
            log::debug!(
                "Approved sample {} (waited: {:.1}min, streak: {}, avg_score: {:.2})",
                sample.id,
                sample.wait_time_minutes(),
                sample.clean_streak,
                sample.avg_score
            );
        }
    }

    // Xóa samples đã approve
    for id in ids_to_remove {
        q.pending.retain(|s| s.id != id);
    }

    approved
}

/// Pause learning (khi phát hiện drift bất thường)
pub fn pause_learning(reason: &str) {
    let mut q = QUARANTINE.write();
    if !q.learning_paused {
        q.learning_paused = true;
        q.pause_reason = Some(reason.to_string());
        audit::log_action(AuditAction::LearningPaused);
        log::warn!("Learning paused: {}", reason);
    }
}

/// Resume learning
pub fn resume_learning() {
    let mut q = QUARANTINE.write();
    if q.learning_paused {
        q.learning_paused = false;
        q.pause_reason = None;
        audit::log_action(AuditAction::LearningResumed);
        log::info!("Learning resumed");
    }
}

/// Kiểm tra learning có đang pause không
pub fn is_learning_paused() -> bool {
    QUARANTINE.read().learning_paused
}

/// Lấy lý do pause
pub fn get_pause_reason() -> Option<String> {
    QUARANTINE.read().pause_reason.clone()
}

/// Lấy thống kê quarantine (cho UI)
pub fn get_stats() -> QuarantineStats {
    let q = QUARANTINE.read();

    let pending = q.pending.len();
    let accepted = TOTAL_ACCEPTED.load(Ordering::SeqCst);
    let rejected = TOTAL_REJECTED.load(Ordering::SeqCst);

    // Tính avg delay
    let avg_delay = if !q.pending.is_empty() {
        q.pending.iter()
            .map(|s| s.wait_time_minutes())
            .sum::<f32>() / q.pending.len() as f32
    } else {
        0.0
    };

    // Oldest sample
    let oldest = q.pending.front()
        .map(|s| s.wait_time_minutes())
        .unwrap_or(0.0);

    // Queue health
    let health = if q.learning_paused {
        QueueHealth::Paused
    } else if pending >= q.config.quarantine_max_size * 9 / 10 {
        QueueHealth::Critical
    } else if pending >= q.config.quarantine_max_size / 2 {
        QueueHealth::Warning
    } else {
        QueueHealth::Healthy
    };

    QuarantineStats {
        pending,
        accepted,
        rejected,
        avg_delay_minutes: avg_delay,
        oldest_sample_minutes: oldest,
        queue_health: health,
    }
}

/// Lấy config hiện tại
pub fn get_config() -> AntiPoisoningConfig {
    QUARANTINE.read().config.clone()
}

/// Cập nhật config
pub fn set_config(config: AntiPoisoningConfig) {
    let mut q = QUARANTINE.write();
    q.config = config;
}

/// Clear toàn bộ queue (dùng khi reset baseline)
pub fn clear() {
    let mut q = QUARANTINE.write();
    q.pending.clear();
    log::info!("Quarantine queue cleared");
}

/// Lấy số lượng pending
pub fn pending_count() -> usize {
    QUARANTINE.read().pending.len()
}

// ============================================================================
// MULTI-FEATURE VOTING
// ============================================================================

/// Feature groups cho voting
const FEATURE_GROUPS: &[(&str, &[usize])] = &[
    ("CPU", &[0, 1]),           // cpu_percent, cpu_spike_rate
    ("Memory", &[2, 3]),        // memory_percent, memory_spike_rate
    ("Network", &[4, 5, 6]),    // network_sent_rate, network_recv_rate, network_ratio
    ("Disk", &[7, 8, 9]),       // disk_read_rate, disk_write_rate, combined_io
    ("Process", &[10, 11, 12]), // unique_processes, new_process_rate, process_churn_rate
    ("Correlation", &[13, 14]), // cpu_memory_product, spike_correlation
];

/// Kiểm tra tất cả 6 nhóm features có sạch không
pub fn check_feature_voting(
    features: &FeatureVector,
    baseline_mean: &[f32],
    baseline_variance: &[f32],
) -> FeatureVotingResult {
    let config = QUARANTINE.read().config.clone();

    let mut clean_groups = Vec::new();
    let mut dirty_groups = Vec::new();
    let mut group_scores = Vec::new();

    for (group_name, indices) in FEATURE_GROUPS {
        let deviation = calculate_group_deviation(
            features,
            baseline_mean,
            baseline_variance,
            indices
        );

        group_scores.push((group_name.to_string(), deviation));

        // Threshold: deviation < 1.5 std = clean
        if deviation < 1.5 {
            clean_groups.push(group_name.to_string());
        } else {
            dirty_groups.push(group_name.to_string());
        }
    }

    // Nếu require_all_groups_clean = true, tất cả phải sạch
    let can_learn = if config.require_all_groups_clean {
        dirty_groups.is_empty()
    } else {
        // Ít nhất 4/6 groups phải sạch
        clean_groups.len() >= 4
    };

    FeatureVotingResult {
        can_learn,
        clean_groups,
        dirty_groups,
        group_scores,
    }
}

/// Tính deviation trung bình của một nhóm features
fn calculate_group_deviation(
    features: &FeatureVector,
    baseline_mean: &[f32],
    baseline_variance: &[f32],
    indices: &[usize],
) -> f32 {
    if indices.is_empty() {
        return 0.0;
    }

    let deviations: Vec<f32> = indices.iter().map(|&i| {
        if i >= features.values.len() || i >= baseline_mean.len() {
            return 0.0;
        }

        let value = features.values[i];
        let mean = baseline_mean[i];
        let std = baseline_variance[i].sqrt().max(0.001); // Avoid div by 0

        ((value - mean) / std).abs()
    }).collect();

    deviations.iter().sum::<f32>() / deviations.len() as f32
}

/// Lấy tên feature từ index
pub fn get_feature_name(index: usize) -> &'static str {
    FEATURE_LAYOUT.get(index).copied().unwrap_or("unknown")
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logic::features::FeatureVector;

    #[test]
    fn test_pending_sample_creation() {
        let features = vec![0.0; 15];
        let sample = PendingSample::new(features.clone());

        assert_eq!(sample.features.len(), 15);
        assert_eq!(sample.clean_streak, 0);
        assert_eq!(sample.total_checks, 0);
    }

    #[test]
    fn test_sample_update() {
        let features = vec![0.0; 15];
        let mut sample = PendingSample::new(features);

        // Clean updates
        sample.update_score(0.1, true);
        sample.update_score(0.2, true);
        sample.update_score(0.15, true);

        assert_eq!(sample.clean_streak, 3);
        assert_eq!(sample.total_checks, 3);
        assert!(sample.avg_score < 0.3);

        // Dirty update resets streak
        sample.update_score(0.6, false);
        assert_eq!(sample.clean_streak, 0);
    }

    #[test]
    fn test_feature_voting() {
        let values = [10.0; 15];
        let features = FeatureVector::from_values(values);

        let mean = [10.0; 15];
        let variance = [1.0; 15];

        let result = check_feature_voting(&features, &mean, &variance);

        // All values = mean → should pass
        assert!(result.can_learn);
        assert!(result.dirty_groups.is_empty());
    }
}
