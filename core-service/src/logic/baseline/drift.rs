//! Drift Monitor Module - Theo dõi baseline shift bất thường (Phase 1: Anti-Poisoning)
//!
//! Mục đích: Phát hiện khi baseline bị "drift" quá nhanh (dấu hiệu poisoning)
//!
//! Cách hoạt động:
//! 1. Lưu snapshots của baseline mean/variance theo thời gian
//! 2. Tính % thay đổi giữa các snapshots
//! 3. Alert nếu drift vượt ngưỡng

use parking_lot::RwLock;
use chrono::Utc;

use super::types::{DriftResult, VersionedBaseline, AuditAction};
use super::audit;
use crate::logic::features::layout::FEATURE_COUNT;

// ============================================================================
// CONSTANTS
// ============================================================================

const DEFAULT_MAX_DRIFT_PER_HOUR: f32 = 0.05;   // 5% drift max per hour
const DEFAULT_ALERT_THRESHOLD: f32 = 0.10;      // Alert if > 10% drift
const DEFAULT_PAUSE_THRESHOLD: f32 = 0.20;      // Pause learning if > 20% drift
const MAX_HISTORY_POINTS: usize = 60;           // Giữ 60 điểm (1 giờ nếu 1 phút/điểm)

// ============================================================================
// STATE
// ============================================================================

static DRIFT_MONITOR: RwLock<DriftMonitor> = RwLock::new(DriftMonitor::new_const());

// ============================================================================
// DRIFT MONITOR STRUCT
// ============================================================================

pub struct DriftMonitor {
    /// Lịch sử mean values theo thời gian
    history: Vec<DriftPoint>,

    /// Thresholds
    max_drift_per_hour: f32,
    alert_threshold: f32,
    pause_threshold: f32,

    /// Current drift stats
    current_drift: f32,
    drift_direction: DriftDirection,

    /// Cumulative drift trong 1 giờ qua
    hourly_drift: f32,
    last_hourly_reset: i64,
}

#[derive(Debug, Clone)]
struct DriftPoint {
    timestamp: i64,
    mean: [f32; FEATURE_COUNT],
    variance: [f32; FEATURE_COUNT],
    samples: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DriftDirection {
    Stable,
    Increasing,
    Decreasing,
    Erratic,
}

impl DriftMonitor {
    const fn new_const() -> Self {
        Self {
            history: Vec::new(),
            max_drift_per_hour: DEFAULT_MAX_DRIFT_PER_HOUR,
            alert_threshold: DEFAULT_ALERT_THRESHOLD,
            pause_threshold: DEFAULT_PAUSE_THRESHOLD,
            current_drift: 0.0,
            drift_direction: DriftDirection::Stable,
            hourly_drift: 0.0,
            last_hourly_reset: 0,
        }
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Khởi tạo drift monitor với thresholds
pub fn init(max_drift: f32, alert_threshold: f32, pause_threshold: f32) {
    let mut monitor = DRIFT_MONITOR.write();
    monitor.max_drift_per_hour = max_drift;
    monitor.alert_threshold = alert_threshold;
    monitor.pause_threshold = pause_threshold;
    monitor.last_hourly_reset = Utc::now().timestamp();
    log::info!(
        "Drift monitor initialized: max={:.1}%, alert={:.1}%, pause={:.1}%",
        max_drift * 100.0,
        alert_threshold * 100.0,
        pause_threshold * 100.0
    );
}

/// Ghi nhận baseline state hiện tại
pub fn record_baseline(baseline: &VersionedBaseline) {
    let mut monitor = DRIFT_MONITOR.write();

    let point = DriftPoint {
        timestamp: Utc::now().timestamp(),
        mean: baseline.mean,
        variance: baseline.variance,
        samples: baseline.samples,
    };

    monitor.history.push(point);

    // Giữ tối đa MAX_HISTORY_POINTS
    if monitor.history.len() > MAX_HISTORY_POINTS {
        monitor.history.remove(0);
    }

    // Reset hourly counter nếu đã qua 1 giờ
    let now = Utc::now().timestamp();
    if now - monitor.last_hourly_reset >= 3600 {
        log::debug!("Hourly drift: {:.2}%", monitor.hourly_drift * 100.0);
        monitor.hourly_drift = 0.0;
        monitor.last_hourly_reset = now;
    }
}

/// Kiểm tra drift so với baseline trước đó
pub fn check_drift(current_baseline: &VersionedBaseline) -> DriftResult {
    let mut monitor = DRIFT_MONITOR.write();

    // Cần ít nhất 2 điểm để so sánh
    if monitor.history.len() < 2 {
        return DriftResult::Normal;
    }

    // Clone dữ liệu cần thiết trước khi modify
    let history_len = monitor.history.len();
    let previous_mean = monitor.history[history_len - 1].mean;
    let previous_timestamp = monitor.history[history_len - 1].timestamp;

    let drift = calculate_drift(&previous_mean, &current_baseline.mean);

    // Cập nhật state
    monitor.current_drift = drift;
    monitor.hourly_drift += drift;

    // Xác định direction
    monitor.drift_direction = determine_direction(&monitor.history);

    // Clone thresholds để sử dụng sau
    let pause_threshold = monitor.pause_threshold;
    let alert_threshold = monitor.alert_threshold;
    let max_drift_per_hour = monitor.max_drift_per_hour;

    // Kiểm tra thresholds
    let result = if drift >= pause_threshold {
        let reason = format!(
            "Drift quá cao: {:.1}% (ngưỡng: {:.1}%). Có thể baseline đang bị poisoning.",
            drift * 100.0,
            pause_threshold * 100.0
        );
        audit::log_drift_alert(drift, &reason);
        DriftResult::PauseLearning { drift, reason }
    } else if drift >= alert_threshold {
        let message = format!(
            "Drift bất thường: {:.1}% trong {} giây",
            drift * 100.0,
            Utc::now().timestamp() - previous_timestamp
        );
        audit::log_drift_alert(drift, &message);
        DriftResult::Alert { drift, message }
    } else if drift >= max_drift_per_hour / 60.0 {
        // Drift cao nhưng chưa đến mức alert
        let message = format!(
            "Drift đáng chú ý: {:.2}%",
            drift * 100.0
        );
        DriftResult::Warning { drift, message }
    } else {
        DriftResult::Normal
    };

    result
}

/// Kiểm tra drift trong 1 giờ qua
pub fn check_hourly_drift() -> DriftResult {
    let monitor = DRIFT_MONITOR.read();
    let drift = monitor.hourly_drift;

    if drift >= monitor.pause_threshold {
        DriftResult::PauseLearning {
            drift,
            reason: format!("Hourly drift: {:.1}% vượt ngưỡng", drift * 100.0),
        }
    } else if drift >= monitor.alert_threshold {
        DriftResult::Alert {
            drift,
            message: format!("Hourly drift: {:.1}%", drift * 100.0),
        }
    } else if drift >= monitor.max_drift_per_hour {
        DriftResult::Warning {
            drift,
            message: format!("Hourly drift: {:.1}%", drift * 100.0),
        }
    } else {
        DriftResult::Normal
    }
}

/// Lấy thống kê drift hiện tại
#[derive(Debug, Clone, serde::Serialize)]
pub struct DriftStats {
    pub current_drift: f32,
    pub hourly_drift: f32,
    pub direction: String,
    pub history_points: usize,
    pub max_drift_threshold: f32,
    pub alert_threshold: f32,
    pub is_healthy: bool,
}

pub fn get_stats() -> DriftStats {
    let monitor = DRIFT_MONITOR.read();

    DriftStats {
        current_drift: monitor.current_drift,
        hourly_drift: monitor.hourly_drift,
        direction: format!("{:?}", monitor.drift_direction),
        history_points: monitor.history.len(),
        max_drift_threshold: monitor.max_drift_per_hour,
        alert_threshold: monitor.alert_threshold,
        is_healthy: monitor.hourly_drift < monitor.alert_threshold,
    }
}

/// Lấy feature nào đóng góp nhiều nhất vào drift
pub fn get_top_drifting_features(limit: usize) -> Vec<(String, f32)> {
    let monitor = DRIFT_MONITOR.read();

    if monitor.history.len() < 2 {
        return Vec::new();
    }

    let previous = &monitor.history[monitor.history.len() - 2];
    let current = &monitor.history[monitor.history.len() - 1];

    let mut feature_drifts: Vec<(String, f32)> = (0..FEATURE_COUNT)
        .map(|i| {
            let name = crate::logic::features::layout::FEATURE_LAYOUT
                .get(i)
                .copied()
                .unwrap_or("unknown")
                .to_string();

            let drift = if previous.mean[i].abs() > 0.001 {
                ((current.mean[i] - previous.mean[i]) / previous.mean[i]).abs()
            } else {
                0.0
            };

            (name, drift)
        })
        .collect();

    // Sắp xếp theo drift giảm dần
    feature_drifts.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    feature_drifts.truncate(limit);

    feature_drifts
}

/// Reset drift monitor (khi reset baseline)
pub fn reset() {
    let mut monitor = DRIFT_MONITOR.write();
    monitor.history.clear();
    monitor.current_drift = 0.0;
    monitor.hourly_drift = 0.0;
    monitor.drift_direction = DriftDirection::Stable;
    monitor.last_hourly_reset = Utc::now().timestamp();
    log::info!("Drift monitor reset");
}

/// Cập nhật thresholds
pub fn set_thresholds(max_drift: f32, alert: f32, pause: f32) {
    let mut monitor = DRIFT_MONITOR.write();
    monitor.max_drift_per_hour = max_drift;
    monitor.alert_threshold = alert;
    monitor.pause_threshold = pause;
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/// Tính % drift giữa 2 mean vectors
fn calculate_drift(previous: &[f32; FEATURE_COUNT], current: &[f32; FEATURE_COUNT]) -> f32 {
    let mut total_drift = 0.0;
    let mut valid_features = 0;

    for i in 0..FEATURE_COUNT {
        // Bỏ qua features có giá trị quá nhỏ
        if previous[i].abs() < 0.001 {
            continue;
        }

        let drift = ((current[i] - previous[i]) / previous[i]).abs();
        total_drift += drift;
        valid_features += 1;
    }

    if valid_features > 0 {
        total_drift / valid_features as f32
    } else {
        0.0
    }
}

/// Xác định hướng drift dựa trên lịch sử
fn determine_direction(history: &[DriftPoint]) -> DriftDirection {
    if history.len() < 3 {
        return DriftDirection::Stable;
    }

    // Lấy 3 điểm gần nhất
    let n = history.len();
    let p1 = &history[n - 3];
    let p2 = &history[n - 2];
    let p3 = &history[n - 1];

    // Tính tổng mean để so sánh trend
    let sum1: f32 = p1.mean.iter().sum();
    let sum2: f32 = p2.mean.iter().sum();
    let sum3: f32 = p3.mean.iter().sum();

    let trend1 = sum2 - sum1;
    let trend2 = sum3 - sum2;

    if trend1.abs() < 0.01 && trend2.abs() < 0.01 {
        DriftDirection::Stable
    } else if trend1 > 0.0 && trend2 > 0.0 {
        DriftDirection::Increasing
    } else if trend1 < 0.0 && trend2 < 0.0 {
        DriftDirection::Decreasing
    } else {
        DriftDirection::Erratic
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_drift() {
        let previous = [10.0; FEATURE_COUNT];
        let mut current = [10.0; FEATURE_COUNT];

        // Tất cả feature tăng 10%
        for i in 0..FEATURE_COUNT {
            current[i] = 11.0;
        }

        let drift = calculate_drift(&previous, &current);
        assert!((drift - 0.1).abs() < 0.01); // ~10% drift
    }

    #[test]
    fn test_drift_thresholds() {
        // Setup
        init(0.05, 0.10, 0.20);

        // Create baseline with small drift
        let mut baseline = VersionedBaseline::new("test");
        baseline.mean = [10.0; FEATURE_COUNT];

        record_baseline(&baseline);

        // Small change - should be normal
        baseline.mean = [10.05; FEATURE_COUNT]; // 0.5% change
        record_baseline(&baseline);

        let result = check_drift(&baseline);
        assert!(result.is_safe());
    }
}
