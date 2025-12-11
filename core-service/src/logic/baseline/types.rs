use serde::{Deserialize, Serialize};
use crate::logic::features::layout::{FEATURE_COUNT, FEATURE_VERSION, layout_hash};

// ============================================================================
// VERSIONED BASELINE (P1.2)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedBaseline {
    pub feature_version: u8,
    pub layout_hash: u32,
    pub samples: u64,

    // Statistics for all features (in order of layout)
    pub mean: [f32; FEATURE_COUNT],
    pub variance: [f32; FEATURE_COUNT],

    // Original metadata
    pub id: String,
    pub name: String,
    pub created_at: i64,      // Unix timestamp
    pub last_updated: i64,    // Unix timestamp
    pub typical_hours: Vec<u8>,
}

impl VersionedBaseline {
    pub fn new(name: &str) -> Self {
        Self {
            feature_version: FEATURE_VERSION,
            layout_hash: layout_hash(),
            samples: 0,
            mean: [0.0; FEATURE_COUNT],
            variance: [0.0; FEATURE_COUNT],
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            created_at: chrono::Utc::now().timestamp(),
            last_updated: chrono::Utc::now().timestamp(),
            typical_hours: (8..22).collect(),
        }
    }

    /// Reset stats while keeping metadata
    pub fn reset_stats(&mut self) {
        self.feature_version = FEATURE_VERSION;
        self.layout_hash = layout_hash();
        self.samples = 0;
        self.mean = [0.0; FEATURE_COUNT];
        self.variance = [0.0; FEATURE_COUNT];
        self.last_updated = chrono::Utc::now().timestamp();
    }
}

// ============================================================================
// ANOMALY TAGS (Moved from baseline.rs)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyTag {
    // Resource tags (Severity: Low-Medium)
    HighCpu,                // 2.0
    HighMemory,             // 2.0

    // Network tags (Severity: Medium-High)
    UnusualNetwork,         // 2.5
    NetworkSpike,           // 3.5
    NetworkPortScan,        // 4.5

    // Process tags (Severity: Medium-Very High)
    NewProcess,             // 2.5
    ProcessSpike,           // 3.0
    SuspiciousPattern,      // 4.0

    // Disk tags (Severity: Medium-High)
    RapidDiskActivity,      // 3.0

    // Time/Behavior tags (Severity: Medium)
    UnusualTime,            // 2.5

    // Memory leak (Severity: High)
    MemoryLeak,             // 3.5

    // Combined/Cross-feature tags (Severity: High-Critical)
    HighChurnRate,          // 3.5
    MultipleSpikes,         // 4.0
    CoordinatedActivity,    // 4.5
    CriticalAnomaly,        // 5.0
}

impl AnomalyTag {
    pub fn severity(&self) -> f32 {
        match self {
            AnomalyTag::HighCpu => 2.0,
            AnomalyTag::HighMemory => 2.0,
            AnomalyTag::UnusualNetwork => 2.5,
            AnomalyTag::NewProcess => 2.5,
            AnomalyTag::UnusualTime => 2.5,
            AnomalyTag::RapidDiskActivity => 3.0,
            AnomalyTag::ProcessSpike => 3.0,
            AnomalyTag::NetworkSpike => 3.5,
            AnomalyTag::MemoryLeak => 3.5,
            AnomalyTag::HighChurnRate => 3.5,
            AnomalyTag::SuspiciousPattern => 4.0,
            AnomalyTag::MultipleSpikes => 4.0,
            AnomalyTag::NetworkPortScan => 4.5,
            AnomalyTag::CoordinatedActivity => 4.5,
            AnomalyTag::CriticalAnomaly => 5.0,
        }
    }

    pub fn to_string(&self) -> String {
        format!("{:?}", self).to_uppercase() // e.g. "HIGH_CPU"
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

// ============================================================================
// ANALYSIS RESULT
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub summary_id: String,
    pub ml_score: f32,
    pub tag_score: f32,
    pub final_score: f32,
    pub is_anomaly: bool,
    pub tags: Vec<String>,
    pub tag_details: Vec<TagDetail>,
    pub confidence: f32,
    pub severity_level: String,
    pub analyzed_at: String, // ISO 8601 string

    // Captured features for replay/training (P2.2.3)
    #[serde(default)]
    pub features: Vec<f32>,

    #[serde(default)]
    pub baseline_diff: Vec<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagDetail {
    pub tag: String,
    pub severity: f32,
    pub description: String,
}

// ============================================================================
// LEGACY COMPATIBILITY (For UI/API)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyBaselineProfile {
    pub id: String,
    pub name: String,
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

    // Feature crosses mapped
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

    pub typical_hours: Vec<u8>,
    pub sample_count: u64,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl From<&VersionedBaseline> for LegacyBaselineProfile {
    fn from(b: &VersionedBaseline) -> Self {
        let mean = &b.mean;
        let std: Vec<f32> = b.variance.iter().map(|v| v.sqrt()).collect();

        // Helper to safe get
        let m = |idx| mean.get(idx).copied().unwrap_or(0.0);
        let s = |idx| std.get(idx).copied().unwrap_or(0.0);

        // Layout mapping (P1.1):
        // 0: cpu, 1: cpu_spike
        // 2: mem, 3: mem_spike
        // 4: net_sent, 5: net_recv, 6: net_ratio
        // 7: disk_read, 8: disk_write, 9: combined_io
        // 10: unique_procs, 11: new_proc_rate, 12: churn_rate
        // 13: cpu_mem_prod, 14: spike_corr

        Self {
            id: b.id.clone(),
            name: b.name.clone(),

            avg_cpu: m(0),
            std_cpu: s(0),
            avg_memory: m(2),
            std_memory: s(2),
            avg_network_sent: m(4),
            std_network_sent: s(4),
            avg_network_recv: m(5),
            std_network_recv: s(5),
            avg_disk_read: m(7),
            std_disk_read: s(7),
            avg_disk_write: m(8),
            std_disk_write: s(8),
            avg_processes: m(10), // unique_processes
            std_processes: s(10),

            // Feature crosses
            avg_cpu_spike_rate: m(1),
            std_cpu_spike_rate: s(1),
            avg_memory_spike_rate: m(3),
            std_memory_spike_rate: s(3),
            avg_new_process_rate: m(11),
            std_new_process_rate: s(11),
            avg_disk_io_rate: m(9), // combined_io
            std_disk_io_rate: s(9),
            avg_churn_rate: m(12),
            std_churn_rate: s(12),

            typical_hours: b.typical_hours.clone(),
            sample_count: b.samples,
            last_updated: chrono::DateTime::from_timestamp(b.last_updated, 0)
                .unwrap_or_default()
                .with_timezone(&chrono::Utc),
        }
    }
}

// ============================================================================
// PHASE 1: ANTI-POISONING TYPES (v1.1)
// ============================================================================

/// Sample đang chờ xét duyệt trong Quarantine Queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSample {
    pub id: String,
    pub features: Vec<f32>,
    pub first_seen: i64,          // Unix timestamp khi sample được thêm vào queue
    pub last_checked: i64,        // Unix timestamp lần check gần nhất
    pub clean_streak: u32,        // Số lần liên tiếp được đánh giá sạch
    pub total_checks: u32,        // Tổng số lần check
    pub ml_scores: Vec<f32>,      // Lịch sử ML scores
    pub avg_score: f32,           // Score trung bình
}

impl PendingSample {
    pub fn new(features: Vec<f32>) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            features,
            first_seen: now,
            last_checked: now,
            clean_streak: 0,
            total_checks: 0,
            ml_scores: Vec::new(),
            avg_score: 0.0,
        }
    }

    /// Cập nhật với score mới
    pub fn update_score(&mut self, score: f32, is_clean: bool) {
        self.last_checked = chrono::Utc::now().timestamp();
        self.total_checks += 1;
        self.ml_scores.push(score);

        // Giữ tối đa 100 scores gần nhất
        if self.ml_scores.len() > 100 {
            self.ml_scores.remove(0);
        }

        // Tính average score
        self.avg_score = self.ml_scores.iter().sum::<f32>() / self.ml_scores.len() as f32;

        // Cập nhật clean streak
        if is_clean {
            self.clean_streak += 1;
        } else {
            self.clean_streak = 0;
        }
    }

    /// Thời gian chờ (phút)
    pub fn wait_time_minutes(&self) -> f32 {
        let now = chrono::Utc::now().timestamp();
        (now - self.first_seen) as f32 / 60.0
    }
}

/// Thống kê Quarantine Queue (cho UI)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuarantineStats {
    pub pending: usize,           // Số sample đang chờ
    pub accepted: usize,          // Tổng số đã chấp nhận học
    pub rejected: usize,          // Tổng số bị từ chối
    pub avg_delay_minutes: f32,   // Thời gian chờ trung bình
    pub oldest_sample_minutes: f32, // Sample cũ nhất đã chờ bao lâu
    pub queue_health: QueueHealth,  // Trạng thái queue
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub enum QueueHealth {
    #[default]
    Healthy,            // Queue hoạt động bình thường
    Warning,            // Queue đang đầy hoặc có vấn đề nhỏ
    Critical,           // Queue bị overflow hoặc có vấn đề nghiêm trọng
    Paused,             // Learning đang bị tạm dừng
}

/// Entry trong Audit Log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: i64,           // Unix timestamp
    pub action: AuditAction,      // Loại action
    pub sample_id: Option<String>,// ID của sample liên quan
    pub features_changed: Vec<String>, // Features bị thay đổi
    pub drift_score: f32,         // Drift score tại thời điểm này
    pub details: String,          // Chi tiết thêm
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditAction {
    BaselineUpdate,       // Baseline được cập nhật
    BaselineReset,        // Baseline bị reset
    BaselineRollback,     // Rollback về snapshot cũ
    SampleAccepted,       // Sample được chấp nhận học
    SampleRejected,       // Sample bị từ chối
    DriftAlert,           // Cảnh báo drift bất thường
    LearningPaused,       // Learning bị tạm dừng
    LearningResumed,      // Learning được resume
    SnapshotCreated,      // Tạo snapshot mới
}

impl AuditLogEntry {
    pub fn new(action: AuditAction) -> Self {
        Self {
            timestamp: chrono::Utc::now().timestamp(),
            action,
            sample_id: None,
            features_changed: Vec::new(),
            drift_score: 0.0,
            details: String::new(),
        }
    }

    pub fn with_sample(mut self, sample_id: &str) -> Self {
        self.sample_id = Some(sample_id.to_string());
        self
    }

    pub fn with_features(mut self, features: Vec<String>) -> Self {
        self.features_changed = features;
        self
    }

    pub fn with_drift(mut self, drift: f32) -> Self {
        self.drift_score = drift;
        self
    }

    pub fn with_details(mut self, details: &str) -> Self {
        self.details = details.to_string();
        self
    }
}

/// Kết quả kiểm tra Drift
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DriftResult {
    Normal,                       // Drift trong giới hạn cho phép
    Warning { drift: f32, message: String },  // Drift đáng chú ý
    Alert { drift: f32, message: String },    // Drift nghiêm trọng - cần pause
    PauseLearning { drift: f32, reason: String }, // Drift quá cao - pause learning
}

impl DriftResult {
    pub fn is_safe(&self) -> bool {
        matches!(self, DriftResult::Normal)
    }

    pub fn drift_value(&self) -> f32 {
        match self {
            DriftResult::Normal => 0.0,
            DriftResult::Warning { drift, .. } => *drift,
            DriftResult::Alert { drift, .. } => *drift,
            DriftResult::PauseLearning { drift, .. } => *drift,
        }
    }
}

/// Snapshot của Baseline để rollback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub id: String,
    pub timestamp: i64,           // Unix timestamp khi tạo snapshot
    pub baseline: VersionedBaseline,
    pub trigger: SnapshotTrigger, // Lý do tạo snapshot
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnapshotTrigger {
    Scheduled,            // Snapshot định kỳ
    ManualBackup,         // User request backup
    BeforeReset,          // Trước khi reset baseline
    DriftAlert,           // Khi phát hiện drift bất thường
}

impl BaselineSnapshot {
    pub fn new(baseline: VersionedBaseline, trigger: SnapshotTrigger) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            baseline,
            trigger,
        }
    }

    /// Tuổi của snapshot (giờ)
    pub fn age_hours(&self) -> f32 {
        let now = chrono::Utc::now().timestamp();
        (now - self.timestamp) as f32 / 3600.0
    }
}

/// Cấu hình cho Anti-Poisoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiPoisoningConfig {
    // Quarantine settings
    pub quarantine_delay_hours: u32,      // Chờ bao lâu trước khi học (mặc định: 6)
    pub quarantine_clean_streak: u32,     // Cần bao nhiêu checks sạch liên tiếp (mặc định: 180)
    pub quarantine_max_size: usize,       // Max samples trong queue (mặc định: 10000)

    // Drift settings
    pub drift_max_per_hour: f32,          // Max drift cho phép/giờ (mặc định: 0.05 = 5%)
    pub drift_alert_threshold: f32,       // Alert nếu drift > này (mặc định: 0.10 = 10%)

    // Snapshot settings
    pub snapshot_interval_minutes: u32,   // Snapshot mỗi X phút (mặc định: 60)
    pub snapshot_max_count: usize,        // Giữ tối đa bao nhiêu snapshots (mặc định: 24)

    // Feature voting
    pub require_all_groups_clean: bool,   // Tất cả 6 nhóm phải sạch mới học (mặc định: true)
}

impl Default for AntiPoisoningConfig {
    fn default() -> Self {
        Self {
            quarantine_delay_hours: 6,
            quarantine_clean_streak: 180,
            quarantine_max_size: 10_000,
            drift_max_per_hour: 0.05,
            drift_alert_threshold: 0.10,
            snapshot_interval_minutes: 60,
            snapshot_max_count: 24,
            require_all_groups_clean: true,
        }
    }
}

/// Kết quả Multi-Feature Voting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVotingResult {
    pub can_learn: bool,
    pub clean_groups: Vec<String>,
    pub dirty_groups: Vec<String>,
    pub group_scores: Vec<(String, f32)>,  // (group_name, deviation_score)
}
