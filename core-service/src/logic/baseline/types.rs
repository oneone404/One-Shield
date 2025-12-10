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
