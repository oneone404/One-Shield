//! Process Intelligence Types - Shared Types (Phase 2)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ============================================================================
// SIGNATURE TYPES
// ============================================================================

/// Kết quả kiểm tra chữ ký số
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignatureStatus {
    /// Có chữ ký hợp lệ từ publisher tin cậy
    Trusted {
        publisher: String,
        issuer: String,
    },
    /// Có chữ ký nhưng publisher không trong whitelist
    SignedUntrusted {
        publisher: String,
    },
    /// Không có chữ ký
    Unsigned,
    /// Chữ ký không hợp lệ (bị tamper)
    Invalid {
        reason: String,
    },
    /// Lỗi khi kiểm tra (file not found, etc.)
    Error {
        message: String,
    },
}

impl SignatureStatus {
    pub fn is_trusted(&self) -> bool {
        matches!(self, SignatureStatus::Trusted { .. })
    }

    pub fn is_signed(&self) -> bool {
        matches!(self, SignatureStatus::Trusted { .. } | SignatureStatus::SignedUntrusted { .. })
    }

    pub fn trust_level(&self) -> u8 {
        match self {
            SignatureStatus::Trusted { .. } => 3,
            SignatureStatus::SignedUntrusted { .. } => 2,
            SignatureStatus::Unsigned => 1,
            SignatureStatus::Invalid { .. } => 0,
            SignatureStatus::Error { .. } => 0,
        }
    }
}

// ============================================================================
// PROCESS INFO TYPES
// ============================================================================

/// Thông tin chi tiết về một process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
    pub cmdline: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub start_time: i64,
    pub signature: SignatureStatus,
    pub user: Option<String>,
    pub session_id: Option<u32>,
}

impl ProcessInfo {
    pub fn new(pid: u32, name: String) -> Self {
        Self {
            pid,
            name,
            exe_path: None,
            cmdline: None,
            parent_pid: None,
            parent_name: None,
            start_time: chrono::Utc::now().timestamp(),
            signature: SignatureStatus::Unsigned,
            user: None,
            session_id: None,
        }
    }

    /// Kiểm tra xem process có phải system process không
    pub fn is_system_process(&self) -> bool {
        // System processes thường có PID < 100 hoặc là các tên đặc biệt
        self.pid < 100 || matches!(
            self.name.to_lowercase().as_str(),
            "system" | "csrss.exe" | "smss.exe" | "wininit.exe" |
            "services.exe" | "lsass.exe" | "svchost.exe" | "dwm.exe"
        )
    }
}

// ============================================================================
// SPAWN TYPES
// ============================================================================

/// Alert khi phát hiện spawn đáng ngờ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousSpawnAlert {
    pub child: ProcessInfo,
    pub parent: ProcessInfo,
    pub reason: String,
    pub severity: SpawnSeverity,
    pub rule_id: String,
    pub mitre_technique: Option<String>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpawnSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl SpawnSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            SpawnSeverity::Low => "Low",
            SpawnSeverity::Medium => "Medium",
            SpawnSeverity::High => "High",
            SpawnSeverity::Critical => "Critical",
        }
    }
}

// ============================================================================
// REPUTATION TYPES
// ============================================================================

/// Điểm reputation của một executable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationEntry {
    pub exe_hash: String,           // SHA256 của file
    pub exe_name: String,
    pub exe_path: PathBuf,
    pub first_seen: i64,            // Unix timestamp
    pub last_seen: i64,
    pub times_seen: u64,
    pub anomaly_count: u64,
    pub alert_count: u64,
    pub reputation_score: f32,      // 0.0 (bad) - 1.0 (trusted)
    pub signature: SignatureStatus,
    pub flags: ReputationFlags,
}

impl ReputationEntry {
    pub fn new(exe_hash: String, exe_name: String, exe_path: PathBuf) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            exe_hash,
            exe_name,
            exe_path,
            first_seen: now,
            last_seen: now,
            times_seen: 1,
            anomaly_count: 0,
            alert_count: 0,
            reputation_score: 0.5, // Neutral by default
            signature: SignatureStatus::Unsigned,
            flags: ReputationFlags::default(),
        }
    }

    /// Cập nhật sau mỗi lần thấy
    pub fn record_seen(&mut self) {
        self.last_seen = chrono::Utc::now().timestamp();
        self.times_seen += 1;
        self.recalculate_score();
    }

    /// Ghi nhận anomaly
    pub fn record_anomaly(&mut self) {
        self.anomaly_count += 1;
        self.recalculate_score();
    }

    /// Ghi nhận alert
    pub fn record_alert(&mut self) {
        self.alert_count += 1;
        self.anomaly_count += 1;
        self.recalculate_score();
    }

    /// Tính lại reputation score
    fn recalculate_score(&mut self) {
        let now = chrono::Utc::now().timestamp();
        let age_days = ((now - self.first_seen) as f32 / 86400.0).max(0.0);

        // Factors:
        // 1. Age: Older = more trusted (max 0.3 after 30 days)
        let age_factor = (age_days / 30.0).min(1.0) * 0.3;

        // 2. Clean rate: Lower anomaly rate = more trusted (max 0.4)
        let anomaly_rate = if self.times_seen > 0 {
            self.anomaly_count as f32 / self.times_seen as f32
        } else {
            0.0
        };
        let clean_factor = (1.0 - anomaly_rate) * 0.4;

        // 3. Signature: Signed = more trusted (0.2 for signed, 0.3 for trusted)
        let signature_factor = match &self.signature {
            SignatureStatus::Trusted { .. } => 0.3,
            SignatureStatus::SignedUntrusted { .. } => 0.2,
            SignatureStatus::Unsigned => 0.0,
            SignatureStatus::Invalid { .. } => -0.2,
            SignatureStatus::Error { .. } => 0.0,
        };

        self.reputation_score = (age_factor + clean_factor + signature_factor).clamp(0.0, 1.0);
    }

    /// Tuổi của entry (ngày)
    pub fn age_days(&self) -> f32 {
        let now = chrono::Utc::now().timestamp();
        (now - self.first_seen) as f32 / 86400.0
    }
}

/// Flags đặc biệt cho reputation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReputationFlags {
    pub is_lolbin: bool,            // Living-off-the-land binary
    pub is_known_malware: bool,     // Known malware hash
    pub is_whitelisted: bool,       // Admin whitelisted
    pub is_blacklisted: bool,       // Admin blacklisted
    pub spawns_children: bool,      // Đã từng spawn child processes
    pub network_activity: bool,     // Đã từng có network activity
    pub registry_access: bool,      // Đã từng access registry
    pub persistence_behavior: bool, // Đã từng ghi vào run keys
}

// ============================================================================
// TREE TYPES
// ============================================================================

/// Node trong process tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeNode {
    pub info: ProcessInfo,
    pub children: Vec<u32>,         // PIDs of children
    pub depth: u32,                 // Depth in tree (0 = root)
}

/// Kết quả phân tích process tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeAnalysisResult {
    pub root_pid: u32,
    pub total_descendants: usize,
    pub max_depth: u32,
    pub suspicious_chains: Vec<SuspiciousChain>,
}

/// Chain của processes đáng ngờ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousChain {
    pub chain: Vec<ProcessInfo>,    // From root to leaf
    pub reason: String,
    pub severity: SpawnSeverity,
}

// ============================================================================
// LOLBIN TYPES
// ============================================================================

/// Thông tin về một LOLBin (compile-time only, not deserializable)
#[derive(Debug, Clone, Copy)]
pub struct LolbinInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub risk_level: SpawnSeverity,
    pub mitre_techniques: &'static [&'static str],
    pub suspicious_parents: &'static [&'static str],
}

// ============================================================================
// TRUSTED PUBLISHERS
// ============================================================================

/// Danh sách publishers tin cậy mặc định
pub const TRUSTED_PUBLISHERS: &[&str] = &[
    "Microsoft Corporation",
    "Microsoft Windows",
    "Microsoft Windows Publisher",
    "Google LLC",
    "Google Inc",
    "Mozilla Corporation",
    "Apple Inc.",
    "Adobe Inc.",
    "Valve",
    "NVIDIA Corporation",
    "Intel Corporation",
    "AMD",
    "Realtek Semiconductor Corp.",
];

/// Kiểm tra publisher có trong whitelist không
pub fn is_publisher_trusted(publisher: &str) -> bool {
    let publisher_lower = publisher.to_lowercase();
    TRUSTED_PUBLISHERS.iter().any(|&trusted| {
        publisher_lower.contains(&trusted.to_lowercase())
    })
}
