//! Behavioral Signatures Types (Phase 3)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::net::IpAddr;

// ============================================================================
// BEACONING TYPES
// ============================================================================

/// Alert khi phát hiện beaconing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconAlert {
    pub endpoint: String,
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub interval_seconds: f32,
    pub jitter_percent: f32,
    pub sample_count: usize,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub severity: BeaconSeverity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BeaconSeverity {
    Low,        // Có thể là legit (updates, heartbeat)
    Medium,     // Đáng ngờ
    High,       // Rất có thể là C2
    Critical,   // Chắc chắn là C2 (known bad endpoint)
}

// ============================================================================
// PERSISTENCE TYPES
// ============================================================================

/// Alert khi phát hiện persistence mechanism
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceAlert {
    pub mechanism: PersistenceMechanism,
    pub location: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub process_name: String,
    pub process_pid: u32,
    pub timestamp: i64,
    pub severity: PersistenceSeverity,
    pub mitre_technique: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PersistenceMechanism {
    RunKey,
    RunOnceKey,
    ScheduledTask,
    Service,
    StartupFolder,
    ImageFileExecution,
    WmiSubscription,
    ComHijack,
    AppInitDll,
    Other(String),
}

impl PersistenceMechanism {
    pub fn mitre_technique(&self) -> &'static str {
        match self {
            PersistenceMechanism::RunKey => "T1547.001",
            PersistenceMechanism::RunOnceKey => "T1547.001",
            PersistenceMechanism::ScheduledTask => "T1053.005",
            PersistenceMechanism::Service => "T1543.003",
            PersistenceMechanism::StartupFolder => "T1547.001",
            PersistenceMechanism::ImageFileExecution => "T1546.012",
            PersistenceMechanism::WmiSubscription => "T1546.003",
            PersistenceMechanism::ComHijack => "T1546.015",
            PersistenceMechanism::AppInitDll => "T1546.010",
            PersistenceMechanism::Other(_) => "T1547",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            PersistenceMechanism::RunKey => "Registry Run Key",
            PersistenceMechanism::RunOnceKey => "Registry RunOnce Key",
            PersistenceMechanism::ScheduledTask => "Scheduled Task",
            PersistenceMechanism::Service => "Windows Service",
            PersistenceMechanism::StartupFolder => "Startup Folder",
            PersistenceMechanism::ImageFileExecution => "Image File Execution Options",
            PersistenceMechanism::WmiSubscription => "WMI Event Subscription",
            PersistenceMechanism::ComHijack => "COM Object Hijacking",
            PersistenceMechanism::AppInitDll => "AppInit DLLs",
            PersistenceMechanism::Other(_) => "Other Persistence",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PersistenceSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

// ============================================================================
// RULE TYPES
// ============================================================================

/// Một behavioral rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralRuleDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub severity: RuleSeverity,
    pub mitre_technique: Option<String>,
    pub conditions: Vec<RuleCondition>,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl RuleSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleSeverity::Info => "Info",
            RuleSeverity::Low => "Low",
            RuleSeverity::Medium => "Medium",
            RuleSeverity::High => "High",
            RuleSeverity::Critical => "Critical",
        }
    }
}

/// Điều kiện của rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    // Process conditions
    ProcessName { pattern: String, is_regex: bool },
    ProcessPath { pattern: String, is_regex: bool },
    ProcessCmdline { pattern: String, is_regex: bool },
    ParentProcessName { pattern: String, is_regex: bool },
    ProcessUnsigned,

    // Network conditions
    NetworkConnection { dest_pattern: String },
    NetworkPort { port: u16 },
    NetworkProtocol { protocol: String },
    NetworkBytes { min_bytes: u64 },

    // File conditions
    FileWrite { path_pattern: String },
    FileRead { path_pattern: String },
    FileDelete { path_pattern: String },

    // Registry conditions
    RegistryWrite { key_pattern: String },
    RegistryRead { key_pattern: String },

    // Feature conditions
    CpuUsageAbove { threshold: f32 },
    MemoryUsageAbove { threshold: f32 },
    NetworkRateAbove { threshold: f32 },

    // Composite
    And(Vec<RuleCondition>),
    Or(Vec<RuleCondition>),
    Not(Box<RuleCondition>),
}

/// Action khi rule match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Alert,              // Chỉ alert
    NeverLearn,         // Không học vào baseline
    Block,              // Block process (future)
    Quarantine,         // Quarantine file (future)
    Custom(String),     // Custom action
}

/// Kết quả khi rule match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: RuleSeverity,
    pub mitre_technique: Option<String>,
    pub matched_conditions: Vec<String>,
    pub context: MatchContext,
    pub timestamp: i64,
    pub action: RuleAction,
}

/// Context khi rule match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchContext {
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub process_path: Option<PathBuf>,
    pub parent_process_name: Option<String>,
    pub parent_pid: Option<u32>,
    pub extra: std::collections::HashMap<String, String>,
}

impl MatchContext {
    pub fn new() -> Self {
        Self {
            process_name: None,
            process_pid: None,
            process_path: None,
            parent_process_name: None,
            parent_pid: None,
            extra: std::collections::HashMap::new(),
        }
    }

    pub fn with_process(mut self, name: &str, pid: u32) -> Self {
        self.process_name = Some(name.to_string());
        self.process_pid = Some(pid);
        self
    }
}

impl Default for MatchContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// NEVER LEARN TYPES
// ============================================================================

/// Reason tại sao sample không được học
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NeverLearnReason {
    ProcessBlacklisted { name: String },
    HashBlacklisted { hash: String },
    NetworkToTor,
    NetworkToKnownC2 { endpoint: String },
    RegistryPersistence { key: String },
    UnsignedWithNetwork,
    UnsignedWithDiskWrite,
    BeaconingDetected { endpoint: String },
    CustomRule { rule_id: String },
}

impl NeverLearnReason {
    pub fn description(&self) -> String {
        match self {
            NeverLearnReason::ProcessBlacklisted { name } =>
                format!("Process '{}' is blacklisted", name),
            NeverLearnReason::HashBlacklisted { hash } =>
                format!("Hash {} is blacklisted", &hash[..16.min(hash.len())]),
            NeverLearnReason::NetworkToTor =>
                "Network connection to Tor".to_string(),
            NeverLearnReason::NetworkToKnownC2 { endpoint } =>
                format!("Network connection to known C2: {}", endpoint),
            NeverLearnReason::RegistryPersistence { key } =>
                format!("Registry persistence: {}", key),
            NeverLearnReason::UnsignedWithNetwork =>
                "Unsigned process with network activity".to_string(),
            NeverLearnReason::UnsignedWithDiskWrite =>
                "Unsigned process with disk write activity".to_string(),
            NeverLearnReason::BeaconingDetected { endpoint } =>
                format!("Beaconing detected to {}", endpoint),
            NeverLearnReason::CustomRule { rule_id } =>
                format!("Custom rule: {}", rule_id),
        }
    }
}

// ============================================================================
// SAMPLE CONTEXT
// ============================================================================

/// Context đầy đủ của một sample để evaluate rules
#[derive(Debug, Clone, Default)]
pub struct SampleContext {
    // Process info
    pub process_name: Option<String>,
    pub process_path: Option<PathBuf>,
    pub process_pid: Option<u32>,
    pub process_cmdline: Option<String>,
    pub process_hash: Option<String>,
    pub process_signed: Option<bool>,

    // Parent info
    pub parent_name: Option<String>,
    pub parent_pid: Option<u32>,

    // Network
    pub has_network_activity: bool,
    pub network_destinations: Vec<String>,
    pub network_bytes_sent: u64,
    pub network_bytes_recv: u64,

    // File
    pub has_disk_write: bool,
    pub files_written: Vec<PathBuf>,

    // Registry
    pub registry_writes: Vec<String>,

    // Features
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub network_rate: f32,
}

impl SampleContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_process(mut self, name: &str, pid: u32) -> Self {
        self.process_name = Some(name.to_string());
        self.process_pid = Some(pid);
        self
    }
}
