//! External Intelligence Types (Phase 4)

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ============================================================================
// VIRUSTOTAL TYPES
// ============================================================================

/// Kết quả từ VirusTotal API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VTResult {
    pub sha256: String,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
    pub file_type: Option<String>,

    /// Số engine phát hiện là malicious
    pub malicious: u32,
    /// Số engine phát hiện là suspicious
    pub suspicious: u32,
    /// Tổng số engines đã scan
    pub total_engines: u32,

    /// Ngày file first seen trên VT
    pub first_seen: Option<i64>,
    /// Ngày scan gần nhất
    pub last_scan: Option<i64>,

    /// Detection names từ các engines
    pub detection_names: Vec<String>,

    /// Cached locally?
    pub is_cached: bool,
    /// Thời gian cache
    pub cached_at: Option<i64>,
}

impl VTResult {
    /// Tỷ lệ phát hiện (0.0 - 1.0)
    pub fn detection_ratio(&self) -> f32 {
        if self.total_engines == 0 {
            return 0.0;
        }
        (self.malicious + self.suspicious) as f32 / self.total_engines as f32
    }

    /// Đánh giá threat level dựa trên kết quả VT
    pub fn threat_level(&self) -> ThreatLevel {
        let ratio = self.detection_ratio();

        if ratio >= 0.5 {
            ThreatLevel::Critical
        } else if ratio >= 0.25 {
            ThreatLevel::High
        } else if ratio >= 0.1 {
            ThreatLevel::Medium
        } else if ratio > 0.0 {
            ThreatLevel::Low
        } else {
            ThreatLevel::Unknown
        }
    }

    /// Có phải malware không (theo VT)
    pub fn is_malware(&self) -> bool {
        self.malicious >= 3 || self.detection_ratio() >= 0.1
    }
}

/// Thống kê nhanh từ VT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VTStats {
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub harmless: u32,
    pub timeout: u32,
    pub type_unsupported: u32,
}

/// VirusTotal error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VTError {
    /// API key không hợp lệ
    InvalidApiKey,
    /// Rate limit exceeded
    RateLimited { retry_after: u64 },
    /// File không tìm thấy trên VT
    NotFound,
    /// Network error
    NetworkError { message: String },
    /// Parse error
    ParseError { message: String },
    /// Other error
    Other { message: String },
}

impl std::fmt::Display for VTError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VTError::InvalidApiKey => write!(f, "Invalid VirusTotal API key"),
            VTError::RateLimited { retry_after } =>
                write!(f, "Rate limited, retry after {} seconds", retry_after),
            VTError::NotFound => write!(f, "File not found on VirusTotal"),
            VTError::NetworkError { message } => write!(f, "Network error: {}", message),
            VTError::ParseError { message } => write!(f, "Parse error: {}", message),
            VTError::Other { message } => write!(f, "Error: {}", message),
        }
    }
}

impl std::error::Error for VTError {}

// ============================================================================
// THREAT FEED TYPES
// ============================================================================

/// Một threat indicator từ feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub threat_level: ThreatLevel,
    pub source: String,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub tags: Vec<String>,
    pub description: Option<String>,
}

/// Loại indicator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorType {
    IPv4,
    IPv6,
    Domain,
    Url,
    Sha256,
    Sha1,
    Md5,
    Email,
}

impl IndicatorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            IndicatorType::IPv4 => "ipv4",
            IndicatorType::IPv6 => "ipv6",
            IndicatorType::Domain => "domain",
            IndicatorType::Url => "url",
            IndicatorType::Sha256 => "sha256",
            IndicatorType::Sha1 => "sha1",
            IndicatorType::Md5 => "md5",
            IndicatorType::Email => "email",
        }
    }
}

/// Mức độ threat
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatLevel {
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl ThreatLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatLevel::Unknown => "Unknown",
            ThreatLevel::Low => "Low",
            ThreatLevel::Medium => "Medium",
            ThreatLevel::High => "High",
            ThreatLevel::Critical => "Critical",
        }
    }
}

// ============================================================================
// MITRE ATT&CK TYPES
// ============================================================================

/// MITRE ATT&CK Technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,           // "T1055"
    pub name: String,         // "Process Injection"
    pub tactic: MitreTactic,
    pub description: String,
    pub url: String,
    pub sub_techniques: Vec<String>,
}

/// MITRE ATT&CK Tactic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MitreTactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl MitreTactic {
    pub fn as_str(&self) -> &'static str {
        match self {
            MitreTactic::InitialAccess => "Initial Access",
            MitreTactic::Execution => "Execution",
            MitreTactic::Persistence => "Persistence",
            MitreTactic::PrivilegeEscalation => "Privilege Escalation",
            MitreTactic::DefenseEvasion => "Defense Evasion",
            MitreTactic::CredentialAccess => "Credential Access",
            MitreTactic::Discovery => "Discovery",
            MitreTactic::LateralMovement => "Lateral Movement",
            MitreTactic::Collection => "Collection",
            MitreTactic::CommandAndControl => "Command and Control",
            MitreTactic::Exfiltration => "Exfiltration",
            MitreTactic::Impact => "Impact",
        }
    }

    pub fn id(&self) -> &'static str {
        match self {
            MitreTactic::InitialAccess => "TA0001",
            MitreTactic::Execution => "TA0002",
            MitreTactic::Persistence => "TA0003",
            MitreTactic::PrivilegeEscalation => "TA0004",
            MitreTactic::DefenseEvasion => "TA0005",
            MitreTactic::CredentialAccess => "TA0006",
            MitreTactic::Discovery => "TA0007",
            MitreTactic::LateralMovement => "TA0008",
            MitreTactic::Collection => "TA0009",
            MitreTactic::CommandAndControl => "TA0011",
            MitreTactic::Exfiltration => "TA0010",
            MitreTactic::Impact => "TA0040",
        }
    }
}

// ============================================================================
// API RESPONSE TYPES (for parsing VT API)
// ============================================================================

/// VirusTotal API Response (for parsing)
#[derive(Debug, Deserialize)]
pub struct VTApiResponse {
    pub data: VTApiData,
}

#[derive(Debug, Deserialize)]
pub struct VTApiData {
    pub id: String,
    #[serde(rename = "type")]
    pub data_type: String,
    pub attributes: VTApiAttributes,
}

#[derive(Debug, Deserialize)]
pub struct VTApiAttributes {
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub size: Option<u64>,
    pub type_description: Option<String>,
    pub meaningful_name: Option<String>,
    pub first_submission_date: Option<i64>,
    pub last_analysis_date: Option<i64>,
    pub last_analysis_stats: Option<VTApiStats>,
    pub last_analysis_results: Option<std::collections::HashMap<String, VTApiEngineResult>>,
}

#[derive(Debug, Deserialize)]
pub struct VTApiStats {
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub harmless: u32,
    pub timeout: u32,
    #[serde(rename = "type-unsupported")]
    pub type_unsupported: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct VTApiEngineResult {
    pub category: String,
    pub engine_name: String,
    pub result: Option<String>,
}
