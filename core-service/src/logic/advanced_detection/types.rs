//! AMSI Types - Shared types for AMSI scanning

use serde::{Deserialize, Serialize};

/// Threat level from AMSI scan
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Content is clean
    Clean,
    /// Content is not detected as malware (below threshold)
    NotDetected,
    /// Content is blocked by admin policy
    BlockedByAdmin,
    /// Content is detected as malware
    Malware,
}

impl ThreatLevel {
    pub fn is_malicious(&self) -> bool {
        matches!(self, ThreatLevel::Malware | ThreatLevel::BlockedByAdmin)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatLevel::Clean => "Clean",
            ThreatLevel::NotDetected => "Not Detected",
            ThreatLevel::BlockedByAdmin => "Blocked by Admin",
            ThreatLevel::Malware => "Malware",
        }
    }
}

/// Result of an AMSI scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Content that was scanned (truncated for large content)
    pub content_preview: String,
    /// Type of content (e.g., "PowerShell", "VBScript")
    pub content_type: String,
    /// Raw AMSI result value
    pub amsi_result: u32,
    /// Interpreted threat level
    pub threat_level: ThreatLevel,
    /// Whether the content should be blocked
    pub should_block: bool,
    /// Scan duration in milliseconds
    pub scan_duration_ms: u64,
    /// Timestamp of scan
    pub timestamp: i64,
}

impl ScanResult {
    pub fn new(content: &str, content_type: &str, amsi_result: u32, duration_ms: u64) -> Self {
        let threat_level = Self::interpret_result(amsi_result);
        Self {
            content_preview: if content.len() > 100 {
                format!("{}...", &content[..100])
            } else {
                content.to_string()
            },
            content_type: content_type.to_string(),
            amsi_result,
            threat_level,
            should_block: threat_level.is_malicious(),
            scan_duration_ms: duration_ms,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Interpret AMSI result value
    /// See: https://docs.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result
    fn interpret_result(result: u32) -> ThreatLevel {
        // AMSI_RESULT values:
        // 0 = AMSI_RESULT_CLEAN
        // 1 = AMSI_RESULT_NOT_DETECTED
        // 16384 (0x4000) = AMSI_RESULT_BLOCKED_BY_ADMIN_START
        // 20479 (0x4FFF) = AMSI_RESULT_BLOCKED_BY_ADMIN_END
        // 32768 (0x8000) = AMSI_RESULT_DETECTED (malware threshold)
        match result {
            0 => ThreatLevel::Clean,
            1..=16383 => ThreatLevel::NotDetected,
            16384..=20479 => ThreatLevel::BlockedByAdmin,
            _ if result >= 32768 => ThreatLevel::Malware,
            _ => ThreatLevel::NotDetected,
        }
    }
}

/// Error types for AMSI operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AmsiError {
    /// AMSI is not available on this system
    NotAvailable,
    /// Failed to initialize AMSI
    InitFailed { code: u32 },
    /// Failed to open session
    SessionFailed { code: u32 },
    /// Scan failed
    ScanFailed { code: u32 },
    /// Invalid content (null bytes, too large, etc.)
    InvalidContent { reason: String },
    /// Other error
    Other { message: String },
}

impl std::fmt::Display for AmsiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AmsiError::NotAvailable => write!(f, "AMSI is not available on this system"),
            AmsiError::InitFailed { code } => write!(f, "AMSI init failed: 0x{:08X}", code),
            AmsiError::SessionFailed { code } => write!(f, "AMSI session failed: 0x{:08X}", code),
            AmsiError::ScanFailed { code } => write!(f, "AMSI scan failed: 0x{:08X}", code),
            AmsiError::InvalidContent { reason } => write!(f, "Invalid content: {}", reason),
            AmsiError::Other { message } => write!(f, "AMSI error: {}", message),
        }
    }
}

impl std::error::Error for AmsiError {}

/// Statistics for AMSI scanning
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AmsiStats {
    pub total_scans: u64,
    pub clean_count: u64,
    pub malware_count: u64,
    pub blocked_count: u64,
    pub error_count: u64,
    pub avg_scan_time_ms: f64,
}
