//! Memory Scanning Types

use serde::{Deserialize, Serialize};

/// Type of memory pattern detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellcodeType {
    /// Generic shellcode pattern
    Generic,
    /// Windows API resolution (GetProcAddress pattern)
    ApiResolution,
    /// Metasploit shellcode
    Metasploit,
    /// Cobalt Strike beacon
    CobaltStrike,
    /// Reverse shell
    ReverseShell,
    /// Bind shell
    BindShell,
    /// Egg hunter
    EggHunter,
    /// Socket operations
    SocketCode,
    /// NOP sled
    NopSled,
    /// Encoded/obfuscated shellcode
    Encoded,
}

impl ShellcodeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShellcodeType::Generic => "Generic Shellcode",
            ShellcodeType::ApiResolution => "API Resolution Shellcode",
            ShellcodeType::Metasploit => "Metasploit Shellcode",
            ShellcodeType::CobaltStrike => "Cobalt Strike Beacon",
            ShellcodeType::ReverseShell => "Reverse Shell",
            ShellcodeType::BindShell => "Bind Shell",
            ShellcodeType::EggHunter => "Egg Hunter",
            ShellcodeType::SocketCode => "Socket Shellcode",
            ShellcodeType::NopSled => "NOP Sled",
            ShellcodeType::Encoded => "Encoded Shellcode",
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            ShellcodeType::CobaltStrike => 10,
            ShellcodeType::Metasploit => 9,
            ShellcodeType::ReverseShell => 9,
            ShellcodeType::BindShell => 8,
            ShellcodeType::ApiResolution => 7,
            ShellcodeType::EggHunter => 7,
            ShellcodeType::SocketCode => 6,
            ShellcodeType::Encoded => 6,
            ShellcodeType::NopSled => 5,
            ShellcodeType::Generic => 5,
        }
    }

    pub fn mitre_id(&self) -> &'static str {
        "T1055" // Process Injection
    }
}

/// Result of a memory scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanResult {
    /// Process ID scanned
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Type of shellcode detected
    pub shellcode_type: ShellcodeType,
    /// Confidence (0-100)
    pub confidence: u8,
    /// Offset where pattern was found
    pub offset: usize,
    /// Pattern that matched
    pub pattern_name: String,
    /// Match length
    pub match_length: usize,
    /// Timestamp
    pub timestamp: i64,
}

impl MemoryScanResult {
    pub fn new(
        pid: u32,
        process_name: &str,
        shellcode_type: ShellcodeType,
        confidence: u8,
        offset: usize,
        pattern_name: &str,
        match_length: usize,
    ) -> Self {
        Self {
            pid,
            process_name: process_name.to_string(),
            shellcode_type,
            confidence,
            offset,
            pattern_name: pattern_name.to_string(),
            match_length,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn is_critical(&self) -> bool {
        self.confidence >= 80 && self.shellcode_type.severity() >= 8
    }
}

/// Statistics for memory scanning
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryScanStats {
    pub total_scans: u64,
    pub bytes_scanned: u64,
    pub detections: u64,
    pub critical_detections: u64,
    pub avg_scan_time_ms: f64,
}

/// Error types for memory scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryScanError {
    /// Process not found
    ProcessNotFound { pid: u32 },
    /// Access denied
    AccessDenied { pid: u32 },
    /// Scan failed
    ScanFailed { reason: String },
}

impl std::fmt::Display for MemoryScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryScanError::ProcessNotFound { pid } => write!(f, "Process {} not found", pid),
            MemoryScanError::AccessDenied { pid } => write!(f, "Access denied to process {}", pid),
            MemoryScanError::ScanFailed { reason } => write!(f, "Scan failed: {}", reason),
        }
    }
}

impl std::error::Error for MemoryScanError {}

