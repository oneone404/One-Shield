//! Import Address Table (IAT) Analysis Module (Phase 9)
//!
//! Analyze PE file imports to detect suspicious API combinations:
//! - Process injection combo (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
//! - Credential theft combo (Lsa* APIs)
//! - Evasion combo (Nt* undocumented APIs)
//! - Keylogger combo (GetAsyncKeyState + SetWindowsHookEx)
//!
//! MITRE ATT&CK: Multiple techniques

#![allow(dead_code)]

use std::collections::HashSet;
use std::path::Path;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

// ============================================================================
// GLOBAL STATE
// ============================================================================

/// Analysis results cache
static CACHE: Lazy<RwLock<std::collections::HashMap<String, IatAnalysisResult>>> =
    Lazy::new(|| RwLock::new(std::collections::HashMap::new()));

/// Module statistics
static STATS: Lazy<RwLock<IatStats>> =
    Lazy::new(|| RwLock::new(IatStats::default()));

// ============================================================================
// SUSPICIOUS API COMBINATIONS
// ============================================================================

/// API combo for process injection (T1055)
pub const INJECTION_COMBO: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
];

/// Alternative injection combo
pub const INJECTION_COMBO_ALT: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
];

/// APC Injection combo (T1055.004)
pub const APC_INJECTION_COMBO: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "QueueUserAPC",
];

/// Thread hijacking combo (T1055.003)
pub const THREAD_HIJACK_COMBO: &[&str] = &[
    "OpenThread",
    "SuspendThread",
    "SetThreadContext",
    "ResumeThread",
];

/// Process hollowing combo (T1055.012)
pub const HOLLOWING_COMBO: &[&str] = &[
    "CreateProcessW",
    "NtUnmapViewOfSection",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "SetThreadContext",
];

/// Credential theft combo (T1003)
pub const CREDENTIAL_THEFT_COMBO: &[&str] = &[
    "LsaOpenPolicy",
    "LsaQueryInformationPolicy",
];

/// LSASS access combo (T1003.001)
pub const LSASS_ACCESS_COMBO: &[&str] = &[
    "OpenProcess",
    "ReadProcessMemory",
    "MiniDumpWriteDump",
];

/// Keylogger combo (T1056.001)
pub const KEYLOGGER_COMBO: &[&str] = &[
    "GetAsyncKeyState",
    "SetWindowsHookExW",
];

/// Keylogger combo alternative
pub const KEYLOGGER_COMBO_ALT: &[&str] = &[
    "GetKeyboardState",
    "GetForegroundWindow",
    "GetWindowTextW",
];

/// Screen capture combo (T1113)
pub const SCREEN_CAPTURE_COMBO: &[&str] = &[
    "GetDC",
    "BitBlt",
    "CreateCompatibleBitmap",
];

/// Network evasion combo
pub const NETWORK_EVASION_COMBO: &[&str] = &[
    "InternetOpenW",
    "InternetConnectW",
    "HttpOpenRequestW",
];

/// Registry persistence combo (T1547)
pub const REGISTRY_PERSIST_COMBO: &[&str] = &[
    "RegOpenKeyExW",
    "RegSetValueExW",
];

// ============================================================================
// TYPES
// ============================================================================

/// Single suspicious API combo definition
#[derive(Debug, Clone)]
pub struct SuspiciousCombo {
    pub name: &'static str,
    pub apis: &'static [&'static str],
    pub mitre_id: &'static str,
    pub mitre_name: &'static str,
    pub severity: u8,
    pub min_match: usize,  // Minimum APIs that must match
}

/// All defined combos
pub const SUSPICIOUS_COMBOS: &[SuspiciousCombo] = &[
    SuspiciousCombo {
        name: "Process Injection (Classic)",
        apis: INJECTION_COMBO,
        mitre_id: "T1055.001",
        mitre_name: "DLL Injection",
        severity: 95,
        min_match: 3,
    },
    SuspiciousCombo {
        name: "Process Injection (Native)",
        apis: INJECTION_COMBO_ALT,
        mitre_id: "T1055",
        mitre_name: "Process Injection",
        severity: 95,
        min_match: 3,
    },
    SuspiciousCombo {
        name: "APC Injection",
        apis: APC_INJECTION_COMBO,
        mitre_id: "T1055.004",
        mitre_name: "Asynchronous Procedure Call",
        severity: 90,
        min_match: 3,
    },
    SuspiciousCombo {
        name: "Thread Hijacking",
        apis: THREAD_HIJACK_COMBO,
        mitre_id: "T1055.003",
        mitre_name: "Thread Execution Hijacking",
        severity: 90,
        min_match: 4,
    },
    SuspiciousCombo {
        name: "Process Hollowing",
        apis: HOLLOWING_COMBO,
        mitre_id: "T1055.012",
        mitre_name: "Process Hollowing",
        severity: 95,
        min_match: 4,
    },
    SuspiciousCombo {
        name: "Credential Access (LSA)",
        apis: CREDENTIAL_THEFT_COMBO,
        mitre_id: "T1003",
        mitre_name: "OS Credential Dumping",
        severity: 90,
        min_match: 2,
    },
    SuspiciousCombo {
        name: "LSASS Memory Access",
        apis: LSASS_ACCESS_COMBO,
        mitre_id: "T1003.001",
        mitre_name: "LSASS Memory",
        severity: 95,
        min_match: 2,
    },
    SuspiciousCombo {
        name: "Keylogger",
        apis: KEYLOGGER_COMBO,
        mitre_id: "T1056.001",
        mitre_name: "Keylogging",
        severity: 85,
        min_match: 2,
    },
    SuspiciousCombo {
        name: "Keylogger (Alt)",
        apis: KEYLOGGER_COMBO_ALT,
        mitre_id: "T1056.001",
        mitre_name: "Keylogging",
        severity: 75,
        min_match: 3,
    },
    SuspiciousCombo {
        name: "Screen Capture",
        apis: SCREEN_CAPTURE_COMBO,
        mitre_id: "T1113",
        mitre_name: "Screen Capture",
        severity: 70,
        min_match: 3,
    },
    SuspiciousCombo {
        name: "Registry Persistence",
        apis: REGISTRY_PERSIST_COMBO,
        mitre_id: "T1547.001",
        mitre_name: "Registry Run Keys",
        severity: 60,
        min_match: 2,
    },
];

/// Single IAT alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatAlert {
    pub combo_name: String,
    pub mitre_id: String,
    pub mitre_name: String,
    pub severity: u8,
    pub matched_apis: Vec<String>,
    pub total_apis_in_combo: usize,
}

/// Full analysis result for a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatAnalysisResult {
    pub file_path: String,
    pub total_imports: usize,
    pub alerts: Vec<IatAlert>,
    pub is_suspicious: bool,
    pub max_severity: u8,
    pub timestamp: i64,
}

/// Module statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IatStats {
    pub total_scans: u64,
    pub suspicious_count: u64,
    pub critical_count: u64,
    pub cache_hits: u64,
    pub last_scan: i64,
}

// ============================================================================
// CORE LOGIC
// ============================================================================

/// Initialize IAT analysis module
pub fn init() {
    log::info!("IAT Analysis module initialized ({} combo patterns)", SUSPICIOUS_COMBOS.len());
}

/// Check if module is available
pub fn is_available() -> bool {
    true
}

/// Analyze a list of imports for suspicious combinations
pub fn analyze_imports(imports: &[String]) -> Vec<IatAlert> {
    let import_set: HashSet<String> = imports
        .iter()
        .map(|s| normalize_api_name(s))
        .collect();

    let mut alerts = Vec::new();

    for combo in SUSPICIOUS_COMBOS {
        let matched: Vec<String> = combo.apis
            .iter()
            .filter(|api| import_set.contains(&normalize_api_name(api)))
            .map(|s| s.to_string())
            .collect();

        if matched.len() >= combo.min_match {
            alerts.push(IatAlert {
                combo_name: combo.name.to_string(),
                mitre_id: combo.mitre_id.to_string(),
                mitre_name: combo.mitre_name.to_string(),
                severity: combo.severity,
                matched_apis: matched,
                total_apis_in_combo: combo.apis.len(),
            });
        }
    }

    alerts
}

/// Analyze a PE file's imports
pub fn analyze_file(path: &Path) -> Result<IatAnalysisResult, IatError> {
    let path_str = path.to_string_lossy().to_string();

    // Check cache first
    {
        let cache = CACHE.read();
        if let Some(cached) = cache.get(&path_str) {
            let mut stats = STATS.write();
            stats.cache_hits += 1;
            return Ok(cached.clone());
        }
    }

    // Read file
    let data = std::fs::read(path).map_err(|e| IatError::IoError(e.to_string()))?;

    // Parse imports
    let imports = parse_pe_imports(&data)?;

    // Analyze
    let alerts = analyze_imports(&imports);
    let max_severity = alerts.iter().map(|a| a.severity).max().unwrap_or(0);

    let result = IatAnalysisResult {
        file_path: path_str.clone(),
        total_imports: imports.len(),
        alerts: alerts.clone(),
        is_suspicious: !alerts.is_empty(),
        max_severity,
        timestamp: chrono::Utc::now().timestamp(),
    };

    // Update cache
    {
        let mut cache = CACHE.write();
        // Limit cache size
        if cache.len() > 1000 {
            cache.clear();
        }
        cache.insert(path_str, result.clone());
    }

    // Update stats
    {
        let mut stats = STATS.write();
        stats.total_scans += 1;
        if result.is_suspicious {
            stats.suspicious_count += 1;
        }
        if max_severity >= 90 {
            stats.critical_count += 1;
        }
        stats.last_scan = chrono::Utc::now().timestamp();
    }

    Ok(result)
}

/// Analyze raw binary data
pub fn analyze_binary(data: &[u8], source_name: &str) -> Result<IatAnalysisResult, IatError> {
    let imports = parse_pe_imports(data)?;
    let alerts = analyze_imports(&imports);
    let max_severity = alerts.iter().map(|a| a.severity).max().unwrap_or(0);

    Ok(IatAnalysisResult {
        file_path: source_name.to_string(),
        total_imports: imports.len(),
        alerts,
        is_suspicious: max_severity > 0,
        max_severity,
        timestamp: chrono::Utc::now().timestamp(),
    })
}

/// Get module statistics
pub fn get_stats() -> IatStats {
    STATS.read().clone()
}

/// Clear cache
pub fn clear_cache() {
    CACHE.write().clear();
}

// ============================================================================
// PE PARSING
// ============================================================================

/// Simplified PE import parser
fn parse_pe_imports(data: &[u8]) -> Result<Vec<String>, IatError> {
    // Check DOS header
    if data.len() < 64 {
        return Err(IatError::NotPe("File too small".to_string()));
    }

    if &data[0..2] != b"MZ" {
        return Err(IatError::NotPe("Not a PE file (no MZ)".to_string()));
    }

    // Get PE header offset
    let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

    if pe_offset + 4 > data.len() {
        return Err(IatError::NotPe("Invalid PE offset".to_string()));
    }

    // Check PE signature
    if &data[pe_offset..pe_offset+4] != b"PE\0\0" {
        return Err(IatError::NotPe("Invalid PE signature".to_string()));
    }

    // For now, return heuristic-based common imports
    // Real implementation would parse the Import Directory Table
    // This is a placeholder that can be replaced with goblin crate

    Ok(extract_api_strings(data))
}

/// Extract potential API names from binary (heuristic)
fn extract_api_strings(data: &[u8]) -> Vec<String> {
    let mut apis = Vec::new();

    // Common API patterns to search for
    let api_patterns: &[&str] = &[
        // Injection
        "VirtualAllocEx",
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "NtQueueApcThread",
        "OpenProcess",
        "ReadProcessMemory",
        "OpenThread",
        "SuspendThread",
        "ResumeThread",
        "SetThreadContext",
        "GetThreadContext",
        "NtUnmapViewOfSection",

        // Credential
        "LsaOpenPolicy",
        "LsaQueryInformationPolicy",
        "LsaRetrievePrivateData",
        "MiniDumpWriteDump",
        "CredEnumerate",
        "CryptUnprotectData",

        // Keylogger
        "GetAsyncKeyState",
        "GetKeyState",
        "GetKeyboardState",
        "SetWindowsHookExW",
        "SetWindowsHookExA",
        "RegisterRawInputDevices",
        "GetRawInputData",
        "GetForegroundWindow",
        "GetWindowTextW",
        "GetWindowTextA",
        "GetClipboardData",
        "OpenClipboard",

        // Screen
        "GetDC",
        "GetWindowDC",
        "BitBlt",
        "StretchBlt",
        "CreateCompatibleBitmap",
        "CreateCompatibleDC",

        // Network
        "WSAStartup",
        "socket",
        "connect",
        "send",
        "recv",
        "InternetOpenW",
        "InternetConnectW",
        "HttpOpenRequestW",
        "WinHttpOpen",

        // Registry
        "RegOpenKeyExW",
        "RegOpenKeyExA",
        "RegSetValueExW",
        "RegSetValueExA",
        "RegCreateKeyExW",

        // Other suspicious
        "CreateProcessW",
        "CreateProcessA",
        "ShellExecuteW",
        "WinExec",
        "LoadLibraryW",
        "LoadLibraryA",
        "GetProcAddress",
    ];

    // Search for each pattern in the binary
    for pattern in api_patterns {
        if contains_string(data, pattern) {
            apis.push(pattern.to_string());
        }
    }

    apis
}

/// Check if binary contains a string
fn contains_string(data: &[u8], needle: &str) -> bool {
    let needle_bytes = needle.as_bytes();
    data.windows(needle_bytes.len()).any(|window| window == needle_bytes)
}

/// Normalize API name (remove A/W suffix, lowercase)
fn normalize_api_name(name: &str) -> String {
    let mut normalized = name.to_string();

    // Only remove W/A Unicode/ANSI suffixes
    if normalized.ends_with('W') || normalized.ends_with('A') {
        if normalized.len() > 4 {
            normalized.pop();
        }
    }

    normalized.to_lowercase()
}

// ============================================================================
// ERROR TYPE
// ============================================================================

#[derive(Debug, Clone)]
pub enum IatError {
    IoError(String),
    NotPe(String),
    ParseError(String),
}

impl std::fmt::Display for IatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::NotPe(e) => write!(f, "Not a PE file: {}", e),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
        }
    }
}

impl std::error::Error for IatError {}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injection_combo() {
        let imports = vec![
            "VirtualAllocEx".to_string(),
            "WriteProcessMemory".to_string(),
            "CreateRemoteThread".to_string(),
        ];

        let alerts = analyze_imports(&imports);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].mitre_id, "T1055.001");
    }

    #[test]
    fn test_keylogger_combo() {
        let imports = vec![
            "GetAsyncKeyState".to_string(),
            "SetWindowsHookExW".to_string(),
        ];

        let alerts = analyze_imports(&imports);
        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| a.mitre_id == "T1056.001"));
    }

    #[test]
    fn test_clean_imports() {
        let imports = vec![
            "CreateFileW".to_string(),
            "ReadFile".to_string(),
            "WriteFile".to_string(),
            "CloseHandle".to_string(),
        ];

        let alerts = analyze_imports(&imports);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_normalize_api() {
        assert_eq!(normalize_api_name("CreateFileW"), "createfile");
        assert_eq!(normalize_api_name("RegOpenKeyExA"), "regopenkeyex"); // Strips A only
        assert_eq!(normalize_api_name("VirtualAllocEx"), "virtualallocex"); // No W/A to strip
    }

    #[test]
    fn test_lsass_combo() {
        let imports = vec![
            "OpenProcess".to_string(),
            "ReadProcessMemory".to_string(),
            "MiniDumpWriteDump".to_string(),
        ];

        let alerts = analyze_imports(&imports);
        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| a.mitre_id == "T1003.001"));
    }
}
