//! DLL Injection Detection Types

use serde::{Deserialize, Serialize};

/// Type of injection technique detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InjectionType {
    /// CreateRemoteThread injection
    RemoteThread,
    /// QueueUserAPC injection
    ApcInjection,
    /// SetWindowsHookEx injection
    WindowsHook,
    /// Atom bombing
    AtomBombing,
    /// Process hollowing
    ProcessHollowing,
    /// DLL side-loading
    DllSideLoading,
    /// Reflective DLL injection
    ReflectiveDll,
    /// Thread hijacking
    ThreadHijacking,
    /// Unknown technique
    Unknown,
}

impl InjectionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            InjectionType::RemoteThread => "Remote Thread Creation",
            InjectionType::ApcInjection => "APC Injection",
            InjectionType::WindowsHook => "Windows Hook",
            InjectionType::AtomBombing => "Atom Bombing",
            InjectionType::ProcessHollowing => "Process Hollowing",
            InjectionType::DllSideLoading => "DLL Side-Loading",
            InjectionType::ReflectiveDll => "Reflective DLL",
            InjectionType::ThreadHijacking => "Thread Hijacking",
            InjectionType::Unknown => "Unknown",
        }
    }

    pub fn mitre_id(&self) -> &'static str {
        match self {
            InjectionType::RemoteThread => "T1055.001",
            InjectionType::ApcInjection => "T1055.004",
            InjectionType::WindowsHook => "T1055.001",
            InjectionType::AtomBombing => "T1055.001",
            InjectionType::ProcessHollowing => "T1055.012",
            InjectionType::DllSideLoading => "T1574.002",
            InjectionType::ReflectiveDll => "T1055.001",
            InjectionType::ThreadHijacking => "T1055.003",
            InjectionType::Unknown => "T1055",
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            InjectionType::ProcessHollowing => 10,
            InjectionType::ReflectiveDll => 9,
            InjectionType::RemoteThread => 8,
            InjectionType::ThreadHijacking => 8,
            InjectionType::ApcInjection => 7,
            InjectionType::AtomBombing => 7,
            InjectionType::WindowsHook => 6,
            InjectionType::DllSideLoading => 5,
            InjectionType::Unknown => 5,
        }
    }
}

/// Alert for injection detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionAlert {
    /// Source process ID
    pub source_pid: u32,
    /// Source process name
    pub source_name: String,
    /// Target process ID
    pub target_pid: u32,
    /// Target process name
    pub target_name: String,
    /// Type of injection
    pub injection_type: InjectionType,
    /// Confidence (0-100)
    pub confidence: u8,
    /// MITRE ATT&CK ID
    pub mitre_id: String,
    /// Description
    pub description: String,
    /// Timestamp
    pub timestamp: i64,
}

impl InjectionAlert {
    pub fn new(
        source_pid: u32,
        source_name: &str,
        target_pid: u32,
        target_name: &str,
        injection_type: InjectionType,
        confidence: u8,
    ) -> Self {
        Self {
            source_pid,
            source_name: source_name.to_string(),
            target_pid,
            target_name: target_name.to_string(),
            injection_type,
            confidence,
            mitre_id: injection_type.mitre_id().to_string(),
            description: format!(
                "{} ({}) attempting {} on {} ({})",
                source_name, source_pid, injection_type.as_str(), target_name, target_pid
            ),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn is_critical(&self) -> bool {
        self.confidence >= 80 && self.injection_type.severity() >= 8
    }
}

/// Statistics for injection detection
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InjectionStats {
    pub total_checks: u64,
    pub alerts_count: u64,
    pub critical_count: u64,
    pub blocked_count: u64,
    pub by_type: std::collections::HashMap<String, u64>,
}

/// Error types for injection detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionError {
    /// Process not found
    ProcessNotFound { pid: u32 },
    /// Access denied
    AccessDenied { pid: u32 },
    /// Detection failed
    DetectionFailed { reason: String },
}

impl std::fmt::Display for InjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectionError::ProcessNotFound { pid } => write!(f, "Process {} not found", pid),
            InjectionError::AccessDenied { pid } => write!(f, "Access denied to process {}", pid),
            InjectionError::DetectionFailed { reason } => write!(f, "Detection failed: {}", reason),
        }
    }
}

impl std::error::Error for InjectionError {}
