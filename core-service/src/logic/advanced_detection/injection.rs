//! DLL Injection Detection - Monitor for Code Injection Techniques
//!
//! Detects various injection techniques by analyzing:
//! - Process relationships and spawning patterns
//! - Suspicious process behavior
//! - Known malware injection patterns
//!
//! # Detection Methods
//! 1. Heuristic pattern matching on process names and command lines
//! 2. Parent-child relationship anomaly detection
//! 3. Known injection tool signatures
//!
//! # Usage
//! ```ignore
//! use crate::logic::advanced_detection::injection;
//!
//! injection::init();
//!
//! // Check for injection patterns
//! let alerts = injection::analyze_process(pid, name, cmdline, parent_name);
//! for alert in alerts {
//!     if alert.is_critical() {
//!         // Take action
//!     }
//! }
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::{HashMap, HashSet};
use parking_lot::Mutex;
use once_cell::sync::Lazy;

use super::injection_types::{InjectionType, InjectionAlert, InjectionStats, InjectionError};

// ============================================================================
// GLOBAL STATE
// ============================================================================

static STATS: Lazy<Mutex<InjectionStats>> = Lazy::new(|| Mutex::new(InjectionStats::default()));
static INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// INJECTION PATTERNS DATABASE
// ============================================================================

/// Processes that commonly inject into others (suspicious sources)
const SUSPICIOUS_INJECTORS: &[&str] = &[
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "msiexec.exe",
];

/// Processes commonly targeted for injection
const COMMON_TARGETS: &[&str] = &[
    "explorer.exe",
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "spoolsv.exe",
    "wininit.exe",
    "notepad.exe",
    "calc.exe",
    "iexplore.exe",
    "firefox.exe",
    "chrome.exe",
];

/// High-value targets (credential/security processes)
const CRITICAL_TARGETS: &[&str] = &[
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "wininit.exe",
    "smss.exe",
];

/// Known injection tool names
const INJECTION_TOOLS: &[&str] = &[
    "inject",
    "injector",
    "hollowing",
    "migrate",
    "reflective",
    "shellcode",
    "payload",
    "meterpreter",
    "cobalt",
    "beacon",
    "donut",
    "srdi",
    "shellter",
    "veil",
];

/// Suspicious command line patterns indicating injection
const SUSPICIOUS_CMDLINE_PATTERNS: &[&str] = &[
    // Process hollowing indicators
    "/c start /b",
    "CREATE_SUSPENDED",
    "NtUnmapViewOfSection",

    // Remote thread indicators
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "NtWriteVirtualMemory",

    // APC injection
    "QueueUserAPC",
    "NtQueueApcThread",

    // Reflective loading
    "ReflectiveLoader",
    "MemoryModule",

    // Common injection tools
    "-inject",
    "/inject",
    "-pid",
    "--pid",
    "-target",
    "--target",
    "-process",
    "--process",

    // Base64/encoded payloads
    "-enc ",
    "-e ",
    "FromBase64String",
    "[Convert]::FromBase64String",

    // PowerShell injection cmdlets
    "Invoke-DllInjection",
    "Invoke-Shellcode",
    "Invoke-ReflectivePEInjection",
];

/// Suspicious parent-child relationships
const SUSPICIOUS_SPAWN_PATTERNS: &[(&str, &str)] = &[
    // Office spawning cmd/powershell
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    // Browser spawning scripts
    ("iexplore.exe", "wscript.exe"),
    ("iexplore.exe", "cscript.exe"),
    // Script hosts spawning other processes
    ("wscript.exe", "cmd.exe"),
    ("cscript.exe", "powershell.exe"),
    // Services spawning unexpected children
    ("svchost.exe", "mshta.exe"),
    ("svchost.exe", "regsvr32.exe"),
    // Suspicious spawns from system processes
    ("services.exe", "cmd.exe"),
    ("lsass.exe", "cmd.exe"),
    ("csrss.exe", "powershell.exe"),
];

// ============================================================================
// DETECTION ENGINE
// ============================================================================

/// Injection Detector
pub struct InjectionDetector {
    /// Track recent process activity for correlation
    recent_activity: HashMap<u32, Vec<ProcessActivity>>,
    /// Known parent-child relationships
    process_tree: HashMap<u32, u32>,
    /// Alert history
    alerts: Vec<InjectionAlert>,
    max_alerts: usize,
}

#[derive(Clone)]
struct ProcessActivity {
    pid: u32,
    name: String,
    cmdline: String,
    parent_pid: Option<u32>,
    timestamp: i64,
}

impl InjectionDetector {
    pub fn new() -> Self {
        Self {
            recent_activity: HashMap::new(),
            process_tree: HashMap::new(),
            alerts: Vec::new(),
            max_alerts: 1000,
        }
    }

    /// Analyze a process for injection indicators
    pub fn analyze_process(
        &mut self,
        pid: u32,
        name: &str,
        cmdline: &str,
        parent_pid: Option<u32>,
        parent_name: Option<&str>,
    ) -> Vec<InjectionAlert> {
        let mut alerts = Vec::new();
        let name_lower = name.to_lowercase();
        let cmdline_lower = cmdline.to_lowercase();

        // Record activity
        let activity = ProcessActivity {
            pid,
            name: name.to_string(),
            cmdline: cmdline.to_string(),
            parent_pid,
            timestamp: chrono::Utc::now().timestamp(),
        };
        self.recent_activity.entry(pid).or_default().push(activity);

        // Check 1: Known injection tool names
        for tool in INJECTION_TOOLS {
            if name_lower.contains(tool) || cmdline_lower.contains(tool) {
                alerts.push(InjectionAlert::new(
                    pid, name, 0, "unknown",
                    InjectionType::Unknown,
                    85,
                ));
            }
        }

        // Check 2: Suspicious command line patterns
        let mut cmdline_score = 0u32;
        let mut found_patterns = Vec::new();

        for pattern in SUSPICIOUS_CMDLINE_PATTERNS {
            if cmdline_lower.contains(&pattern.to_lowercase()) {
                cmdline_score += 1;
                found_patterns.push(*pattern);
            }
        }

        if cmdline_score >= 2 {
            let injection_type = self.classify_injection_type(&found_patterns);
            alerts.push(InjectionAlert::new(
                pid, name, 0, "unknown",
                injection_type,
                (50 + cmdline_score * 10).min(95) as u8,
            ));
        }

        // Check 3: Suspicious parent-child relationships
        if let (Some(ppid), Some(pname)) = (parent_pid, parent_name) {
            let pname_lower = pname.to_lowercase();

            for (parent_pattern, child_pattern) in SUSPICIOUS_SPAWN_PATTERNS {
                if pname_lower.contains(&parent_pattern.to_lowercase())
                    && name_lower.contains(&child_pattern.to_lowercase())
                {
                    alerts.push(InjectionAlert::new(
                        ppid, pname, pid, name,
                        InjectionType::Unknown,
                        75,
                    ));
                }
            }

            // Check if targeting critical processes
            for target in CRITICAL_TARGETS {
                if name_lower == *target {
                    // Non-system process accessing critical process
                    if !CRITICAL_TARGETS.contains(&pname_lower.as_str())
                        && pname_lower != "services.exe"
                    {
                        alerts.push(InjectionAlert::new(
                            ppid, pname, pid, name,
                            InjectionType::RemoteThread,
                            80,
                        ));
                    }
                }
            }
        }

        // Check 4: Is this a suspicious injector process?
        let is_suspicious_injector = SUSPICIOUS_INJECTORS
            .iter()
            .any(|s| name_lower.contains(&s.to_lowercase()));

        let targets_critical = CRITICAL_TARGETS
            .iter()
            .any(|t| cmdline_lower.contains(&t.to_lowercase()));

        if is_suspicious_injector && targets_critical {
            alerts.push(InjectionAlert::new(
                pid, name, 0, "critical_process",
                InjectionType::RemoteThread,
                90,
            ));
        }

        // Update stats
        update_stats(|s| {
            s.total_checks += 1;
            s.alerts_count += alerts.len() as u64;
            s.critical_count += alerts.iter().filter(|a| a.is_critical()).count() as u64;
            for alert in &alerts {
                *s.by_type.entry(alert.injection_type.as_str().to_string()).or_default() += 1;
            }
        });

        // Store alerts
        for alert in &alerts {
            self.alerts.push(alert.clone());
            if self.alerts.len() > self.max_alerts {
                self.alerts.remove(0);
            }

            log::warn!(
                "Injection detected: {} -> {} ({}) [{}%]",
                alert.source_name, alert.target_name,
                alert.injection_type.as_str(), alert.confidence
            );
        }

        alerts
    }

    /// Classify injection type based on patterns found
    fn classify_injection_type(&self, patterns: &[&str]) -> InjectionType {
        for pattern in patterns {
            let p = pattern.to_lowercase();
            if p.contains("hollowing") || p.contains("unmapviewofsection") {
                return InjectionType::ProcessHollowing;
            }
            if p.contains("reflective") {
                return InjectionType::ReflectiveDll;
            }
            if p.contains("apc") || p.contains("queueapc") {
                return InjectionType::ApcInjection;
            }
            if p.contains("createremotethread") {
                return InjectionType::RemoteThread;
            }
            if p.contains("hook") {
                return InjectionType::WindowsHook;
            }
        }
        InjectionType::Unknown
    }

    /// Get recent alerts
    pub fn get_recent_alerts(&self, limit: usize) -> Vec<InjectionAlert> {
        let start = if self.alerts.len() > limit {
            self.alerts.len() - limit
        } else {
            0
        };
        self.alerts[start..].to_vec()
    }

    /// Clear old activity data
    pub fn cleanup(&mut self) {
        let cutoff = chrono::Utc::now().timestamp() - 3600; // 1 hour
        self.recent_activity.retain(|_, activities| {
            activities.retain(|a| a.timestamp > cutoff);
            !activities.is_empty()
        });
    }
}

impl Default for InjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GLOBAL INSTANCE
// ============================================================================

static DETECTOR: Lazy<Mutex<InjectionDetector>> = Lazy::new(|| Mutex::new(InjectionDetector::new()));

// ============================================================================
// PUBLIC API
// ============================================================================

/// Initialize injection detection
pub fn init() {
    if INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    INITIALIZED.store(true, Ordering::SeqCst);
    log::info!("Injection detection initialized");
}

/// Check if initialized
pub fn is_available() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

/// Analyze a process for injection patterns
pub fn analyze_process(
    pid: u32,
    name: &str,
    cmdline: &str,
    parent_pid: Option<u32>,
    parent_name: Option<&str>,
) -> Vec<InjectionAlert> {
    DETECTOR.lock().analyze_process(pid, name, cmdline, parent_pid, parent_name)
}

/// Quick check if a process exhibits injection behavior
pub fn is_suspicious(
    pid: u32,
    name: &str,
    cmdline: &str,
    parent_pid: Option<u32>,
    parent_name: Option<&str>,
) -> bool {
    !analyze_process(pid, name, cmdline, parent_pid, parent_name).is_empty()
}

/// Get recent injection alerts
pub fn get_recent_alerts(limit: usize) -> Vec<InjectionAlert> {
    DETECTOR.lock().get_recent_alerts(limit)
}

/// Get detection statistics
pub fn get_stats() -> InjectionStats {
    STATS.lock().clone()
}

/// Reset statistics
pub fn reset_stats() {
    *STATS.lock() = InjectionStats::default();
}

/// Cleanup old data
pub fn cleanup() {
    DETECTOR.lock().cleanup();
}

fn update_stats<F: FnOnce(&mut InjectionStats)>(f: F) {
    f(&mut STATS.lock());
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_process() {
        init();
        let alerts = analyze_process(
            1234, "notepad.exe", "notepad.exe C:\\test.txt",
            Some(5678), Some("explorer.exe")
        );
        // Notepad from explorer is normal
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_injection_tool_detection() {
        init();
        let alerts = analyze_process(
            1234, "injector.exe", "injector.exe -pid 5678",
            None, None
        );
        assert!(!alerts.is_empty());
    }

    #[test]
    fn test_suspicious_cmdline() {
        init();
        let alerts = analyze_process(
            1234, "powershell.exe",
            "powershell.exe Invoke-DllInjection -pid 5678",
            None, None
        );
        assert!(!alerts.is_empty());
    }

    #[test]
    fn test_suspicious_spawn() {
        init();
        let alerts = analyze_process(
            1234, "cmd.exe", "cmd.exe /c whoami",
            Some(5678), Some("winword.exe")
        );
        // Word spawning cmd is suspicious
        assert!(!alerts.is_empty());
    }

    #[test]
    fn test_critical_process_access() {
        init();
        // Test with powershell targeting lsass (suspicious injector + critical target)
        let alerts = analyze_process(
            1234, "powershell.exe", "powershell.exe -target lsass.exe -inject",
            None, None
        );
        assert!(!alerts.is_empty());
    }
}
