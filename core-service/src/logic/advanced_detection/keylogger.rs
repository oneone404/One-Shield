//! Keylogger Detection Module (Phase 9)
//!
//! Detect keylogger behavior patterns:
//! - High frequency GetAsyncKeyState calls
//! - Clipboard monitoring
//! - Window tracking for focus logging
//! - Suspicious log file patterns
//!
//! MITRE ATT&CK: T1056.001 - Keylogging

#![allow(dead_code)]

use std::collections::HashMap;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

// ============================================================================
// GLOBAL STATE
// ============================================================================

/// Track API call frequency per process
static API_TRACKER: Lazy<RwLock<HashMap<u32, ApiCallStats>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Keylogger alerts history
static ALERTS: Lazy<RwLock<Vec<KeyloggerAlert>>> =
    Lazy::new(|| RwLock::new(Vec::new()));

/// Detection statistics
static STATS: Lazy<RwLock<KeyloggerStats>> =
    Lazy::new(|| RwLock::new(KeyloggerStats::default()));

// ============================================================================
// TYPES
// ============================================================================

/// Suspicious APIs commonly abused by keyloggers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuspiciousApi {
    GetAsyncKeyState,
    GetKeyState,
    GetKeyboardState,
    SetWindowsHookEx,
    GetClipboardData,
    OpenClipboard,
    GetForegroundWindow,
    GetWindowText,
    RegisterRawInputDevices,
}

impl SuspiciousApi {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GetAsyncKeyState => "GetAsyncKeyState",
            Self::GetKeyState => "GetKeyState",
            Self::GetKeyboardState => "GetKeyboardState",
            Self::SetWindowsHookEx => "SetWindowsHookEx",
            Self::GetClipboardData => "GetClipboardData",
            Self::OpenClipboard => "OpenClipboard",
            Self::GetForegroundWindow => "GetForegroundWindow",
            Self::GetWindowText => "GetWindowText",
            Self::RegisterRawInputDevices => "RegisterRawInputDevices",
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            Self::GetAsyncKeyState => 80,
            Self::GetKeyboardState => 85,
            Self::SetWindowsHookEx => 90,
            Self::RegisterRawInputDevices => 85,
            Self::GetClipboardData => 70,
            Self::OpenClipboard => 60,
            Self::GetForegroundWindow => 50,
            Self::GetWindowText => 40,
            Self::GetKeyState => 60,
        }
    }

    /// Get from API name string
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "getasynckeystate" => Some(Self::GetAsyncKeyState),
            "getkeystate" => Some(Self::GetKeyState),
            "getkeyboardstate" => Some(Self::GetKeyboardState),
            "setwindowshookexw" | "setwindowshookexa" | "setwindowshookex" =>
                Some(Self::SetWindowsHookEx),
            "getclipboarddata" => Some(Self::GetClipboardData),
            "openclipboard" => Some(Self::OpenClipboard),
            "getforegroundwindow" => Some(Self::GetForegroundWindow),
            "getwindowtextw" | "getwindowtexta" | "getwindowtext" =>
                Some(Self::GetWindowText),
            "registerrawinputdevices" => Some(Self::RegisterRawInputDevices),
            _ => None,
        }
    }
}

/// API call frequency statistics per process
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiCallStats {
    pub pid: u32,
    pub process_name: String,
    pub get_async_key_state: u32,
    pub get_key_state: u32,
    pub get_keyboard_state: u32,
    pub set_windows_hook: u32,
    pub clipboard_access: u32,
    pub window_tracking: u32,
    pub raw_input: u32,
    pub last_reset: i64,
    pub total_calls: u32,
}

/// Keylogger detection alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyloggerAlert {
    pub pid: u32,
    pub process_name: String,
    pub confidence: u8,
    pub severity: u8,
    pub indicators: Vec<String>,
    pub mitre_id: String,
    pub mitre_name: String,
    pub timestamp: i64,
}

impl KeyloggerAlert {
    pub fn is_critical(&self) -> bool {
        self.confidence >= 80 || self.severity >= 85
    }
}

/// Module statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyloggerStats {
    pub total_checks: u64,
    pub alerts_count: u64,
    pub critical_count: u64,
    pub processes_monitored: u64,
    pub last_check: i64,
}

// ============================================================================
// THRESHOLDS (calls per minute)
// ============================================================================

/// Thresholds for suspicious activity
pub struct Thresholds {
    pub keyboard_polling: u32,      // GetAsyncKeyState
    pub keyboard_dump: u32,         // GetKeyboardState
    pub clipboard_access: u32,
    pub window_tracking: u32,
    pub combined_score: u32,        // Minimum score to trigger alert
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            keyboard_polling: 100,   // > 100 calls/min = suspicious
            keyboard_dump: 50,       // > 50 calls/min = suspicious
            clipboard_access: 10,    // > 10 accesses/min = suspicious
            window_tracking: 30,     // > 30 calls/min = suspicious
            combined_score: 50,      // Need 50+ points to alert
        }
    }
}

// ============================================================================
// CORE LOGIC
// ============================================================================

/// Initialize keylogger detection module
pub fn init() {
    log::info!("Keylogger detection initialized (T1056.001)");
}

/// Check if module is available
pub fn is_available() -> bool {
    true
}

/// Record an API call for a process
pub fn record_api_call(pid: u32, process_name: &str, api: SuspiciousApi) {
    let mut tracker = API_TRACKER.write();

    let stats = tracker.entry(pid).or_insert_with(|| ApiCallStats {
        pid,
        process_name: process_name.to_string(),
        last_reset: chrono::Utc::now().timestamp(),
        ..Default::default()
    });

    match api {
        SuspiciousApi::GetAsyncKeyState => stats.get_async_key_state += 1,
        SuspiciousApi::GetKeyState => stats.get_key_state += 1,
        SuspiciousApi::GetKeyboardState => stats.get_keyboard_state += 1,
        SuspiciousApi::SetWindowsHookEx => stats.set_windows_hook += 1,
        SuspiciousApi::GetClipboardData | SuspiciousApi::OpenClipboard =>
            stats.clipboard_access += 1,
        SuspiciousApi::GetForegroundWindow | SuspiciousApi::GetWindowText =>
            stats.window_tracking += 1,
        SuspiciousApi::RegisterRawInputDevices => stats.raw_input += 1,
    }

    stats.total_calls += 1;
}

/// Analyze a process for keylogger behavior (heuristic)
pub fn analyze_process(
    pid: u32,
    process_name: &str,
    imported_apis: &[String],
) -> Option<KeyloggerAlert> {
    let thresholds = Thresholds::default();
    let mut indicators = Vec::new();
    let mut score = 0u32;
    let mut max_severity = 0u8;

    // Check imported APIs (static analysis)
    let mut keyboard_apis = 0;
    let mut clipboard_apis = 0;
    let mut hook_apis = 0;

    for api_name in imported_apis {
        if let Some(api) = SuspiciousApi::from_name(api_name) {
            max_severity = max_severity.max(api.severity());

            match api {
                SuspiciousApi::GetAsyncKeyState |
                SuspiciousApi::GetKeyState |
                SuspiciousApi::GetKeyboardState => keyboard_apis += 1,

                SuspiciousApi::GetClipboardData |
                SuspiciousApi::OpenClipboard => clipboard_apis += 1,

                SuspiciousApi::SetWindowsHookEx |
                SuspiciousApi::RegisterRawInputDevices => hook_apis += 1,

                _ => {}
            }
        }
    }

    // Score based on API combinations
    if keyboard_apis >= 2 {
        indicators.push(format!(
            "Multiple keyboard APIs imported ({})",
            keyboard_apis
        ));
        score += 25;
    }

    if keyboard_apis >= 1 && clipboard_apis >= 1 {
        indicators.push("Keyboard + Clipboard API combination".to_string());
        score += 30;
    }

    if hook_apis >= 1 {
        indicators.push("Keyboard hooking API imported".to_string());
        score += 35;
    }

    if keyboard_apis >= 1 && hook_apis >= 1 {
        indicators.push("Keyboard API + Hook API combination".to_string());
        score += 20;
    }

    // Check runtime behavior (if we have stats)
    if let Some(stats) = API_TRACKER.read().get(&pid) {
        let age_seconds = (chrono::Utc::now().timestamp() - stats.last_reset).max(1);
        let calls_per_minute = |count: u32| (count as f64 / age_seconds as f64 * 60.0) as u32;

        let keyboard_rate = calls_per_minute(stats.get_async_key_state);
        if keyboard_rate > thresholds.keyboard_polling {
            indicators.push(format!(
                "High GetAsyncKeyState rate: {}/min",
                keyboard_rate
            ));
            score += 30;
        }

        let dump_rate = calls_per_minute(stats.get_keyboard_state);
        if dump_rate > thresholds.keyboard_dump {
            indicators.push(format!(
                "GetKeyboardState polling: {}/min",
                dump_rate
            ));
            score += 25;
        }

        let clipboard_rate = calls_per_minute(stats.clipboard_access);
        if clipboard_rate > thresholds.clipboard_access {
            indicators.push(format!(
                "Clipboard access: {}/min",
                clipboard_rate
            ));
            score += 20;
        }

        let window_rate = calls_per_minute(stats.window_tracking);
        if window_rate > thresholds.window_tracking {
            indicators.push(format!(
                "Window tracking: {}/min",
                window_rate
            ));
            score += 15;
        }
    }

    // Check process name patterns
    let name_lower = process_name.to_lowercase();
    if SUSPICIOUS_PROCESS_NAMES.iter().any(|p| name_lower.contains(p)) {
        indicators.push(format!("Suspicious process name: {}", process_name));
        score += 20;
    }

    // Create alert if score exceeds threshold
    if score >= thresholds.combined_score {
        let confidence = score.min(100) as u8;
        let alert = KeyloggerAlert {
            pid,
            process_name: process_name.to_string(),
            confidence,
            severity: max_severity.max(if confidence >= 80 { 90 } else { 70 }),
            indicators,
            mitre_id: "T1056.001".to_string(),
            mitre_name: "Input Capture: Keylogging".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
        };

        // Store alert
        {
            let mut alerts = ALERTS.write();
            alerts.push(alert.clone());
            if alerts.len() > 100 {
                alerts.remove(0);
            }
        }

        // Update stats
        {
            let mut stats = STATS.write();
            stats.alerts_count += 1;
            if alert.is_critical() {
                stats.critical_count += 1;
            }
        }

        return Some(alert);
    }

    None
}

/// Analyze process by checking its Import Address Table
pub fn analyze_process_imports(pid: u32, process_name: &str) -> Option<KeyloggerAlert> {
    // Get imports from process (simplified - would need PE parsing in real impl)
    let imports = get_process_imports(pid);
    analyze_process(pid, process_name, &imports)
}

/// Check all tracked processes for keylogger behavior
pub fn check_all_processes() -> Vec<KeyloggerAlert> {
    let mut alerts = Vec::new();
    let tracker = API_TRACKER.read();

    for (pid, stats) in tracker.iter() {
        // Skip processes with very few calls
        if stats.total_calls < 10 {
            continue;
        }

        if let Some(alert) = analyze_process(
            *pid,
            &stats.process_name,
            &[], // No import list available in runtime check
        ) {
            alerts.push(alert);
        }
    }

    // Update stats
    {
        let mut stats = STATS.write();
        stats.total_checks += 1;
        stats.processes_monitored = tracker.len() as u64;
        stats.last_check = chrono::Utc::now().timestamp();
    }

    alerts
}

/// Reset tracking for a process
pub fn reset_process_stats(pid: u32) {
    API_TRACKER.write().remove(&pid);
}

/// Clear stats older than specified seconds
pub fn cleanup_old_stats(max_age_seconds: i64) {
    let now = chrono::Utc::now().timestamp();
    API_TRACKER.write().retain(|_, stats| {
        now - stats.last_reset < max_age_seconds
    });
}

/// Get recent alerts
pub fn get_recent_alerts(limit: usize) -> Vec<KeyloggerAlert> {
    let alerts = ALERTS.read();
    alerts.iter().rev().take(limit).cloned().collect()
}

/// Get module statistics
pub fn get_stats() -> KeyloggerStats {
    STATS.read().clone()
}

// ============================================================================
// HELPERS
// ============================================================================

/// Suspicious process name patterns
const SUSPICIOUS_PROCESS_NAMES: &[&str] = &[
    "keylog",
    "keystroke",
    "keycapture",
    "inputlog",
    "typelog",
    "hookkey",
    "keyhook",
    "keysniff",
    "keyspy",
    "cliplog",
    "clipspy",
];

/// Get process imports (stub - needs real PE parsing)
fn get_process_imports(_pid: u32) -> Vec<String> {
    // In real implementation, this would:
    // 1. Open process
    // 2. Read PE headers
    // 3. Parse Import Directory
    // 4. Return list of imported function names
    Vec::new()
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_from_name() {
        assert_eq!(
            SuspiciousApi::from_name("GetAsyncKeyState"),
            Some(SuspiciousApi::GetAsyncKeyState)
        );
        assert_eq!(
            SuspiciousApi::from_name("setwindowshookexw"),
            Some(SuspiciousApi::SetWindowsHookEx)
        );
        assert_eq!(SuspiciousApi::from_name("unknown"), None);
    }

    #[test]
    fn test_analyze_keyboard_hook() {
        let imports = vec![
            "SetWindowsHookExW".to_string(),
            "GetAsyncKeyState".to_string(),
            "GetKeyboardState".to_string(),
        ];

        let alert = analyze_process(1234, "suspicious.exe", &imports);
        assert!(alert.is_some());

        let alert = alert.unwrap();
        assert!(alert.confidence >= 50);
        assert_eq!(alert.mitre_id, "T1056.001");
    }

    #[test]
    fn test_analyze_clean_process() {
        let imports = vec![
            "CreateFileW".to_string(),
            "ReadFile".to_string(),
        ];

        let alert = analyze_process(5678, "notepad.exe", &imports);
        assert!(alert.is_none());
    }

    #[test]
    fn test_suspicious_name() {
        // Suspicious name + hook API = enough for alert
        let imports = vec![
            "GetAsyncKeyState".to_string(),
            "SetWindowsHookExW".to_string(),
        ];
        let alert = analyze_process(9999, "keylogger.exe", &imports);
        assert!(alert.is_some());
    }

    #[test]
    fn test_record_api_call() {
        let pid = 11111;
        record_api_call(pid, "test.exe", SuspiciousApi::GetAsyncKeyState);
        record_api_call(pid, "test.exe", SuspiciousApi::GetAsyncKeyState);

        let tracker = API_TRACKER.read();
        let stats = tracker.get(&pid).unwrap();
        assert_eq!(stats.get_async_key_state, 2);
    }
}
