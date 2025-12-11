//! Registry Persistence Monitor Module (Phase 3)
//!
//! Mục đích: Monitor các registry locations thường bị malware sử dụng để persistence
//!
//! Persistence locations được monitor:
//! - Run/RunOnce keys
//! - Services
//! - Scheduled Tasks
//! - Image File Execution Options
//! - AppInit DLLs

use std::collections::HashMap;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use chrono::Utc;

use super::types::{PersistenceAlert, PersistenceMechanism, PersistenceSeverity};

// ============================================================================
// PERSISTENCE REGISTRY KEYS
// ============================================================================

/// Registry keys to monitor for persistence
pub const PERSISTENCE_KEYS: &[(&str, PersistenceMechanism)] = &[
    // Run keys (HKLM)
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", PersistenceMechanism::RunKey),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceMechanism::RunOnceKey),
    (r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", PersistenceMechanism::RunKey),
    (r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceMechanism::RunOnceKey),

    // Run keys (HKCU)
    (r"Software\Microsoft\Windows\CurrentVersion\Run", PersistenceMechanism::RunKey),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceMechanism::RunOnceKey),

    // Services
    (r"SYSTEM\CurrentControlSet\Services", PersistenceMechanism::Service),

    // Scheduled Tasks
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", PersistenceMechanism::ScheduledTask),
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree", PersistenceMechanism::ScheduledTask),

    // Image File Execution Options (debugger hijacking)
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", PersistenceMechanism::ImageFileExecution),
    (r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", PersistenceMechanism::ImageFileExecution),

    // AppInit DLLs
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", PersistenceMechanism::AppInitDll),
    (r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows", PersistenceMechanism::AppInitDll),

    // Shell extensions
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", PersistenceMechanism::StartupFolder),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", PersistenceMechanism::StartupFolder),
];

/// Whitelisted processes that can legitimately write to persistence locations
const WHITELISTED_PROCESSES: &[&str] = &[
    "msiexec.exe",
    "setup.exe",
    "installer.exe",
    "regedit.exe",
    "services.exe",
    "svchost.exe",
    "taskschd.exe",
    "mmc.exe",
];

// ============================================================================
// STATE
// ============================================================================

static MONITOR: Lazy<RwLock<PersistenceMonitor>> =
    Lazy::new(|| RwLock::new(PersistenceMonitor::new()));

// ============================================================================
// PERSISTENCE MONITOR
// ============================================================================

pub struct PersistenceMonitor {
    /// History of persistence events
    alerts: Vec<PersistenceAlert>,

    /// Whitelist of trusted processes
    whitelisted_processes: Vec<String>,

    /// Enable/disable monitoring
    enabled: bool,

    /// Max alerts to keep
    max_alerts: usize,
}

impl PersistenceMonitor {
    pub fn new() -> Self {
        Self {
            alerts: Vec::new(),
            whitelisted_processes: WHITELISTED_PROCESSES.iter().map(|s| s.to_lowercase()).collect(),
            enabled: true,
            max_alerts: 1000,
        }
    }

    /// Record a registry write event
    pub fn record_registry_write(
        &mut self,
        key: &str,
        value_name: Option<&str>,
        value_data: Option<&str>,
        process_name: &str,
        process_pid: u32,
    ) -> Option<PersistenceAlert> {
        if !self.enabled {
            return None;
        }

        // Check if this is a persistence key
        let mechanism = self.classify_key(key)?;

        // Check if process is whitelisted
        if self.is_whitelisted(process_name) {
            log::debug!("Persistence write from whitelisted process: {}", process_name);
            return None;
        }

        let severity = self.calculate_severity(&mechanism, process_name, value_data);

        let alert = PersistenceAlert {
            mechanism: mechanism.clone(),
            location: key.to_string(),
            value_name: value_name.map(|s| s.to_string()),
            value_data: value_data.map(|s| s.to_string()),
            process_name: process_name.to_string(),
            process_pid,
            timestamp: Utc::now().timestamp(),
            severity,
            mitre_technique: mechanism.mitre_technique().to_string(),
        };

        // Store alert
        self.alerts.push(alert.clone());
        if self.alerts.len() > self.max_alerts {
            self.alerts.drain(0..self.alerts.len() - self.max_alerts);
        }

        log::warn!(
            "Persistence detected: {} wrote to {} ({})",
            process_name,
            key,
            mechanism.mitre_technique()
        );

        Some(alert)
    }

    /// Classify a registry key to persistence mechanism
    fn classify_key(&self, key: &str) -> Option<PersistenceMechanism> {
        let key_lower = key.to_lowercase();

        for (pattern, mechanism) in PERSISTENCE_KEYS {
            if key_lower.contains(&pattern.to_lowercase()) {
                return Some(mechanism.clone());
            }
        }

        // Check for other persistence patterns
        if key_lower.contains("currentversion\\run") {
            return Some(PersistenceMechanism::RunKey);
        }
        if key_lower.contains("services\\") {
            return Some(PersistenceMechanism::Service);
        }
        if key_lower.contains("schedule\\taskcache") {
            return Some(PersistenceMechanism::ScheduledTask);
        }
        if key_lower.contains("image file execution") {
            return Some(PersistenceMechanism::ImageFileExecution);
        }

        None
    }

    /// Check if process is whitelisted
    fn is_whitelisted(&self, process_name: &str) -> bool {
        let name_lower = process_name.to_lowercase();
        self.whitelisted_processes.iter().any(|w| name_lower.ends_with(w))
    }

    /// Calculate severity based on context
    fn calculate_severity(
        &self,
        mechanism: &PersistenceMechanism,
        process_name: &str,
        value_data: Option<&str>,
    ) -> PersistenceSeverity {
        let mut score = 0;

        // Mechanism severity
        match mechanism {
            PersistenceMechanism::ImageFileExecution => score += 4,
            PersistenceMechanism::AppInitDll => score += 4,
            PersistenceMechanism::Service => score += 3,
            PersistenceMechanism::ScheduledTask => score += 3,
            PersistenceMechanism::RunKey | PersistenceMechanism::RunOnceKey => score += 2,
            _ => score += 1,
        }

        // Suspicious process names
        let name_lower = process_name.to_lowercase();
        if name_lower.contains("powershell") || name_lower.contains("cmd") {
            score += 2;
        }
        if name_lower.contains("wscript") || name_lower.contains("cscript") {
            score += 2;
        }

        // Suspicious value data
        if let Some(data) = value_data {
            let data_lower = data.to_lowercase();

            // PowerShell in value
            if data_lower.contains("powershell") || data_lower.contains("-enc") {
                score += 3;
            }

            // Script files
            if data_lower.ends_with(".vbs") || data_lower.ends_with(".js") ||
               data_lower.ends_with(".bat") || data_lower.ends_with(".ps1") {
                score += 2;
            }

            // Temp/user folders
            if data_lower.contains("\\temp\\") || data_lower.contains("\\appdata\\") {
                score += 2;
            }
        }

        match score {
            0..=2 => PersistenceSeverity::Low,
            3..=4 => PersistenceSeverity::Medium,
            5..=6 => PersistenceSeverity::High,
            _ => PersistenceSeverity::Critical,
        }
    }

    /// Get recent alerts
    pub fn get_alerts(&self, limit: usize) -> Vec<PersistenceAlert> {
        let start = self.alerts.len().saturating_sub(limit);
        self.alerts[start..].to_vec()
    }

    /// Get alerts by mechanism
    pub fn get_alerts_by_mechanism(&self, mechanism: &PersistenceMechanism) -> Vec<PersistenceAlert> {
        self.alerts.iter()
            .filter(|a| &a.mechanism == mechanism)
            .cloned()
            .collect()
    }

    /// Add to whitelist
    pub fn add_whitelist(&mut self, process_name: &str) {
        self.whitelisted_processes.push(process_name.to_lowercase());
    }

    /// Remove from whitelist
    pub fn remove_whitelist(&mut self, process_name: &str) {
        let name_lower = process_name.to_lowercase();
        self.whitelisted_processes.retain(|w| w != &name_lower);
    }

    /// Enable/disable monitoring
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Clear alerts
    pub fn clear_alerts(&mut self) {
        self.alerts.clear();
    }
}

impl Default for PersistenceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Record a registry write event
pub fn record_registry_write(
    key: &str,
    value_name: Option<&str>,
    value_data: Option<&str>,
    process_name: &str,
    process_pid: u32,
) -> Option<PersistenceAlert> {
    MONITOR.write().record_registry_write(key, value_name, value_data, process_name, process_pid)
}

/// Get recent alerts
pub fn get_alerts(limit: usize) -> Vec<PersistenceAlert> {
    MONITOR.read().get_alerts(limit)
}

/// Get alerts by mechanism
pub fn get_alerts_by_mechanism(mechanism: &PersistenceMechanism) -> Vec<PersistenceAlert> {
    MONITOR.read().get_alerts_by_mechanism(mechanism)
}

/// Check if a key is a persistence key
pub fn is_persistence_key(key: &str) -> bool {
    let key_lower = key.to_lowercase();
    PERSISTENCE_KEYS.iter().any(|(pattern, _)| key_lower.contains(&pattern.to_lowercase()))
}

/// Add process to whitelist
pub fn add_whitelist(process_name: &str) {
    MONITOR.write().add_whitelist(process_name);
}

/// Remove process from whitelist
pub fn remove_whitelist(process_name: &str) {
    MONITOR.write().remove_whitelist(process_name);
}

/// Enable/disable monitoring
pub fn set_enabled(enabled: bool) {
    MONITOR.write().set_enabled(enabled);
}

/// Clear all alerts
pub fn clear_alerts() {
    MONITOR.write().clear_alerts();
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct PersistenceStats {
    pub total_alerts: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub by_mechanism: HashMap<String, usize>,
    pub top_processes: Vec<(String, usize)>,
}

pub fn get_stats() -> PersistenceStats {
    let monitor = MONITOR.read();

    let mut by_mechanism: HashMap<String, usize> = HashMap::new();
    let mut by_process: HashMap<String, usize> = HashMap::new();
    let mut critical = 0;
    let mut high = 0;

    for alert in &monitor.alerts {
        *by_mechanism.entry(format!("{:?}", alert.mechanism)).or_insert(0) += 1;
        *by_process.entry(alert.process_name.clone()).or_insert(0) += 1;

        match alert.severity {
            PersistenceSeverity::Critical => critical += 1,
            PersistenceSeverity::High => high += 1,
            _ => {}
        }
    }

    let mut top_processes: Vec<_> = by_process.into_iter().collect();
    top_processes.sort_by(|a, b| b.1.cmp(&a.1));
    top_processes.truncate(10);

    PersistenceStats {
        total_alerts: monitor.alerts.len(),
        critical_count: critical,
        high_count: high,
        by_mechanism,
        top_processes,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_key() {
        let monitor = PersistenceMonitor::new();

        assert!(matches!(
            monitor.classify_key(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\malware"),
            Some(PersistenceMechanism::RunKey)
        ));

        assert!(matches!(
            monitor.classify_key(r"SYSTEM\CurrentControlSet\Services\evil"),
            Some(PersistenceMechanism::Service)
        ));
    }

    #[test]
    fn test_whitelist() {
        let mut monitor = PersistenceMonitor::new();

        assert!(monitor.is_whitelisted("msiexec.exe"));
        assert!(!monitor.is_whitelisted("malware.exe"));

        monitor.add_whitelist("custom.exe");
        assert!(monitor.is_whitelisted("custom.exe"));
    }

    #[test]
    fn test_persistence_detection() {
        let mut monitor = PersistenceMonitor::new();

        let alert = monitor.record_registry_write(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\malware",
            Some("malware"),
            Some(r"C:\temp\evil.exe"),
            "powershell.exe",
            1234,
        );

        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert!(alert.severity >= PersistenceSeverity::High);
    }
}
