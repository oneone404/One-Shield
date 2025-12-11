//! Suspicious Spawn Detection Module - LOLBins & Spawn Rules (Phase 2)
//!
//! Mục đích: Phát hiện các spawn patterns đáng ngờ, đặc biệt là LOLBins
//!
//! LOLBins (Living-off-the-Land Binaries) là các binary hợp lệ của Windows
//! nhưng có thể bị lợi dụng để thực thi malicious code.

use std::collections::HashMap;
use parking_lot::RwLock;
use chrono::Utc;
use once_cell::sync::Lazy;

use super::types::{ProcessInfo, SuspiciousSpawnAlert, SpawnSeverity, LolbinInfo};

// ============================================================================
// LOLBIN DATABASE
// ============================================================================

/// Danh sách LOLBins thường bị lợi dụng
pub const LOLBINS: &[LolbinInfo] = &[
    LolbinInfo {
        name: "cmd.exe",
        description: "Windows Command Processor",
        risk_level: SpawnSeverity::Medium,
        mitre_techniques: &["T1059.003"],
        suspicious_parents: &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe", "firefox.exe"],
    },
    LolbinInfo {
        name: "powershell.exe",
        description: "PowerShell",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1059.001"],
        suspicious_parents: &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe", "mshta.exe"],
    },
    LolbinInfo {
        name: "pwsh.exe",
        description: "PowerShell Core",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1059.001"],
        suspicious_parents: &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
    },
    LolbinInfo {
        name: "wscript.exe",
        description: "Windows Script Host",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1059.005"],
        suspicious_parents: &["winword.exe", "excel.exe", "explorer.exe", "outlook.exe"],
    },
    LolbinInfo {
        name: "cscript.exe",
        description: "Console Script Host",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1059.005"],
        suspicious_parents: &["winword.exe", "excel.exe", "explorer.exe"],
    },
    LolbinInfo {
        name: "mshta.exe",
        description: "Microsoft HTML Application Host",
        risk_level: SpawnSeverity::Critical,
        mitre_techniques: &["T1218.005"],
        suspicious_parents: &["explorer.exe", "winword.exe", "excel.exe", "cmd.exe"],
    },
    LolbinInfo {
        name: "regsvr32.exe",
        description: "Register Server",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1218.010"],
        suspicious_parents: &["explorer.exe", "cmd.exe", "powershell.exe"],
    },
    LolbinInfo {
        name: "rundll32.exe",
        description: "Run DLL",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1218.011"],
        suspicious_parents: &["explorer.exe", "winword.exe", "excel.exe"],
    },
    LolbinInfo {
        name: "certutil.exe",
        description: "Certificate Utility",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1140", "T1105"],
        suspicious_parents: &["cmd.exe", "powershell.exe"],
    },
    LolbinInfo {
        name: "bitsadmin.exe",
        description: "BITS Administration",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1197", "T1105"],
        suspicious_parents: &["cmd.exe", "powershell.exe"],
    },
    LolbinInfo {
        name: "msiexec.exe",
        description: "Windows Installer",
        risk_level: SpawnSeverity::Medium,
        mitre_techniques: &["T1218.007"],
        suspicious_parents: &["cmd.exe", "powershell.exe", "explorer.exe"],
    },
    LolbinInfo {
        name: "wmic.exe",
        description: "WMI Command Line",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1047"],
        suspicious_parents: &["cmd.exe", "powershell.exe", "winword.exe"],
    },
    LolbinInfo {
        name: "msbuild.exe",
        description: "MSBuild",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1127.001"],
        suspicious_parents: &["cmd.exe", "powershell.exe", "explorer.exe"],
    },
    LolbinInfo {
        name: "installutil.exe",
        description: "Install Utility",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1218.004"],
        suspicious_parents: &["cmd.exe", "powershell.exe"],
    },
    LolbinInfo {
        name: "cmstp.exe",
        description: "Connection Manager Profile Installer",
        risk_level: SpawnSeverity::Critical,
        mitre_techniques: &["T1218.003"],
        suspicious_parents: &["cmd.exe", "powershell.exe", "explorer.exe"],
    },
    LolbinInfo {
        name: "schtasks.exe",
        description: "Task Scheduler",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1053.005"],
        suspicious_parents: &["cmd.exe", "powershell.exe", "wscript.exe"],
    },
    LolbinInfo {
        name: "reg.exe",
        description: "Registry Console Tool",
        risk_level: SpawnSeverity::Medium,
        mitre_techniques: &["T1112"],
        suspicious_parents: &["cmd.exe", "powershell.exe", "wscript.exe"],
    },
    LolbinInfo {
        name: "sc.exe",
        description: "Service Control",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1543.003"],
        suspicious_parents: &["cmd.exe", "powershell.exe"],
    },
    LolbinInfo {
        name: "net.exe",
        description: "Net Command",
        risk_level: SpawnSeverity::Medium,
        mitre_techniques: &["T1087", "T1201"],
        suspicious_parents: &["cmd.exe", "powershell.exe", "wscript.exe"],
    },
    LolbinInfo {
        name: "netsh.exe",
        description: "Network Shell",
        risk_level: SpawnSeverity::High,
        mitre_techniques: &["T1562.004"],
        suspicious_parents: &["cmd.exe", "powershell.exe"],
    },
];

// ============================================================================
// STATE
// ============================================================================

static SPAWN_ALERTS: Lazy<RwLock<Vec<SuspiciousSpawnAlert>>> =
    Lazy::new(|| RwLock::new(Vec::new()));
static LOLBIN_MAP: Lazy<RwLock<HashMap<String, &'static LolbinInfo>>> =
    Lazy::new(|| {
        let mut m = HashMap::new();
        for lolbin in LOLBINS {
            m.insert(lolbin.name.to_lowercase(), lolbin);
        }
        RwLock::new(m)
    });

const MAX_ALERTS_HISTORY: usize = 1000;

// ============================================================================
// PUBLIC API
// ============================================================================

/// Kiểm tra một process có phải LOLBin không
pub fn is_lolbin(process_name: &str) -> bool {
    LOLBIN_MAP.read().contains_key(&process_name.to_lowercase())
}

/// Lấy thông tin LOLBin nếu có
pub fn get_lolbin_info(process_name: &str) -> Option<&'static LolbinInfo> {
    LOLBIN_MAP.read().get(&process_name.to_lowercase()).copied()
}

/// Kiểm tra spawn có đáng ngờ không
pub fn check_suspicious_spawn(parent: &ProcessInfo, child: &ProcessInfo) -> Option<SuspiciousSpawnAlert> {
    let parent_name = parent.name.to_lowercase();
    let child_name = child.name.to_lowercase();

    // Check if child is a LOLBin
    let child_lolbin = get_lolbin_info(&child_name);

    // Check spawn rules
    let alert = check_spawn_rules(&parent_name, &child_name, child_lolbin, parent, child);

    if let Some(ref a) = alert {
        // Store alert in history
        let mut alerts = SPAWN_ALERTS.write();
        alerts.push(a.clone());

        // Trim if too many
        let current_len = alerts.len();
        if current_len > MAX_ALERTS_HISTORY {
            alerts.drain(0..current_len - MAX_ALERTS_HISTORY);
        }
    }

    alert
}

/// Kiểm tra spawn rules
fn check_spawn_rules(
    parent_name: &str,
    child_name: &str,
    child_lolbin: Option<&'static LolbinInfo>,
    parent: &ProcessInfo,
    child: &ProcessInfo,
) -> Option<SuspiciousSpawnAlert> {

    // Rule 1: Office apps spawning shells
    if is_office_app(parent_name) && is_shell(child_name) {
        return Some(create_alert(
            parent, child,
            format!("Office app {} spawned shell {}", parent.name, child.name),
            SpawnSeverity::High,
            "OFFICE_SHELL_SPAWN",
            Some("T1059"),
        ));
    }

    // Rule 2: Browser spawning suspicious process
    if is_browser(parent_name) && (is_shell(child_name) || is_lolbin(child_name)) {
        return Some(create_alert(
            parent, child,
            format!("Browser {} spawned suspicious process {}", parent.name, child.name),
            SpawnSeverity::High,
            "BROWSER_SUSPICIOUS_SPAWN",
            Some("T1189"),
        ));
    }

    // Rule 3: LOLBin with suspicious parent
    if let Some(lolbin) = child_lolbin {
        for &suspicious_parent in lolbin.suspicious_parents {
            if parent_name.contains(suspicious_parent) {
                return Some(create_alert(
                    parent, child,
                    format!("LOLBin {} spawned by suspicious parent {}", child.name, parent.name),
                    lolbin.risk_level,
                    &format!("LOLBIN_{}", lolbin.name.to_uppercase().replace('.', "_")),
                    lolbin.mitre_techniques.first().copied(),
                ));
            }
        }
    }

    // Rule 4: Critical LOLBins (always suspicious regardless of parent)
    if let Some(lolbin) = child_lolbin {
        if lolbin.risk_level == SpawnSeverity::Critical {
            return Some(create_alert(
                parent, child,
                format!("Critical LOLBin {} executed", child.name),
                SpawnSeverity::High,
                "CRITICAL_LOLBIN",
                lolbin.mitre_techniques.first().copied(),
            ));
        }
    }

    // Rule 5: Script interpreters spawned by other scripts
    if is_script_interpreter(parent_name) && is_script_interpreter(child_name) {
        return Some(create_alert(
            parent, child,
            format!("Script interpreter chain: {} -> {}", parent.name, child.name),
            SpawnSeverity::Medium,
            "SCRIPT_CHAIN",
            Some("T1059"),
        ));
    }

    // Rule 6: Unsigned child from signed parent (when signature info available)
    if parent.signature.is_trusted() && !child.signature.is_signed() {
        if is_lolbin(child_name) {
            return Some(create_alert(
                parent, child,
                format!("Trusted process {} spawned unsigned LOLBin {}", parent.name, child.name),
                SpawnSeverity::Medium,
                "TRUSTED_SPAWN_UNSIGNED",
                None,
            ));
        }
    }

    None
}

/// Helper để tạo alert
fn create_alert(
    parent: &ProcessInfo,
    child: &ProcessInfo,
    reason: String,
    severity: SpawnSeverity,
    rule_id: &str,
    mitre: Option<&str>,
) -> SuspiciousSpawnAlert {
    SuspiciousSpawnAlert {
        parent: parent.clone(),
        child: child.clone(),
        reason,
        severity,
        rule_id: rule_id.to_string(),
        mitre_technique: mitre.map(|s| s.to_string()),
        timestamp: Utc::now().timestamp(),
    }
}

/// Kiểm tra có phải Office app không
fn is_office_app(name: &str) -> bool {
    matches!(
        name,
        "winword.exe" | "excel.exe" | "powerpnt.exe" | "outlook.exe" |
        "msaccess.exe" | "onenote.exe" | "visio.exe"
    )
}

/// Kiểm tra có phải browser không
fn is_browser(name: &str) -> bool {
    name.contains("chrome") || name.contains("firefox") ||
    name.contains("edge") || name.contains("iexplore") ||
    name.contains("opera") || name.contains("brave")
}

/// Kiểm tra có phải shell không
fn is_shell(name: &str) -> bool {
    matches!(name, "cmd.exe" | "powershell.exe" | "pwsh.exe")
}

/// Kiểm tra có phải script interpreter không
fn is_script_interpreter(name: &str) -> bool {
    matches!(
        name,
        "cmd.exe" | "powershell.exe" | "pwsh.exe" |
        "wscript.exe" | "cscript.exe" | "mshta.exe"
    )
}

// ============================================================================
// ALERT HISTORY
// ============================================================================

/// Lấy alert history
pub fn get_alerts(limit: usize) -> Vec<SuspiciousSpawnAlert> {
    let alerts = SPAWN_ALERTS.read();
    let start = alerts.len().saturating_sub(limit);
    alerts[start..].to_vec()
}

/// Lấy alerts theo severity
pub fn get_alerts_by_severity(severity: SpawnSeverity, limit: usize) -> Vec<SuspiciousSpawnAlert> {
    let alerts = SPAWN_ALERTS.read();
    alerts.iter()
        .rev()
        .filter(|a| a.severity >= severity)
        .take(limit)
        .cloned()
        .collect()
}

/// Clear alert history
pub fn clear_alerts() {
    SPAWN_ALERTS.write().clear();
}

/// Thống kê alerts
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpawnStats {
    pub total_alerts: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub unique_rules_triggered: usize,
    pub top_rules: Vec<(String, usize)>,
}

pub fn get_stats() -> SpawnStats {
    let alerts = SPAWN_ALERTS.read();

    let mut rule_counts: HashMap<String, usize> = HashMap::new();
    let mut stats = SpawnStats {
        total_alerts: alerts.len(),
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        unique_rules_triggered: 0,
        top_rules: Vec::new(),
    };

    for alert in alerts.iter() {
        match alert.severity {
            SpawnSeverity::Critical => stats.critical_count += 1,
            SpawnSeverity::High => stats.high_count += 1,
            SpawnSeverity::Medium => stats.medium_count += 1,
            SpawnSeverity::Low => stats.low_count += 1,
        }

        *rule_counts.entry(alert.rule_id.clone()).or_insert(0) += 1;
    }

    stats.unique_rules_triggered = rule_counts.len();

    // Get top 5 rules
    let mut rules: Vec<_> = rule_counts.into_iter().collect();
    rules.sort_by(|a, b| b.1.cmp(&a.1));
    stats.top_rules = rules.into_iter().take(5).collect();

    stats
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_lolbin() {
        assert!(is_lolbin("cmd.exe"));
        assert!(is_lolbin("PowerShell.exe"));
        assert!(is_lolbin("MSHTA.EXE"));
        assert!(!is_lolbin("notepad.exe"));
        assert!(!is_lolbin("random.exe"));
    }

    #[test]
    fn test_office_shell_spawn() {
        let parent = ProcessInfo::new(1000, "WINWORD.EXE".to_string());
        let child = ProcessInfo::new(2000, "cmd.exe".to_string());

        let alert = check_suspicious_spawn(&parent, &child);
        assert!(alert.is_some());

        let alert = alert.unwrap();
        assert_eq!(alert.severity, SpawnSeverity::High);
        assert_eq!(alert.rule_id, "OFFICE_SHELL_SPAWN");
    }

    #[test]
    fn test_normal_spawn() {
        let parent = ProcessInfo::new(1000, "explorer.exe".to_string());
        let child = ProcessInfo::new(2000, "notepad.exe".to_string());

        let alert = check_suspicious_spawn(&parent, &child);
        assert!(alert.is_none());
    }

    #[test]
    fn test_lolbin_info() {
        let info = get_lolbin_info("mshta.exe");
        assert!(info.is_some());

        let info = info.unwrap();
        assert_eq!(info.risk_level, SpawnSeverity::Critical);
        assert!(!info.mitre_techniques.is_empty());
    }
}
