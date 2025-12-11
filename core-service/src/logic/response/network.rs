//! Network Isolation Module (Phase 5)
//!
//! Mục đích: Block/unblock network access via Windows Firewall
//!
//! Uses netsh advfirewall commands

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use chrono::Utc;

use super::types::{ActionResult, ActionError, ActionStatus, ResponseAction};

// ============================================================================
// CONSTANTS
// ============================================================================

const RULE_PREFIX: &str = "OneShield_Block_";

// ============================================================================
// STATE
// ============================================================================

static BLOCKED_PROCESSES: Lazy<RwLock<HashMap<u32, BlockedProcess>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

struct BlockedProcess {
    pid: u32,
    exe_path: PathBuf,
    rule_name: String,
    blocked_at: i64,
}

// ============================================================================
// NETWORK ACTIONS
// ============================================================================

/// Block network access for a process
pub fn block_network(pid: u32, exe_path: Option<PathBuf>) -> Result<ActionResult, ActionError> {
    let start = Instant::now();

    // Get exe path if not provided
    let exe_path = match exe_path {
        Some(path) => path,
        None => get_exe_path_from_pid(pid)?,
    };

    // Check if already blocked
    if BLOCKED_PROCESSES.read().contains_key(&pid) {
        return Err(ActionError::InvalidAction {
            reason: format!("Process {} is already blocked", pid),
        });
    }

    let rule_name = format!("{}{}", RULE_PREFIX, pid);
    let exe_path_str = exe_path.to_string_lossy();

    // Create outbound block rule
    let out_result = create_firewall_rule(&rule_name, &exe_path_str, "out");

    // Create inbound block rule
    let in_rule_name = format!("{}_in", rule_name);
    let in_result = create_firewall_rule(&in_rule_name, &exe_path_str, "in");

    let duration = start.elapsed().as_millis() as u64;

    if out_result.is_ok() || in_result.is_ok() {
        // Track blocked process
        BLOCKED_PROCESSES.write().insert(pid, BlockedProcess {
            pid,
            exe_path: exe_path.clone(),
            rule_name: rule_name.clone(),
            blocked_at: Utc::now().timestamp(),
        });

        let result = ActionResult {
            action: ResponseAction::BlockNetwork {
                pid,
                exe_path: Some(exe_path.clone())
            },
            status: if out_result.is_ok() && in_result.is_ok() {
                ActionStatus::Success
            } else {
                ActionStatus::PartialSuccess
            },
            message: format!("Blocked network for {} ({})", pid, exe_path.display()),
            timestamp: Utc::now().timestamp(),
            duration_ms: duration,
        };

        log::warn!("Blocked network for process {} ({})", pid, exe_path.display());
        Ok(result)
    } else {
        Err(out_result.err().unwrap())
    }
}

/// Unblock network access for a process
pub fn unblock_network(pid: u32) -> Result<ActionResult, ActionError> {
    let start = Instant::now();

    // Check if we blocked this process
    let blocked = BLOCKED_PROCESSES.read().get(&pid).map(|b| b.rule_name.clone());

    let rule_name = match blocked {
        Some(name) => name,
        None => {
            // Try with default name
            format!("{}{}", RULE_PREFIX, pid)
        }
    };

    // Delete outbound rule
    let out_result = delete_firewall_rule(&rule_name);

    // Delete inbound rule
    let in_rule_name = format!("{}_in", rule_name);
    let in_result = delete_firewall_rule(&in_rule_name);

    let duration = start.elapsed().as_millis() as u64;

    // Remove from tracking
    BLOCKED_PROCESSES.write().remove(&pid);

    if out_result.is_ok() || in_result.is_ok() {
        let result = ActionResult {
            action: ResponseAction::UnblockNetwork { pid },
            status: ActionStatus::Success,
            message: format!("Unblocked network for PID {}", pid),
            timestamp: Utc::now().timestamp(),
            duration_ms: duration,
        };

        log::info!("Unblocked network for process {}", pid);
        Ok(result)
    } else {
        Err(ActionError::Other {
            message: "Failed to delete firewall rules".to_string(),
        })
    }
}

/// Check if process network is blocked
pub fn is_network_blocked(pid: u32) -> bool {
    BLOCKED_PROCESSES.read().contains_key(&pid)
}

/// Get all blocked processes
pub fn get_blocked_processes() -> Vec<(u32, String, i64)> {
    BLOCKED_PROCESSES.read()
        .values()
        .map(|b| (b.pid, b.exe_path.to_string_lossy().to_string(), b.blocked_at))
        .collect()
}

// ============================================================================
// FIREWALL HELPERS
// ============================================================================

fn create_firewall_rule(name: &str, program: &str, direction: &str) -> Result<(), ActionError> {
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", name),
            &format!("dir={}", direction),
            &format!("program={}", program),
            "action=block",
            "enable=yes",
        ])
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                Err(ActionError::CommandFailed {
                    command: "netsh".to_string(),
                    exit_code: output.status.code().unwrap_or(-1),
                    stderr,
                })
            }
        }
        Err(e) => Err(ActionError::Other { message: e.to_string() }),
    }
}

fn delete_firewall_rule(name: &str) -> Result<(), ActionError> {
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", name),
        ])
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                Err(ActionError::CommandFailed {
                    command: "netsh".to_string(),
                    exit_code: output.status.code().unwrap_or(-1),
                    stderr,
                })
            }
        }
        Err(e) => Err(ActionError::Other { message: e.to_string() }),
    }
}

fn get_exe_path_from_pid(pid: u32) -> Result<PathBuf, ActionError> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-Process -Id {} -ErrorAction SilentlyContinue).Path", pid),
        ])
        .output()
        .map_err(|e| ActionError::Other { message: e.to_string() })?;

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if path.is_empty() {
        Err(ActionError::ProcessNotFound { pid })
    } else {
        Ok(PathBuf::from(path))
    }
}

// ============================================================================
// CLEANUP
// ============================================================================

/// Remove all OneShield firewall rules
pub fn cleanup_all_rules() -> Result<usize, ActionError> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Get-NetFirewallRule | Where-Object {{ $_.DisplayName -like '{}*' }} | Remove-NetFirewallRule",
                RULE_PREFIX
            ),
        ])
        .output();

    match output {
        Ok(_) => {
            let count = BLOCKED_PROCESSES.read().len();
            BLOCKED_PROCESSES.write().clear();
            log::info!("Cleaned up {} firewall rules", count);
            Ok(count)
        }
        Err(e) => Err(ActionError::Other { message: e.to_string() }),
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkStats {
    pub blocked_count: usize,
    pub blocked_processes: Vec<BlockedInfo>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockedInfo {
    pub pid: u32,
    pub exe_path: String,
    pub blocked_at: i64,
    pub duration_hours: f64,
}

pub fn get_stats() -> NetworkStats {
    let blocked = BLOCKED_PROCESSES.read();
    let now = Utc::now().timestamp();

    let blocked_info: Vec<_> = blocked.values()
        .map(|b| BlockedInfo {
            pid: b.pid,
            exe_path: b.exe_path.to_string_lossy().to_string(),
            blocked_at: b.blocked_at,
            duration_hours: (now - b.blocked_at) as f64 / 3600.0,
        })
        .collect();

    NetworkStats {
        blocked_count: blocked_info.len(),
        blocked_processes: blocked_info,
    }
}
