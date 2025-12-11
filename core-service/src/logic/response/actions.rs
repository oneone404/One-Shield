//! Process Actions Module (Phase 5)
//!
//! Mục đích: Suspend, resume, kill processes
//!
//! Uses Windows API via PowerShell commands

use std::collections::HashMap;
use std::process::Command;
use std::time::Instant;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use chrono::Utc;

use super::types::{ResponseAction, ActionResult, ActionError, ActionStatus};

// ============================================================================
// STATE
// ============================================================================

static ACTION_HISTORY: Lazy<RwLock<Vec<ActionResult>>> =
    Lazy::new(|| RwLock::new(Vec::new()));

static SUSPENDED_PROCESSES: Lazy<RwLock<HashMap<u32, SuspendedProcess>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

const MAX_HISTORY: usize = 500;

struct SuspendedProcess {
    pid: u32,
    name: String,
    suspended_at: i64,
}

// ============================================================================
// PROCESS ACTIONS
// ============================================================================

/// Suspend a process by PID
pub fn suspend_process(pid: u32) -> Result<ActionResult, ActionError> {
    let start = Instant::now();

    // Check if process exists
    if !process_exists(pid) {
        return Err(ActionError::ProcessNotFound { pid });
    }

    // Get process name for logging
    let process_name = get_process_name(pid).unwrap_or_else(|| "Unknown".to_string());

    // Use PowerShell to suspend (via debug API)
    // Note: This requires elevated privileges
    let ps_script = format!(
        r#"
        $process = Get-Process -Id {} -ErrorAction SilentlyContinue
        if ($process) {{
            # Suspend via NtSuspendProcess
            $signature = @"
            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern int NtSuspendProcess(IntPtr processHandle);
"@
            $ntdll = Add-Type -MemberDefinition $signature -Name 'NtDll' -Namespace 'Win32' -PassThru
            $handle = $process.Handle
            $result = $ntdll::NtSuspendProcess($handle)
            if ($result -eq 0) {{
                Write-Output "SUCCESS"
            }} else {{
                Write-Output "FAILED:$result"
            }}
        }} else {{
            Write-Output "NOT_FOUND"
        }}
        "#,
        pid
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output();

    let duration = start.elapsed().as_millis() as u64;

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

            if stdout.contains("SUCCESS") {
                // Track suspended process
                SUSPENDED_PROCESSES.write().insert(pid, SuspendedProcess {
                    pid,
                    name: process_name.clone(),
                    suspended_at: Utc::now().timestamp(),
                });

                let result = ActionResult {
                    action: ResponseAction::SuspendProcess { pid },
                    status: ActionStatus::Success,
                    message: format!("Suspended process {} ({})", pid, process_name),
                    timestamp: Utc::now().timestamp(),
                    duration_ms: duration,
                };

                record_action(result.clone());
                log::info!("Suspended process {} ({})", pid, process_name);
                Ok(result)
            } else if stdout.contains("NOT_FOUND") {
                Err(ActionError::ProcessNotFound { pid })
            } else {
                Err(ActionError::CommandFailed {
                    command: "NtSuspendProcess".to_string(),
                    exit_code: -1,
                    stderr: stdout,
                })
            }
        }
        Err(e) => Err(ActionError::Other { message: e.to_string() }),
    }
}

/// Resume a suspended process
pub fn resume_process(pid: u32) -> Result<ActionResult, ActionError> {
    let start = Instant::now();

    // Check if we suspended this process
    if !SUSPENDED_PROCESSES.read().contains_key(&pid) {
        return Err(ActionError::InvalidAction {
            reason: format!("Process {} was not suspended by us", pid),
        });
    }

    let ps_script = format!(
        r#"
        $process = Get-Process -Id {} -ErrorAction SilentlyContinue
        if ($process) {{
            $signature = @"
            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern int NtResumeProcess(IntPtr processHandle);
"@
            $ntdll = Add-Type -MemberDefinition $signature -Name 'NtDll2' -Namespace 'Win32' -PassThru
            $handle = $process.Handle
            $result = $ntdll::NtResumeProcess($handle)
            if ($result -eq 0) {{
                Write-Output "SUCCESS"
            }} else {{
                Write-Output "FAILED:$result"
            }}
        }} else {{
            Write-Output "NOT_FOUND"
        }}
        "#,
        pid
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output();

    let duration = start.elapsed().as_millis() as u64;

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

            if stdout.contains("SUCCESS") {
                // Remove from tracked
                SUSPENDED_PROCESSES.write().remove(&pid);

                let result = ActionResult {
                    action: ResponseAction::ResumeProcess { pid },
                    status: ActionStatus::Success,
                    message: format!("Resumed process {}", pid),
                    timestamp: Utc::now().timestamp(),
                    duration_ms: duration,
                };

                record_action(result.clone());
                log::info!("Resumed process {}", pid);
                Ok(result)
            } else {
                Err(ActionError::CommandFailed {
                    command: "NtResumeProcess".to_string(),
                    exit_code: -1,
                    stderr: stdout,
                })
            }
        }
        Err(e) => Err(ActionError::Other { message: e.to_string() }),
    }
}

/// Kill a process
pub fn kill_process(pid: u32, force: bool) -> Result<ActionResult, ActionError> {
    let start = Instant::now();

    if !process_exists(pid) {
        return Err(ActionError::ProcessNotFound { pid });
    }

    let process_name = get_process_name(pid).unwrap_or_else(|| "Unknown".to_string());

    let pid_str = pid.to_string();
    let args: Vec<&str> = if force {
        vec!["/F", "/PID", &pid_str]
    } else {
        vec!["/PID", &pid_str]
    };

    let output = Command::new("taskkill")
        .args(&args)
        .output();

    let duration = start.elapsed().as_millis() as u64;

    match output {
        Ok(output) => {
            if output.status.success() {
                // Remove from suspended if it was there
                SUSPENDED_PROCESSES.write().remove(&pid);

                let result = ActionResult {
                    action: ResponseAction::KillProcess { pid, force },
                    status: ActionStatus::Success,
                    message: format!("Killed process {} ({})", pid, process_name),
                    timestamp: Utc::now().timestamp(),
                    duration_ms: duration,
                };

                record_action(result.clone());
                log::warn!("Killed process {} ({})", pid, process_name);
                Ok(result)
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                Err(ActionError::CommandFailed {
                    command: "taskkill".to_string(),
                    exit_code: output.status.code().unwrap_or(-1),
                    stderr,
                })
            }
        }
        Err(e) => Err(ActionError::Other { message: e.to_string() }),
    }
}

/// Execute a response action
pub fn execute_action(action: ResponseAction) -> Result<ActionResult, ActionError> {
    match action {
        ResponseAction::SuspendProcess { pid } => suspend_process(pid),
        ResponseAction::ResumeProcess { pid } => resume_process(pid),
        ResponseAction::KillProcess { pid, force } => kill_process(pid, force),
        _ => Err(ActionError::InvalidAction {
            reason: format!("Action {:?} not handled by actions module", action.action_type()),
        }),
    }
}

// ============================================================================
// UTILITIES
// ============================================================================

fn process_exists(pid: u32) -> bool {
    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Get-Process -Id {} -ErrorAction SilentlyContinue", pid),
        ])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

fn get_process_name(pid: u32) -> Option<String> {
    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-Process -Id {} -ErrorAction SilentlyContinue).ProcessName", pid),
        ])
        .output()
        .ok()
        .and_then(|o| {
            let name = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if name.is_empty() { None } else { Some(name) }
        })
}

fn record_action(result: ActionResult) {
    let mut history = ACTION_HISTORY.write();
    history.push(result);

    // Trim if too large
    let current_len = history.len();
    if current_len > MAX_HISTORY {
        history.drain(0..current_len - MAX_HISTORY);
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Get action history
pub fn get_action_history(limit: usize) -> Vec<ActionResult> {
    let history = ACTION_HISTORY.read();
    let start = history.len().saturating_sub(limit);
    history[start..].to_vec()
}

/// Get suspended processes
pub fn get_suspended_processes() -> Vec<(u32, String, i64)> {
    SUSPENDED_PROCESSES.read()
        .values()
        .map(|sp| (sp.pid, sp.name.clone(), sp.suspended_at))
        .collect()
}

/// Check if process is suspended (by us)
pub fn is_process_suspended(pid: u32) -> bool {
    SUSPENDED_PROCESSES.read().contains_key(&pid)
}

/// Clear action history
pub fn clear_history() {
    ACTION_HISTORY.write().clear();
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct ActionStats {
    pub total_actions: usize,
    pub success_count: usize,
    pub failed_count: usize,
    pub suspended_processes: usize,
    pub by_action_type: HashMap<String, usize>,
}

pub fn get_stats() -> ActionStats {
    let history = ACTION_HISTORY.read();

    let mut by_type: HashMap<String, usize> = HashMap::new();
    let mut success = 0;
    let mut failed = 0;

    for result in history.iter() {
        *by_type.entry(result.action.action_type().to_string()).or_insert(0) += 1;
        match result.status {
            ActionStatus::Success => success += 1,
            ActionStatus::Failed => failed += 1,
            _ => {}
        }
    }

    ActionStats {
        total_actions: history.len(),
        success_count: success,
        failed_count: failed,
        suspended_processes: SUSPENDED_PROCESSES.read().len(),
        by_action_type: by_type,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_description() {
        let action = ResponseAction::KillProcess { pid: 1234, force: true };
        assert!(action.description().contains("1234"));
        assert!(action.description().contains("Force"));
    }
}
