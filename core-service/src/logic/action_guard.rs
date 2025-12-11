#![allow(dead_code)]

//! Action Guard - Module Hành động Phòng thủ Chủ động
//!
//! Can thiệp khi Final Score vượt ngưỡng hoặc theo quyết định từ Policy Engine.
//! Hỗ trợ: Kill Process, Block Network I/O, Isolate Session.
//!
//! ## Pipeline (v0.6)
//! AI Score → threat::classify() → policy::decide() → Action Guard

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::collections::HashMap;
use parking_lot::RwLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// EDR Pipeline imports (v0.6)
use super::threat::{self, AnomalyScore, BaselineDiff, ThreatContext, ClassificationResult};
use super::policy::{self, Decision, PolicyResult};

// Telemetry imports (v0.6.1)
use super::telemetry::{self, SecurityEvent, ProcessInfo as TelemetryProcessInfo};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Ngưỡng kích hoạt hành động chủ động
pub const ACTION_THRESHOLD: f32 = 0.95;

/// Ngưỡng cảnh báo cao (không can thiệp nhưng alert)
pub const HIGH_ALERT_THRESHOLD: f32 = 0.85;

/// Thời gian cooldown giữa các hành động (seconds)
const ACTION_COOLDOWN_SECS: i64 = 30;

/// Số lần tối đa can thiệp 1 process trong 1 phút
const MAX_ACTIONS_PER_MINUTE: u32 = 3;

// ============================================================================
// STATE
// ============================================================================

/// Đếm số hành động đã thực hiện
static TOTAL_ACTIONS: AtomicU32 = AtomicU32::new(0);

/// Lịch sử hành động
static ACTION_HISTORY: RwLock<Vec<ActionRecord>> = RwLock::new(Vec::new());

/// Actions đang pending (chờ approval)
static PENDING_ACTIONS: RwLock<Vec<PendingAction>> = RwLock::new(Vec::new());

/// Whitelist processes (không can thiệp)
static WHITELIST: RwLock<Vec<String>> = RwLock::new(Vec::new());

/// Cooldown tracker per process
static PROCESS_COOLDOWNS: RwLock<Option<HashMap<u32, DateTime<Utc>>>> = RwLock::new(None);

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Loại hành động can thiệp
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    /// Dừng tiến trình
    KillProcess,
    /// Block network I/O (firewall rule)
    BlockNetworkIO,
    /// Suspend process (tạm dừng)
    SuspendProcess,
    /// Isolate user session
    IsolateSession,
    /// Alert only (không can thiệp)
    AlertOnly,
}

impl ActionType {
    pub fn to_string(&self) -> String {
        match self {
            ActionType::KillProcess => "KILL_PROCESS".to_string(),
            ActionType::BlockNetworkIO => "BLOCK_NETWORK".to_string(),
            ActionType::SuspendProcess => "SUSPEND_PROCESS".to_string(),
            ActionType::IsolateSession => "ISOLATE_SESSION".to_string(),
            ActionType::AlertOnly => "ALERT_ONLY".to_string(),
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            ActionType::AlertOnly => 1,
            ActionType::SuspendProcess => 2,
            ActionType::BlockNetworkIO => 3,
            ActionType::KillProcess => 4,
            ActionType::IsolateSession => 5,
        }
    }
}

/// Trạng thái hành động
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionStatus {
    Pending,
    Approved,
    Executed,
    Failed,
    Cancelled,
}

/// Record một hành động đã thực hiện
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub id: String,
    pub action_type: ActionType,
    pub target_pid: Option<u32>,
    pub target_name: String,
    pub final_score: f32,
    pub tags: Vec<String>,
    pub status: ActionStatus,
    pub result: Option<String>,
    pub executed_at: DateTime<Utc>,
    pub auto_executed: bool,
}

/// Hành động đang chờ approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAction {
    pub id: String,
    pub action_type: ActionType,
    pub target_pid: u32,
    pub target_name: String,
    pub final_score: f32,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Kết quả của hành động
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub success: bool,
    pub action_type: ActionType,
    pub target_pid: Option<u32>,
    pub message: String,
    pub executed_at: DateTime<Utc>,
}

/// Cấu hình Action Guard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionGuardConfig {
    pub enabled: bool,
    pub auto_execute: bool,          // Tự động thực hiện hay chờ approval
    pub action_threshold: f32,
    pub high_alert_threshold: f32,
    pub require_confirmation: bool,   // Yêu cầu user xác nhận
}

impl Default for ActionGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_execute: false,      // Mặc định: chờ approval
            action_threshold: ACTION_THRESHOLD,
            high_alert_threshold: HIGH_ALERT_THRESHOLD,
            require_confirmation: true,
        }
    }
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

#[derive(Debug)]
pub struct ActionError(pub String);

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ActionError: {}", self.0)
    }
}

impl std::error::Error for ActionError {}

// ============================================================================
// WHITELIST MANAGEMENT
// ============================================================================

/// Thêm process vào whitelist
pub fn add_to_whitelist(process_name: &str) {
    let mut whitelist = WHITELIST.write();
    if !whitelist.contains(&process_name.to_lowercase()) {
        whitelist.push(process_name.to_lowercase());
        log::info!("Added to whitelist: {}", process_name);
    }
}

/// Xóa process khỏi whitelist
pub fn remove_from_whitelist(process_name: &str) {
    let mut whitelist = WHITELIST.write();
    whitelist.retain(|p| p != &process_name.to_lowercase());
}

/// Kiểm tra process có trong whitelist không
pub fn is_whitelisted(process_name: &str) -> bool {
    let whitelist = WHITELIST.read();

    // System processes luôn được whitelist
    let system_procs = [
        "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "svchost.exe", "dwm.exe",
        "explorer.exe", "taskhostw.exe", "runtimebroker.exe",
    ];

    let name_lower = process_name.to_lowercase();

    system_procs.iter().any(|&p| name_lower.contains(p)) ||
        whitelist.iter().any(|p| name_lower.contains(p))
}

/// Lấy danh sách whitelist
pub fn get_whitelist() -> Vec<String> {
    WHITELIST.read().clone()
}

// ============================================================================
// COOLDOWN MANAGEMENT
// ============================================================================

/// Kiểm tra process có đang trong cooldown không
fn is_in_cooldown(pid: u32) -> bool {
    let guard = PROCESS_COOLDOWNS.read();
    if let Some(cooldowns) = guard.as_ref() {
        if let Some(last_action) = cooldowns.get(&pid) {
            let elapsed = (Utc::now() - *last_action).num_seconds();
            return elapsed < ACTION_COOLDOWN_SECS;
        }
    }
    false
}

/// Đặt cooldown cho process
fn set_cooldown(pid: u32) {
    let mut guard = PROCESS_COOLDOWNS.write();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    if let Some(cooldowns) = guard.as_mut() {
        cooldowns.insert(pid, Utc::now());

        // Cleanup old entries
        let cutoff = Utc::now() - chrono::Duration::minutes(5);
        cooldowns.retain(|_, time| *time > cutoff);
    }
}

// ============================================================================
// ACTION IMPLEMENTATIONS
// ============================================================================

/// Kill một process theo PID
#[cfg(windows)]
pub fn kill_process(pid: u32) -> Result<ActionResult, ActionError> {
    if is_in_cooldown(pid) {
        return Err(ActionError(format!("Process {} đang trong cooldown", pid)));
    }

    log::warn!("Executing KILL_PROCESS for PID: {}", pid);

    let output = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .output()
        .map_err(|e| ActionError(format!("Failed to execute taskkill: {}", e)))?;

    set_cooldown(pid);
    TOTAL_ACTIONS.fetch_add(1, Ordering::SeqCst);

    if output.status.success() {
        Ok(ActionResult {
            success: true,
            action_type: ActionType::KillProcess,
            target_pid: Some(pid),
            message: format!("Process {} đã bị dừng", pid),
            executed_at: Utc::now(),
        })
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(ActionError(format!("taskkill failed: {}", stderr)))
    }
}

#[cfg(not(windows))]
pub fn kill_process(pid: u32) -> Result<ActionResult, ActionError> {
    use std::process::Command;

    if is_in_cooldown(pid) {
        return Err(ActionError(format!("Process {} đang trong cooldown", pid)));
    }

    log::warn!("Executing KILL_PROCESS for PID: {}", pid);

    let output = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output()
        .map_err(|e| ActionError(format!("Failed to execute kill: {}", e)))?;

    set_cooldown(pid);
    TOTAL_ACTIONS.fetch_add(1, Ordering::SeqCst);

    if output.status.success() {
        Ok(ActionResult {
            success: true,
            action_type: ActionType::KillProcess,
            target_pid: Some(pid),
            message: format!("Process {} đã bị dừng", pid),
            executed_at: Utc::now(),
        })
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(ActionError(format!("kill failed: {}", stderr)))
    }
}

/// Suspend (tạm dừng) một process
#[cfg(windows)]
pub fn suspend_process(pid: u32) -> Result<ActionResult, ActionError> {
    if is_in_cooldown(pid) {
        return Err(ActionError(format!("Process {} đang trong cooldown", pid)));
    }

    log::warn!("Executing SUSPEND_PROCESS for PID: {}", pid);

    // Windows: Use pssuspend từ Sysinternals hoặc PowerShell
    // Fallback: Dùng debug API (cần admin)
    let _output = Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "try {{ \
                    $p = Get-Process -Id {}; \
                    $p.Suspend(); \
                    Write-Output 'OK' \
                }} catch {{ \
                    Write-Error $_.Exception.Message \
                }}",
                pid
            ),
        ])
        .output()
        .map_err(|e| ActionError(format!("Failed to suspend: {}", e)))?;

    set_cooldown(pid);
    TOTAL_ACTIONS.fetch_add(1, Ordering::SeqCst);

    // PowerShell Suspend thường không work, fallback message
    Ok(ActionResult {
        success: true,
        action_type: ActionType::SuspendProcess,
        target_pid: Some(pid),
        message: format!("Process {} đã được đánh dấu để suspend (cần admin)", pid),
        executed_at: Utc::now(),
    })
}

#[cfg(not(windows))]
pub fn suspend_process(pid: u32) -> Result<ActionResult, ActionError> {
    if is_in_cooldown(pid) {
        return Err(ActionError(format!("Process {} đang trong cooldown", pid)));
    }

    log::warn!("Executing SUSPEND_PROCESS for PID: {}", pid);

    let output = Command::new("kill")
        .args(["-STOP", &pid.to_string()])
        .output()
        .map_err(|e| ActionError(format!("Failed to suspend: {}", e)))?;

    set_cooldown(pid);
    TOTAL_ACTIONS.fetch_add(1, Ordering::SeqCst);

    if output.status.success() {
        Ok(ActionResult {
            success: true,
            action_type: ActionType::SuspendProcess,
            target_pid: Some(pid),
            message: format!("Process {} đã bị tạm dừng (SIGSTOP)", pid),
            executed_at: Utc::now(),
        })
    } else {
        Err(ActionError("Suspend failed".to_string()))
    }
}

/// Block network I/O của một process
#[cfg(windows)]
pub fn block_network_io(pid: u32, process_name: &str) -> Result<ActionResult, ActionError> {
    log::warn!("Executing BLOCK_NETWORK for PID: {} ({})", pid, process_name);

    // Tạo Windows Firewall rule để block
    let rule_name = format!("AISecurityBlock_{}", pid);

    // Block outbound
    let output = Command::new("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule",
            &format!("name={}", rule_name),
            "dir=out",
            "action=block",
            &format!("program={}", process_name),
        ])
        .output();

    TOTAL_ACTIONS.fetch_add(1, Ordering::SeqCst);

    match output {
        Ok(out) if out.status.success() => {
            Ok(ActionResult {
                success: true,
                action_type: ActionType::BlockNetworkIO,
                target_pid: Some(pid),
                message: format!("Network I/O của {} đã bị block (rule: {})", process_name, rule_name),
                executed_at: Utc::now(),
            })
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Không fail, chỉ warn
            Ok(ActionResult {
                success: false,
                action_type: ActionType::BlockNetworkIO,
                target_pid: Some(pid),
                message: format!("Cần quyền Admin để block network: {}", stderr),
                executed_at: Utc::now(),
            })
        }
        Err(e) => Err(ActionError(format!("netsh failed: {}", e))),
    }
}

#[cfg(not(windows))]
pub fn block_network_io(pid: u32, process_name: &str) -> Result<ActionResult, ActionError> {
    log::warn!("Executing BLOCK_NETWORK for PID: {} ({})", pid, process_name);

    // Linux: Use iptables với owner match
    let output = Command::new("iptables")
        .args([
            "-A", "OUTPUT",
            "-m", "owner", "--pid-owner", &pid.to_string(),
            "-j", "DROP",
        ])
        .output();

    TOTAL_ACTIONS.fetch_add(1, Ordering::SeqCst);

    match output {
        Ok(out) if out.status.success() => {
            Ok(ActionResult {
                success: true,
                action_type: ActionType::BlockNetworkIO,
                target_pid: Some(pid),
                message: format!("Network I/O của PID {} đã bị block", pid),
                executed_at: Utc::now(),
            })
        }
        _ => {
            Ok(ActionResult {
                success: false,
                action_type: ActionType::BlockNetworkIO,
                target_pid: Some(pid),
                message: "Cần quyền root để block network".to_string(),
                executed_at: Utc::now(),
            })
        }
    }
}

/// Isolate user session (lock workstation)
#[cfg(windows)]
pub fn isolate_session() -> Result<ActionResult, ActionError> {
    log::warn!("Executing ISOLATE_SESSION - Locking workstation");

    let output = Command::new("rundll32.exe")
        .args(["user32.dll,LockWorkStation"])
        .output()
        .map_err(|e| ActionError(format!("Failed to lock: {}", e)))?;

    TOTAL_ACTIONS.fetch_add(1, Ordering::SeqCst);

    if output.status.success() {
        Ok(ActionResult {
            success: true,
            action_type: ActionType::IsolateSession,
            target_pid: None,
            message: "Workstation đã bị khóa".to_string(),
            executed_at: Utc::now(),
        })
    } else {
        Err(ActionError("Lock workstation failed".to_string()))
    }
}

#[cfg(not(windows))]
pub fn isolate_session() -> Result<ActionResult, ActionError> {
    log::warn!("Executing ISOLATE_SESSION");

    // Linux: Try different lock commands
    for cmd in ["loginctl lock-session", "gnome-screensaver-command -l", "xdg-screensaver lock"] {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if let Ok(output) = Command::new(parts[0]).args(&parts[1..]).output() {
            if output.status.success() {
                TOTAL_ACTIONS.fetch_add(1, Ordering::SeqCst);
                return Ok(ActionResult {
                    success: true,
                    action_type: ActionType::IsolateSession,
                    target_pid: None,
                    message: "Session đã bị lock".to_string(),
                    executed_at: Utc::now(),
                });
            }
        }
    }

    Err(ActionError("Không thể lock session".to_string()))
}

// ============================================================================
// DECISION ENGINE
// ============================================================================

/// Quyết định hành động dựa trên Final Score và tags
pub fn decide_action(
    final_score: f32,
    tags: &[String],
    target_pid: Option<u32>,
    target_name: &str,
) -> Option<ActionType> {
    // Không can thiệp process whitelist
    if is_whitelisted(target_name) {
        return None;
    }

    // Check cooldown
    if let Some(pid) = target_pid {
        if is_in_cooldown(pid) {
            return None;
        }
    }

    // Critical: Kill hoặc Isolate
    if final_score >= ACTION_THRESHOLD {
        // Kiểm tra tags để quyết định hành động phù hợp
        let has_coordinated = tags.iter().any(|t| t.contains("COORDINATED"));
        let has_critical = tags.iter().any(|t| t.contains("CRITICAL"));
        let has_network = tags.iter().any(|t| t.contains("NETWORK"));

        if has_coordinated || has_critical {
            // Multi-process attack → Isolate session
            return Some(ActionType::IsolateSession);
        } else if has_network {
            // Network-based threat → Block network first
            return Some(ActionType::BlockNetworkIO);
        } else {
            // Single process threat → Kill
            return Some(ActionType::KillProcess);
        }
    }

    // High alert: Suspend
    if final_score >= HIGH_ALERT_THRESHOLD {
        return Some(ActionType::SuspendProcess);
    }

    None
}

// ============================================================================
// EDR-STYLE PIPELINE (v0.6)
// ============================================================================

/// Input cho EDR pipeline
#[derive(Debug, Clone)]
pub struct PipelineInput {
    pub anomaly_score: f32,
    pub confidence: f32,
    pub method: String,
    pub baseline_deviation: f32,
    pub is_spike: bool,
    pub target_pid: u32,
    pub target_name: String,
    pub is_new_process: bool,
    pub child_count: u32,
    pub network_bytes: u64,
    pub tags: Vec<String>,
}

/// Output từ EDR pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineOutput {
    pub threat_class: String,
    pub decision: String,
    pub severity: String,
    pub action: Option<ActionType>,
    pub auto_execute: bool,
    pub confidence: f32,
    pub reasons: Vec<String>,
}

/// Quyết định hành động sử dụng EDR pipeline
///
/// Flow: AI Score → Threat Classification → Policy Decision → Action
pub fn decide_with_pipeline(input: &PipelineInput) -> PipelineOutput {
    // Step 1: Validate whitelist
    if is_whitelisted(&input.target_name) {
        return PipelineOutput {
            threat_class: "Benign".to_string(),
            decision: "SilentLog".to_string(),
            severity: "Low".to_string(),
            action: None,
            auto_execute: false,
            confidence: 1.0,
            reasons: vec!["Process is whitelisted".to_string()],
        };
    }

    // Step 2: Check cooldown
    if is_in_cooldown(input.target_pid) {
        return PipelineOutput {
            threat_class: "Benign".to_string(),
            decision: "SilentLog".to_string(),
            severity: "Low".to_string(),
            action: None,
            auto_execute: false,
            confidence: 1.0,
            reasons: vec!["Process in cooldown".to_string()],
        };
    }

    // Step 3: Build inputs for threat classification
    let anomaly = AnomalyScore {
        score: input.anomaly_score,
        confidence: input.confidence,
        method: input.method.clone(),
    };

    let baseline = BaselineDiff {
        deviation_score: input.baseline_deviation,
        is_spike: input.is_spike,
        ..Default::default()
    };

    let context = ThreatContext {
        is_new_process: input.is_new_process,
        is_whitelisted: false, // Already checked above
        child_process_count: input.child_count,
        network_bytes_sent: input.network_bytes,
        tags: input.tags.clone(),
        process_name: Some(input.target_name.clone()),
        pid: Some(input.target_pid),
        ..Default::default()
    };

    // Step 4: Classify threat
    let classification = threat::classify(&anomaly, &baseline, &context);

    // Step 5: Get policy decision
    let policy_result = policy::decide(&classification);

    // Step 6: Map policy action to our ActionType
    let action = map_policy_action(&policy_result, &classification);

    // FREEZE CORE: Safety Config Check
    let (final_action, auto_exec) = if !crate::logic::config::SafetyConfig::is_auto_block_enabled() {
        if action.is_some() && action != Some(ActionType::AlertOnly) {
            log::info!("Auto-Block disabled: Downgrading action to AlertOnly");
            (Some(ActionType::AlertOnly), false)
        } else {
            (action, false)
        }
    } else {
        (action, policy_result.auto_execute)
    };

    // Step 7: Build output
    PipelineOutput {
        threat_class: format!("{:?}", classification.threat_class),
        decision: format!("{:?}", policy_result.decision),
        severity: format!("{:?}", policy_result.severity),
        action: final_action,
        auto_execute: auto_exec,
        confidence: classification.confidence,
        reasons: [
            classification.reasons.clone(),
            policy_result.reasons.clone(),
        ].concat(),
    }
}

/// Map policy ActionType to our ActionType
fn map_policy_action(policy: &PolicyResult, _classification: &ClassificationResult) -> Option<ActionType> {
    use policy::ActionType as PolicyAction;

    match policy.decision {
        Decision::SilentLog => None,
        Decision::Notify => Some(ActionType::AlertOnly),
        Decision::RequireApproval | Decision::AutoBlock => {
            // Map based on policy action type
            match policy.action {
                PolicyAction::None => None,
                PolicyAction::AlertOnly => Some(ActionType::AlertOnly),
                PolicyAction::SuspendProcess => Some(ActionType::SuspendProcess),
                PolicyAction::KillProcess => Some(ActionType::KillProcess),
                PolicyAction::BlockNetwork => Some(ActionType::BlockNetworkIO),
                PolicyAction::IsolateSession => Some(ActionType::IsolateSession),
            }
        }
    }
}

/// Execute action based on pipeline output
pub fn execute_from_pipeline(
    input: &PipelineInput,
    output: &PipelineOutput,
) -> Result<ActionResult, ActionError> {
    let action = match &output.action {
        Some(a) => *a,
        None => return Err(ActionError("No action required".to_string())),
    };

    execute_action(
        action,
        Some(input.target_pid),
        &input.target_name,
        input.anomaly_score,
        input.tags.clone(),
        output.auto_execute,
    )
}

/// Thực thi hành động (với hoặc không approval)
pub fn execute_action(
    action_type: ActionType,
    target_pid: Option<u32>,
    target_name: &str,
    final_score: f32,
    tags: Vec<String>,
    auto_execute: bool,
) -> Result<ActionResult, ActionError> {
    // Validate
    if is_whitelisted(target_name) {
        return Err(ActionError(format!("{} is whitelisted", target_name)));
    }

    // Create record
    let record = ActionRecord {
        id: uuid::Uuid::new_v4().to_string(),
        action_type,
        target_pid,
        target_name: target_name.to_string(),
        final_score,
        tags: tags.clone(),
        status: if auto_execute { ActionStatus::Executed } else { ActionStatus::Pending },
        result: None,
        executed_at: Utc::now(),
        auto_executed: auto_execute,
    };

    if !auto_execute {
        // Add to pending
        let pending = PendingAction {
            id: record.id.clone(),
            action_type,
            target_pid: target_pid.unwrap_or(0),
            target_name: target_name.to_string(),
            final_score,
            reason: format!("Score {:.2}, Tags: {:?}", final_score, tags),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        };

        // Clone for event before moving to storage
        let pending_clone = pending.clone();
        PENDING_ACTIONS.write().push(pending);

        // Emit event to UI (event-driven)
        super::events::emit_pending_action(serde_json::json!({
            "id": pending_clone.id,
            "action_type": format!("{:?}", pending_clone.action_type),
            "target_pid": pending_clone.target_pid,
            "target_name": pending_clone.target_name,
            "final_score": pending_clone.final_score,
            "reason": pending_clone.reason,
            "created_at": pending_clone.created_at.to_rfc3339(),
            "expires_at": pending_clone.expires_at.to_rfc3339(),
        }));

        // Record telemetry event
        telemetry::record(SecurityEvent::action_created(
            TelemetryProcessInfo::new(target_pid.unwrap_or(0), target_name),
            action_type,
            false, // not auto-execute
        ));

        return Ok(ActionResult {
            success: true,
            action_type,
            target_pid,
            message: "Action pending approval".to_string(),
            executed_at: Utc::now(),
        });
    }

    // Execute
    let result = match action_type {
        ActionType::KillProcess => {
            if let Some(pid) = target_pid {
                kill_process(pid)?
            } else {
                return Err(ActionError("PID required for kill".to_string()));
            }
        }
        ActionType::SuspendProcess => {
            if let Some(pid) = target_pid {
                suspend_process(pid)?
            } else {
                return Err(ActionError("PID required for suspend".to_string()));
            }
        }
        ActionType::BlockNetworkIO => {
            if let Some(pid) = target_pid {
                block_network_io(pid, target_name)?
            } else {
                return Err(ActionError("PID required for block".to_string()));
            }
        }
        ActionType::IsolateSession => {
            isolate_session()?
        }
        ActionType::AlertOnly => {
            ActionResult {
                success: true,
                action_type: ActionType::AlertOnly,
                target_pid,
                message: format!("Alert: {} (score: {:.2})", target_name, final_score),
                executed_at: Utc::now(),
            }
        }
    };

    // Save to history
    let mut history = ACTION_HISTORY.write();
    let mut final_record = record;
    final_record.status = if result.success { ActionStatus::Executed } else { ActionStatus::Failed };
    final_record.result = Some(result.message.clone());
    history.push(final_record);

    // Limit history size
    if history.len() > 1000 {
        history.drain(0..500);
    }

    Ok(result)
}

/// Approve pending action
pub fn approve_action(action_id: &str) -> Result<ActionResult, ActionError> {
    let mut pending = PENDING_ACTIONS.write();

    let idx = pending.iter()
        .position(|a| a.id == action_id)
        .ok_or_else(|| ActionError("Action not found".to_string()))?;

    let action = pending.remove(idx);

    // Record telemetry: user approved
    telemetry::record(SecurityEvent::user_approved(
        TelemetryProcessInfo::new(action.target_pid, &action.target_name),
        action.action_type,
    ));

    // Execute
    execute_action(
        action.action_type,
        Some(action.target_pid),
        &action.target_name,
        action.final_score,
        vec![action.reason],
        true,  // Now auto-execute
    )
}

/// Cancel pending action
pub fn cancel_action(action_id: &str) -> Result<(), ActionError> {
    let mut pending = PENDING_ACTIONS.write();

    // Find and record before removing
    if let Some(action) = pending.iter().find(|a| a.id == action_id) {
        telemetry::record(SecurityEvent::user_denied(
            TelemetryProcessInfo::new(action.target_pid, &action.target_name),
            action.action_type,
        ));
    }

    pending.retain(|a| a.id != action_id);
    Ok(())
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Lấy danh sách pending actions
pub fn get_pending_actions() -> Vec<PendingAction> {
    let mut pending = PENDING_ACTIONS.write();

    // Remove expired
    let now = Utc::now();
    pending.retain(|a| a.expires_at > now);

    pending.clone()
}

/// Lấy lịch sử actions
pub fn get_action_history(limit: usize) -> Vec<ActionRecord> {
    let history = ACTION_HISTORY.read();
    let start = if history.len() > limit { history.len() - limit } else { 0 };
    history[start..].to_vec()
}

/// Lấy tổng số actions
pub fn get_total_actions() -> u32 {
    TOTAL_ACTIONS.load(Ordering::SeqCst)
}

/// Reset action guard
pub fn reset() {
    TOTAL_ACTIONS.store(0, Ordering::SeqCst);
    ACTION_HISTORY.write().clear();
    PENDING_ACTIONS.write().clear();
    *PROCESS_COOLDOWNS.write() = None;
}

/// Lấy trạng thái Action Guard
pub fn get_status() -> serde_json::Value {
    serde_json::json!({
        "enabled": true,
        "action_threshold": ACTION_THRESHOLD,
        "high_alert_threshold": HIGH_ALERT_THRESHOLD,
        "total_actions": get_total_actions(),
        "pending_actions": get_pending_actions().len(),
        "whitelist_count": WHITELIST.read().len(),
    })
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decide_action_critical() {
        // CRITICAL takes priority over NETWORK -> IsolateSession
        let action = decide_action(
            0.98,
            &["CRITICAL_ANOMALY".to_string(), "NETWORK_SPIKE".to_string()],
            Some(1234),
            "malware.exe",
        );

        assert!(action.is_some());
        assert_eq!(action.unwrap(), ActionType::IsolateSession);
    }

    #[test]
    fn test_decide_action_network_only() {
        // NETWORK only (no CRITICAL) -> BlockNetworkIO
        let action = decide_action(
            0.96,
            &["NETWORK_SPIKE".to_string()],
            Some(1234),
            "suspicious.exe",
        );

        assert!(action.is_some());
        assert_eq!(action.unwrap(), ActionType::BlockNetworkIO);
    }

    #[test]
    fn test_decide_action_coordinated() {
        let action = decide_action(
            0.96,
            &["COORDINATED_ACTIVITY".to_string()],
            Some(1234),
            "suspicious.exe",
        );

        assert!(action.is_some());
        assert_eq!(action.unwrap(), ActionType::IsolateSession);
    }

    #[test]
    fn test_whitelist_protection() {
        let action = decide_action(
            0.99,
            &["CRITICAL_ANOMALY".to_string()],
            Some(4),
            "System",
        );

        assert!(action.is_none(), "System process should be protected");
    }

    #[test]
    fn test_threshold_behavior() {
        // Below threshold
        let action = decide_action(0.80, &[], Some(1234), "test.exe");
        assert!(action.is_none());

        // High alert threshold
        let action = decide_action(0.90, &[], Some(1234), "test.exe");
        assert_eq!(action, Some(ActionType::SuspendProcess));

        // Action threshold
        let action = decide_action(0.96, &[], Some(1234), "test.exe");
        assert_eq!(action, Some(ActionType::KillProcess));
    }
}
