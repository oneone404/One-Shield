//! Advanced Detection API - Tauri Commands for Phase 8
//!
//! Expose AMSI, Injection, and Memory scanning to frontend.

use tauri::command;
use serde::{Deserialize, Serialize};

use crate::logic::advanced_detection::{
    amsi, injection, memory,
    ScanResult, ThreatLevel, AmsiStats,
    InjectionAlert, InjectionType, InjectionStats,
    MemoryScanResult, ShellcodeType, MemoryScanStats,
};

// ============================================================================
// RESPONSE TYPES
// ============================================================================

/// Unified threat alert for frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: String,
    pub alert_type: String,        // "AMSI", "INJECTION", "MEMORY"
    pub severity: String,          // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    pub title: String,
    pub description: String,
    pub mitre_id: Option<String>,
    pub source_process: Option<String>,
    pub source_pid: Option<u32>,
    pub target_process: Option<String>,
    pub target_pid: Option<u32>,
    pub confidence: u8,
    pub timestamp: i64,
    pub details: serde_json::Value,
}

/// Stats summary for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedDetectionStats {
    pub amsi_scans: u64,
    pub amsi_detections: u64,
    pub injection_checks: u64,
    pub injection_alerts: u64,
    pub memory_scans: u64,
    pub memory_detections: u64,
    pub total_critical: u64,
}

// ============================================================================
// INITIALIZATION
// ============================================================================

/// Initialize all advanced detection modules
#[command]
pub fn init_advanced_detection() -> Result<String, String> {
    crate::logic::advanced_detection::init();
    Ok("Advanced Detection initialized".to_string())
}

/// Check if advanced detection is available
#[command]
pub fn is_advanced_detection_ready() -> bool {
    amsi::is_available() || injection::is_available() || memory::is_available()
}

// ============================================================================
// AMSI COMMANDS
// ============================================================================

/// Scan a script for malware
#[command]
pub fn scan_script(content: String, content_type: String) -> Result<ScanResultDto, String> {
    amsi::init().map_err(|e| e.to_string())?;

    let result = amsi::scan(&content, &content_type)
        .map_err(|e| e.to_string())?;

    Ok(ScanResultDto::from(result))
}

/// Check if script content is malicious
#[command]
pub fn is_script_malicious(content: String, content_type: String) -> bool {
    if amsi::init().is_err() {
        return false;
    }
    amsi::is_malicious(&content, &content_type)
}

/// Get AMSI statistics
#[command]
pub fn get_amsi_stats() -> AmsiStats {
    amsi::get_stats()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultDto {
    pub content_preview: String,
    pub content_type: String,
    pub threat_level: String,
    pub should_block: bool,
    pub confidence: u8,
    pub scan_duration_ms: u64,
}

impl From<ScanResult> for ScanResultDto {
    fn from(r: ScanResult) -> Self {
        Self {
            content_preview: r.content_preview,
            content_type: r.content_type,
            threat_level: r.threat_level.as_str().to_string(),
            should_block: r.should_block,
            confidence: match r.threat_level {
                ThreatLevel::Malware => 95,
                ThreatLevel::BlockedByAdmin => 90,
                ThreatLevel::NotDetected => 20,
                ThreatLevel::Clean => 0,
            },
            scan_duration_ms: r.scan_duration_ms,
        }
    }
}

// ============================================================================
// INJECTION COMMANDS
// ============================================================================

/// Analyze a process for injection patterns
#[command]
pub fn analyze_process_injection(
    pid: u32,
    name: String,
    cmdline: String,
    parent_pid: Option<u32>,
    parent_name: Option<String>,
) -> Vec<InjectionAlertDto> {
    injection::init();

    let alerts = injection::analyze_process(
        pid,
        &name,
        &cmdline,
        parent_pid,
        parent_name.as_deref(),
    );

    alerts.into_iter().map(InjectionAlertDto::from).collect()
}

/// Get recent injection alerts
#[command]
pub fn get_injection_alerts(limit: usize) -> Vec<InjectionAlertDto> {
    injection::get_recent_alerts(limit)
        .into_iter()
        .map(InjectionAlertDto::from)
        .collect()
}

/// Get injection detection statistics
#[command]
pub fn get_injection_stats() -> InjectionStats {
    injection::get_stats()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionAlertDto {
    pub source_pid: u32,
    pub source_name: String,
    pub target_pid: u32,
    pub target_name: String,
    pub injection_type: String,
    pub mitre_id: String,
    pub severity: u8,
    pub confidence: u8,
    pub description: String,
    pub timestamp: i64,
    pub is_critical: bool,
}

impl From<InjectionAlert> for InjectionAlertDto {
    fn from(a: InjectionAlert) -> Self {
        let injection_type_str = a.injection_type.as_str().to_string();
        let severity = a.injection_type.severity();
        let is_critical = a.is_critical();
        Self {
            source_pid: a.source_pid,
            source_name: a.source_name,
            target_pid: a.target_pid,
            target_name: a.target_name,
            injection_type: injection_type_str,
            mitre_id: a.mitre_id,
            severity,
            confidence: a.confidence,
            description: a.description,
            timestamp: a.timestamp,
            is_critical,
        }
    }
}

// ============================================================================
// MEMORY COMMANDS
// ============================================================================

/// Scan binary data for shellcode
#[command]
pub fn scan_memory(data: Vec<u8>, source_name: String) -> Vec<MemoryScanResultDto> {
    memory::init();

    memory::scan_buffer(&data, &source_name)
        .into_iter()
        .map(MemoryScanResultDto::from)
        .collect()
}

/// Check if file contains shellcode
#[command]
pub fn scan_file_shellcode(path: String) -> Result<Vec<MemoryScanResultDto>, String> {
    memory::init();

    let results = memory::scan_file(std::path::Path::new(&path))
        .map_err(|e| e.to_string())?;

    Ok(results.into_iter().map(MemoryScanResultDto::from).collect())
}

/// Get memory scanning statistics
#[command]
pub fn get_memory_stats() -> MemoryScanStats {
    memory::get_stats()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScanResultDto {
    pub pid: u32,
    pub process_name: String,
    pub shellcode_type: String,
    pub pattern_name: String,
    pub offset: usize,
    pub match_length: usize,
    pub severity: u8,
    pub confidence: u8,
    pub mitre_id: String,
    pub timestamp: i64,
    pub is_critical: bool,
}

impl From<MemoryScanResult> for MemoryScanResultDto {
    fn from(r: MemoryScanResult) -> Self {
        let shellcode_type_str = r.shellcode_type.as_str().to_string();
        let severity = r.shellcode_type.severity();
        let mitre_id = r.shellcode_type.mitre_id().to_string();
        let is_critical = r.is_critical();
        Self {
            pid: r.pid,
            process_name: r.process_name,
            shellcode_type: shellcode_type_str,
            pattern_name: r.pattern_name,
            offset: r.offset,
            match_length: r.match_length,
            severity,
            confidence: r.confidence,
            mitre_id,
            timestamp: r.timestamp,
            is_critical,
        }
    }
}

// ============================================================================
// UNIFIED ALERTS
// ============================================================================

/// Get all recent threat alerts (combined from all modules)
#[command]
pub fn get_threat_alerts(limit: usize) -> Vec<ThreatAlert> {
    let mut alerts: Vec<ThreatAlert> = Vec::new();

    // Injection alerts
    for alert in injection::get_recent_alerts(limit) {
        alerts.push(ThreatAlert {
            id: format!("inj_{}", alert.timestamp),
            alert_type: "INJECTION".to_string(),
            severity: if alert.is_critical() { "CRITICAL" } else { "HIGH" }.to_string(),
            title: format!("{} Detected", alert.injection_type.as_str()),
            description: alert.description.clone(),
            mitre_id: Some(alert.mitre_id.clone()),
            source_process: Some(alert.source_name.clone()),
            source_pid: Some(alert.source_pid),
            target_process: Some(alert.target_name.clone()),
            target_pid: Some(alert.target_pid),
            confidence: alert.confidence,
            timestamp: alert.timestamp,
            details: serde_json::json!({
                "injection_type": alert.injection_type.as_str(),
                "severity_score": alert.injection_type.severity(),
            }),
        });
    }

    // Memory scan results
    for result in memory::get_recent_results(limit) {
        alerts.push(ThreatAlert {
            id: format!("mem_{}", result.timestamp),
            alert_type: "MEMORY".to_string(),
            severity: if result.is_critical() { "CRITICAL" } else { "HIGH" }.to_string(),
            title: format!("{} Detected", result.shellcode_type.as_str()),
            description: format!(
                "Shellcode pattern '{}' found at offset {} in {}",
                result.pattern_name, result.offset, result.process_name
            ),
            mitre_id: Some(result.shellcode_type.mitre_id().to_string()),
            source_process: Some(result.process_name.clone()),
            source_pid: Some(result.pid),
            target_process: None,
            target_pid: None,
            confidence: result.confidence,
            timestamp: result.timestamp,
            details: serde_json::json!({
                "shellcode_type": result.shellcode_type.as_str(),
                "pattern": result.pattern_name,
                "offset": result.offset,
            }),
        });
    }

    // Sort by timestamp (newest first)
    alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    alerts.truncate(limit);

    alerts
}

/// Get combined statistics
#[command]
pub fn get_advanced_detection_stats() -> AdvancedDetectionStats {
    let amsi = amsi::get_stats();
    let inj = injection::get_stats();
    let mem = memory::get_stats();

    AdvancedDetectionStats {
        amsi_scans: amsi.total_scans,
        amsi_detections: amsi.malware_count,
        injection_checks: inj.total_checks,
        injection_alerts: inj.alerts_count,
        memory_scans: mem.total_scans,
        memory_detections: mem.detections,
        total_critical: inj.critical_count + mem.critical_detections,
    }
}
