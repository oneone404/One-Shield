//! Security Event Exporter
//!
//! Future: Export events to external systems (SIEM, analytics, cloud).
//! For now, provides export utilities for local analysis.

use std::path::PathBuf;
use std::io::Write;
use chrono::{DateTime, Utc};
use serde::Serialize;

use super::event::{SecurityEvent, EventType};
use super::recorder;

// ============================================================================
// EXPORT FORMATS
// ============================================================================

/// Supported export formats
#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    /// JSONL (default, one JSON per line)
    Jsonl,
    /// CSV for spreadsheet analysis
    Csv,
    /// Compact JSON array
    JsonArray,
}

// ============================================================================
// EXPORT FUNCTIONS
// ============================================================================

/// Export events from log file to different format
pub fn export_file(
    source: &PathBuf,
    destination: &PathBuf,
    format: ExportFormat,
) -> std::io::Result<usize> {
    let events = recorder::read_events(source)?;
    export_events(&events, destination, format)
}

/// Export events to file
pub fn export_events(
    events: &[SecurityEvent],
    destination: &PathBuf,
    format: ExportFormat,
) -> std::io::Result<usize> {
    let mut file = std::fs::File::create(destination)?;
    let count = events.len();

    match format {
        ExportFormat::Jsonl => {
            for event in events {
                writeln!(file, "{}", event.to_jsonl())?;
            }
        }
        ExportFormat::JsonArray => {
            let json = serde_json::to_string_pretty(events)?;
            file.write_all(json.as_bytes())?;
        }
        ExportFormat::Csv => {
            export_csv(&mut file, events)?;
        }
    }

    Ok(count)
}

/// Export to CSV format
fn export_csv(file: &mut std::fs::File, events: &[SecurityEvent]) -> std::io::Result<()> {
    // Header
    writeln!(
        file,
        "id,timestamp,event_type,session_id,process_name,process_pid,threat_class,decision,severity,action,anomaly_score,confidence,description"
    )?;

    for event in events {
        let empty_string = String::new();
        let process_name = event.process.as_ref().map(|p| p.name.as_str()).unwrap_or("");
        let process_pid = event.process.as_ref().and_then(|p| p.pid).unwrap_or(0);
        let threat_class = event.threat_class.as_ref().map(|t| format!("{:?}", t)).unwrap_or_default();
        let decision = event.decision.as_ref().map(|d| format!("{:?}", d)).unwrap_or_default();
        let severity = event.severity.as_ref().map(|s| format!("{:?}", s)).unwrap_or_default();
        let action = event.action.as_ref().map(|a| format!("{:?}", a)).unwrap_or_default();
        let anomaly_score = event.ai_context.as_ref().map(|a| a.anomaly_score).unwrap_or(0.0);
        let confidence = event.ai_context.as_ref().map(|a| a.confidence).unwrap_or(0.0);

        // Escape CSV fields
        let description = event.description.replace('"', "\"\"");

        writeln!(
            file,
            "{},{},{},{},\"{}\",{},{},{},{},{},{:.4},{:.4},\"{}\"",
            event.id,
            event.timestamp.to_rfc3339(),
            event.event_type.as_str(),
            event.session_id,
            process_name,
            process_pid,
            threat_class,
            decision,
            severity,
            action,
            anomaly_score,
            confidence,
            description
        )?;
    }

    Ok(())
}

// ============================================================================
// TRAINING DATA EXPORT
// ============================================================================

/// Training data record (for AI model improvement)
#[derive(Debug, Clone, Serialize)]
pub struct TrainingRecord {
    pub timestamp: DateTime<Utc>,
    pub process_name: String,
    pub anomaly_score: f32,
    pub confidence: f32,
    pub baseline_deviation: f32,
    pub ai_recommendation: String,
    pub user_decision: String,
    pub is_override: bool,
    pub response_time_ms: u64,
    pub tags: Vec<String>,
}

/// Export user override events as training data
/// This is GOLD for improving the AI model!
pub fn export_training_data(
    log_dir: &PathBuf,
    destination: &PathBuf,
) -> std::io::Result<usize> {
    let mut training_records = Vec::new();

    // Read all log files
    for file_path in recorder::list_log_files(log_dir)? {
        let overrides = recorder::find_overrides(&file_path)?;

        for event in overrides {
            if let Some(override_info) = &event.user_override {
                let record = TrainingRecord {
                    timestamp: event.timestamp,
                    process_name: event.process.as_ref().map(|p| p.name.clone()).unwrap_or_default(),
                    anomaly_score: event.ai_context.as_ref().map(|a| a.anomaly_score).unwrap_or(0.0),
                    confidence: event.ai_context.as_ref().map(|a| a.confidence).unwrap_or(0.0),
                    baseline_deviation: event.ai_context.as_ref().map(|a| a.baseline_deviation).unwrap_or(0.0),
                    ai_recommendation: override_info.ai_recommendation.clone(),
                    user_decision: override_info.user_choice.clone(),
                    is_override: true,
                    response_time_ms: override_info.response_time_ms,
                    tags: event.ai_context.as_ref().map(|a| a.tags.clone()).unwrap_or_default(),
                };
                training_records.push(record);
            }
        }
    }

    // Export as JSONL
    let mut file = std::fs::File::create(destination)?;
    for record in &training_records {
        writeln!(file, "{}", serde_json::to_string(record)?)?;
    }

    Ok(training_records.len())
}

// ============================================================================
// ANALYTICS
// ============================================================================

/// Analytics summary
#[derive(Debug, Clone, Serialize)]
pub struct AnalyticsSummary {
    pub total_events: u64,
    pub threats_detected: u64,
    pub actions_executed: u64,
    pub user_approvals: u64,
    pub user_denials: u64,
    pub user_overrides: u64,
    pub override_rate: f32,
    pub approval_rate: f32,
}

/// Generate analytics summary from log files
pub fn generate_analytics(log_dir: &PathBuf) -> std::io::Result<AnalyticsSummary> {
    let mut summary = AnalyticsSummary {
        total_events: 0,
        threats_detected: 0,
        actions_executed: 0,
        user_approvals: 0,
        user_denials: 0,
        user_overrides: 0,
        override_rate: 0.0,
        approval_rate: 0.0,
    };

    for file_path in recorder::list_log_files(log_dir)? {
        let events = recorder::read_events(&file_path)?;

        for event in events {
            summary.total_events += 1;

            match event.event_type {
                EventType::ThreatDetected => summary.threats_detected += 1,
                EventType::ActionExecuted => summary.actions_executed += 1,
                EventType::UserApproved => summary.user_approvals += 1,
                EventType::UserDenied => summary.user_denials += 1,
                EventType::UserOverride => summary.user_overrides += 1,
                _ => {}
            }
        }
    }

    // Calculate rates
    let total_actions = summary.user_approvals + summary.user_denials;
    if total_actions > 0 {
        summary.approval_rate = summary.user_approvals as f32 / total_actions as f32;
    }
    if summary.threats_detected > 0 {
        summary.override_rate = summary.user_overrides as f32 / summary.threats_detected as f32;
    }

    Ok(summary)
}

// ============================================================================
// FUTURE: EXTERNAL EXPORT
// ============================================================================

/// Configuration for external export (future use)
#[derive(Debug, Clone)]
pub struct ExternalExportConfig {
    pub endpoint: String,
    pub api_key: Option<String>,
    pub batch_size: usize,
    pub retry_count: usize,
}

/// Export to external endpoint (placeholder for future)
#[allow(dead_code)]
pub async fn export_to_external(
    _events: &[SecurityEvent],
    _config: &ExternalExportConfig,
) -> Result<(), String> {
    // TODO: Implement when needed
    // - SIEM integration (Splunk, Elastic)
    // - Cloud storage (S3, GCS)
    // - Custom webhook
    Err("External export not implemented yet".to_string())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::event::{ProcessInfo, AiContext};
    use crate::logic::threat::ThreatClass;
    use tempfile::TempDir;

    fn create_test_events() -> Vec<SecurityEvent> {
        vec![
            SecurityEvent::threat_detected(
                ProcessInfo::new(123, "test.exe"),
                ThreatClass::Suspicious,
                AiContext {
                    anomaly_score: 0.75,
                    confidence: 0.8,
                    ..Default::default()
                },
            ),
            SecurityEvent::user_approved(
                ProcessInfo::new(123, "test.exe"),
                crate::logic::action_guard::ActionType::KillProcess,
            ),
        ]
    }

    #[test]
    fn test_export_jsonl() {
        let temp_dir = TempDir::new().unwrap();
        let dest = temp_dir.path().join("export.jsonl");
        let events = create_test_events();

        let count = export_events(&events, &dest, ExportFormat::Jsonl).unwrap();
        assert_eq!(count, 2);

        // Verify file
        let content = std::fs::read_to_string(&dest).unwrap();
        assert_eq!(content.lines().count(), 2);
    }

    #[test]
    fn test_export_csv() {
        let temp_dir = TempDir::new().unwrap();
        let dest = temp_dir.path().join("export.csv");
        let events = create_test_events();

        export_events(&events, &dest, ExportFormat::Csv).unwrap();

        let content = std::fs::read_to_string(&dest).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 events
        assert!(lines[0].starts_with("id,timestamp"));
    }

    #[test]
    fn test_export_json_array() {
        let temp_dir = TempDir::new().unwrap();
        let dest = temp_dir.path().join("export.json");
        let events = create_test_events();

        export_events(&events, &dest, ExportFormat::JsonArray).unwrap();

        let content = std::fs::read_to_string(&dest).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.len(), 2);
    }
}
