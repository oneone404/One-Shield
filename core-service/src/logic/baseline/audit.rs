//! Audit Log Module - Ghi lại mọi thay đổi baseline (Phase 1: Anti-Poisoning)
//!
//! Mục đích: Debug khi baseline bị lệch, trace source của poisoning.
//!
//! Log format: JSON Lines (.jsonl)
//! Location: {data_dir}/baseline_audit.jsonl

use std::fs::{OpenOptions, File};
use std::io::{BufWriter, Write, BufRead, BufReader};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use parking_lot::RwLock;

use super::types::{AuditLogEntry, AuditAction};

// ============================================================================
// CONSTANTS
// ============================================================================

const AUDIT_FILE_NAME: &str = "baseline_audit.jsonl";
const MAX_LOG_ENTRIES: usize = 10_000; // Rotate sau 10k entries
const MAX_IN_MEMORY: usize = 1_000;    // Cache 1k entries gần nhất

// ============================================================================
// STATE
// ============================================================================

static AUDIT_ENABLED: AtomicBool = AtomicBool::new(true);
static AUDIT_LOG: RwLock<Vec<AuditLogEntry>> = RwLock::new(Vec::new());
static WRITE_COUNT: RwLock<usize> = RwLock::new(0);

// ============================================================================
// PUBLIC API
// ============================================================================

/// Ghi một entry vào audit log
pub fn log(entry: AuditLogEntry) {
    if !AUDIT_ENABLED.load(Ordering::SeqCst) {
        return;
    }

    // In-memory cache
    {
        let mut cache = AUDIT_LOG.write();
        cache.push(entry.clone());

        // Giữ tối đa MAX_IN_MEMORY entries
        let len = cache.len();
        if len > MAX_IN_MEMORY {
            cache.drain(0..len - MAX_IN_MEMORY);
        }
    }

    // Write to disk
    if let Err(e) = write_to_disk(&entry) {
        log::error!("Failed to write audit log: {}", e);
    }

    // Check rotation
    check_rotation();
}

/// Ghi nhanh một action đơn giản
pub fn log_action(action: AuditAction) {
    log(AuditLogEntry::new(action));
}

/// Ghi action với sample ID
pub fn log_sample(action: AuditAction, sample_id: &str) {
    log(AuditLogEntry::new(action).with_sample(sample_id));
}

/// Ghi baseline update với drift score
pub fn log_baseline_update(sample_id: &str, features_changed: Vec<String>, drift: f32) {
    log(
        AuditLogEntry::new(AuditAction::BaselineUpdate)
            .with_sample(sample_id)
            .with_features(features_changed)
            .with_drift(drift)
    );
}

/// Ghi drift alert
pub fn log_drift_alert(drift: f32, message: &str) {
    log(
        AuditLogEntry::new(AuditAction::DriftAlert)
            .with_drift(drift)
            .with_details(message)
    );
}

/// Lấy N entries gần nhất từ cache
pub fn get_recent(limit: usize) -> Vec<AuditLogEntry> {
    let cache = AUDIT_LOG.read();
    let start = cache.len().saturating_sub(limit);
    cache[start..].to_vec()
}

/// Lấy tất cả entries trong khoảng thời gian
pub fn get_range(start_time: i64, end_time: i64) -> Vec<AuditLogEntry> {
    let cache = AUDIT_LOG.read();
    cache
        .iter()
        .filter(|e| e.timestamp >= start_time && e.timestamp <= end_time)
        .cloned()
        .collect()
}

/// Lấy entries theo action type
pub fn get_by_action(action: AuditAction, limit: usize) -> Vec<AuditLogEntry> {
    let cache = AUDIT_LOG.read();
    cache
        .iter()
        .filter(|e| e.action == action)
        .rev()
        .take(limit)
        .cloned()
        .collect()
}

/// Bật/tắt audit logging
pub fn set_enabled(enabled: bool) {
    AUDIT_ENABLED.store(enabled, Ordering::SeqCst);
    log::info!("Audit logging {}", if enabled { "enabled" } else { "disabled" });
}

/// Kiểm tra audit có đang bật không
pub fn is_enabled() -> bool {
    AUDIT_ENABLED.load(Ordering::SeqCst)
}

/// Lấy path của audit file
pub fn get_audit_file_path() -> PathBuf {
    get_data_dir().join(AUDIT_FILE_NAME)
}

/// Load audit log từ disk vào memory
pub fn load_from_disk() -> Result<usize, std::io::Error> {
    let path = get_audit_file_path();
    if !path.exists() {
        return Ok(0);
    }

    let file = File::open(&path)?;
    let reader = BufReader::new(file);

    let mut cache = AUDIT_LOG.write();
    cache.clear();

    let mut count = 0;
    for line in reader.lines() {
        if let Ok(line) = line {
            if let Ok(entry) = serde_json::from_str::<AuditLogEntry>(&line) {
                cache.push(entry);
                count += 1;
            }
        }
    }

    // Giữ tối đa MAX_IN_MEMORY entries
    let len = cache.len();
    if len > MAX_IN_MEMORY {
        cache.drain(0..len - MAX_IN_MEMORY);
    }

    log::info!("Loaded {} audit entries from disk", count);
    Ok(count)
}

/// Thống kê audit log
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditStats {
    pub total_entries: usize,
    pub baseline_updates: usize,
    pub samples_accepted: usize,
    pub samples_rejected: usize,
    pub drift_alerts: usize,
    pub learning_pauses: usize,
    pub oldest_entry: Option<i64>,
    pub newest_entry: Option<i64>,
}

pub fn get_stats() -> AuditStats {
    let cache = AUDIT_LOG.read();

    let mut stats = AuditStats {
        total_entries: cache.len(),
        baseline_updates: 0,
        samples_accepted: 0,
        samples_rejected: 0,
        drift_alerts: 0,
        learning_pauses: 0,
        oldest_entry: cache.first().map(|e| e.timestamp),
        newest_entry: cache.last().map(|e| e.timestamp),
    };

    for entry in cache.iter() {
        match entry.action {
            AuditAction::BaselineUpdate => stats.baseline_updates += 1,
            AuditAction::SampleAccepted => stats.samples_accepted += 1,
            AuditAction::SampleRejected => stats.samples_rejected += 1,
            AuditAction::DriftAlert => stats.drift_alerts += 1,
            AuditAction::LearningPaused => stats.learning_pauses += 1,
            _ => {}
        }
    }

    stats
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

fn get_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("OneShield")
}

fn write_to_disk(entry: &AuditLogEntry) -> Result<(), std::io::Error> {
    let path = get_audit_file_path();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    let mut writer = BufWriter::new(file);
    let json = serde_json::to_string(entry)?;
    writeln!(writer, "{}", json)?;
    writer.flush()?;

    // Track write count
    let mut count = WRITE_COUNT.write();
    *count += 1;

    Ok(())
}

fn check_rotation() {
    let count = *WRITE_COUNT.read();

    if count >= MAX_LOG_ENTRIES {
        if let Err(e) = rotate_log() {
            log::error!("Failed to rotate audit log: {}", e);
        }
    }
}

fn rotate_log() -> Result<(), std::io::Error> {
    let path = get_audit_file_path();

    if !path.exists() {
        return Ok(());
    }

    // Rename current file to .old
    let old_path = path.with_extension("jsonl.old");

    // Remove old backup if exists
    if old_path.exists() {
        std::fs::remove_file(&old_path)?;
    }

    // Rename current to old
    std::fs::rename(&path, &old_path)?;

    // Reset write count
    let mut count = WRITE_COUNT.write();
    *count = 0;

    log::info!("Rotated audit log");
    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = AuditLogEntry::new(AuditAction::BaselineUpdate)
            .with_sample("test-123")
            .with_features(vec!["cpu_percent".to_string()])
            .with_drift(0.05);

        assert_eq!(entry.action, AuditAction::BaselineUpdate);
        assert_eq!(entry.sample_id, Some("test-123".to_string()));
        assert_eq!(entry.drift_score, 0.05);
    }

    #[test]
    fn test_in_memory_cache() {
        // Clear cache first
        AUDIT_LOG.write().clear();

        // Add some entries
        for i in 0..5 {
            let entry = AuditLogEntry::new(AuditAction::BaselineUpdate)
                .with_details(&format!("Test entry {}", i));
            AUDIT_LOG.write().push(entry);
        }

        let recent = get_recent(3);
        assert_eq!(recent.len(), 3);
    }
}
