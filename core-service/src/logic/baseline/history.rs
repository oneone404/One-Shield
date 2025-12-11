//! Baseline History Module - Snapshot & Rollback (Phase 1: Anti-Poisoning)
//!
//! Mục đích: Lưu checkpoints của baseline để có thể rollback khi phát hiện poisoning
//!
//! Flow:
//! 1. Tự động tạo snapshot mỗi X phút
//! 2. Tạo snapshot trước khi có thay đổi lớn (reset, drift alert)
//! 3. Cho phép rollback về bất kỳ snapshot nào

use std::path::PathBuf;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use parking_lot::RwLock;
use chrono::Utc;

use super::types::{BaselineSnapshot, SnapshotTrigger, VersionedBaseline, AuditAction};
use super::audit;

// ============================================================================
// CONSTANTS
// ============================================================================

const DEFAULT_INTERVAL_MINUTES: u32 = 60;
const DEFAULT_MAX_SNAPSHOTS: usize = 24;
const SNAPSHOT_DIR_NAME: &str = "baseline_snapshots";

// ============================================================================
// STATE
// ============================================================================

static HISTORY: RwLock<BaselineHistory> = RwLock::new(BaselineHistory::new_const());

// ============================================================================
// HISTORY STRUCT
// ============================================================================

pub struct BaselineHistory {
    snapshots: Vec<BaselineSnapshot>,
    interval_minutes: u32,
    max_snapshots: usize,
    last_snapshot_time: i64,
}

impl BaselineHistory {
    const fn new_const() -> Self {
        Self {
            snapshots: Vec::new(),
            interval_minutes: DEFAULT_INTERVAL_MINUTES,
            max_snapshots: DEFAULT_MAX_SNAPSHOTS,
            last_snapshot_time: 0,
        }
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Khởi tạo history với config
pub fn init(interval_minutes: u32, max_snapshots: usize) {
    let mut history = HISTORY.write();
    history.interval_minutes = interval_minutes;
    history.max_snapshots = max_snapshots;

    // Load from disk
    if let Err(e) = load_from_disk_internal(&mut history) {
        log::warn!("Failed to load snapshot history: {}", e);
    }

    log::info!(
        "Baseline history initialized: interval={}min, max={}, loaded={}",
        interval_minutes,
        max_snapshots,
        history.snapshots.len()
    );
}

/// Tạo snapshot mới
pub fn create_snapshot(baseline: &VersionedBaseline, trigger: SnapshotTrigger) -> String {
    let mut history = HISTORY.write();

    let snapshot = BaselineSnapshot::new(baseline.clone(), trigger.clone());
    let snapshot_id = snapshot.id.clone();

    history.snapshots.push(snapshot);
    history.last_snapshot_time = Utc::now().timestamp();

    // Giữ tối đa max_snapshots
    while history.snapshots.len() > history.max_snapshots {
        let removed = history.snapshots.remove(0);
        // Xóa file cũ
        let _ = delete_snapshot_file(&removed.id);
    }

    // Save to disk
    if let Err(e) = save_to_disk_internal(&history) {
        log::error!("Failed to save snapshot: {}", e);
    }

    audit::log(
        super::types::AuditLogEntry::new(AuditAction::SnapshotCreated)
            .with_sample(&snapshot_id)
            .with_details(&format!("Trigger: {:?}", trigger))
    );

    log::info!("Created baseline snapshot: {} (trigger: {:?})", snapshot_id, trigger);

    snapshot_id
}

/// Kiểm tra có cần tạo snapshot định kỳ không
pub fn should_create_scheduled_snapshot() -> bool {
    let history = HISTORY.read();
    let now = Utc::now().timestamp();
    let interval_seconds = history.interval_minutes as i64 * 60;

    now - history.last_snapshot_time >= interval_seconds
}

/// Tạo snapshot định kỳ nếu cần
pub fn maybe_create_scheduled_snapshot(baseline: &VersionedBaseline) -> Option<String> {
    if should_create_scheduled_snapshot() {
        Some(create_snapshot(baseline, SnapshotTrigger::Scheduled))
    } else {
        None
    }
}

/// Rollback về snapshot cụ thể
pub fn rollback(snapshot_id: &str) -> Result<VersionedBaseline, String> {
    let history = HISTORY.read();

    if let Some(snapshot) = history.snapshots.iter().find(|s| s.id == snapshot_id) {
        audit::log(
            super::types::AuditLogEntry::new(AuditAction::BaselineRollback)
                .with_sample(snapshot_id)
                .with_details(&format!("Rollback to snapshot from {} hours ago", snapshot.age_hours()))
        );

        log::info!(
            "Rolling back to snapshot {} ({:.1} hours old)",
            snapshot_id,
            snapshot.age_hours()
        );

        Ok(snapshot.baseline.clone())
    } else {
        Err(format!("Snapshot {} not found", snapshot_id))
    }
}

/// Rollback về snapshot N giờ trước
pub fn rollback_hours_ago(hours: u32) -> Result<VersionedBaseline, String> {
    let snapshot_id = {
        let history = HISTORY.read();
        let target_time = Utc::now().timestamp() - (hours as i64 * 3600);

        // Tìm snapshot gần nhất <= target_time
        history.snapshots
            .iter()
            .rev()
            .find(|s| s.timestamp <= target_time)
            .map(|s| s.id.clone())
    };

    if let Some(id) = snapshot_id {
        rollback(&id)
    } else {
        Err(format!("No snapshot found from {} hours ago", hours))
    }
}

/// Lấy snapshot gần nhất
pub fn get_latest_snapshot() -> Option<BaselineSnapshot> {
    HISTORY.read().snapshots.last().cloned()
}

/// Lấy tất cả snapshots
pub fn get_all_snapshots() -> Vec<SnapshotInfo> {
    HISTORY.read().snapshots.iter().map(|s| SnapshotInfo {
        id: s.id.clone(),
        timestamp: s.timestamp,
        age_hours: s.age_hours(),
        trigger: format!("{:?}", s.trigger),
        samples: s.baseline.samples,
    }).collect()
}

/// Lấy snapshot theo ID
pub fn get_snapshot(snapshot_id: &str) -> Option<BaselineSnapshot> {
    HISTORY.read().snapshots.iter().find(|s| s.id == snapshot_id).cloned()
}

/// Xóa snapshot cụ thể
pub fn delete_snapshot(snapshot_id: &str) -> bool {
    let mut history = HISTORY.write();
    let original_len = history.snapshots.len();
    history.snapshots.retain(|s| s.id != snapshot_id);

    if history.snapshots.len() < original_len {
        let _ = delete_snapshot_file(snapshot_id);
        let _ = save_to_disk_internal(&history);
        true
    } else {
        false
    }
}

/// Clear tất cả snapshots
pub fn clear() {
    let mut history = HISTORY.write();
    history.snapshots.clear();
    history.last_snapshot_time = 0;

    // Delete all files
    if let Ok(dir) = get_snapshot_dir() {
        let _ = fs::remove_dir_all(&dir);
    }

    log::info!("Cleared all baseline snapshots");
}

/// Lấy số lượng snapshots
pub fn count() -> usize {
    HISTORY.read().snapshots.len()
}

/// Thống kê history
#[derive(Debug, Clone, serde::Serialize)]
pub struct SnapshotInfo {
    pub id: String,
    pub timestamp: i64,
    pub age_hours: f32,
    pub trigger: String,
    pub samples: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoryStats {
    pub total_snapshots: usize,
    pub oldest_hours: f32,
    pub newest_hours: f32,
    pub interval_minutes: u32,
    pub max_snapshots: usize,
    pub disk_usage_bytes: u64,
}

pub fn get_stats() -> HistoryStats {
    let history = HISTORY.read();

    let oldest = history.snapshots.first().map(|s| s.age_hours()).unwrap_or(0.0);
    let newest = history.snapshots.last().map(|s| s.age_hours()).unwrap_or(0.0);

    let disk_usage = get_disk_usage().unwrap_or(0);

    HistoryStats {
        total_snapshots: history.snapshots.len(),
        oldest_hours: oldest,
        newest_hours: newest,
        interval_minutes: history.interval_minutes,
        max_snapshots: history.max_snapshots,
        disk_usage_bytes: disk_usage,
    }
}

/// Cập nhật config
pub fn set_config(interval_minutes: u32, max_snapshots: usize) {
    let mut history = HISTORY.write();
    history.interval_minutes = interval_minutes;
    history.max_snapshots = max_snapshots;

    // Trim nếu cần
    while history.snapshots.len() > max_snapshots {
        history.snapshots.remove(0);
    }
}

// ============================================================================
// DISK PERSISTENCE
// ============================================================================

fn get_snapshot_dir() -> Result<PathBuf, std::io::Error> {
    let dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("OneShield")
        .join(SNAPSHOT_DIR_NAME);

    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn save_to_disk_internal(history: &BaselineHistory) -> Result<(), Box<dyn std::error::Error>> {
    let dir = get_snapshot_dir()?;

    // Save index file
    let index_path = dir.join("index.json");
    let index: Vec<_> = history.snapshots.iter().map(|s| &s.id).collect();
    let index_file = File::create(&index_path)?;
    serde_json::to_writer(BufWriter::new(index_file), &index)?;

    // Save each snapshot
    for snapshot in &history.snapshots {
        let path = dir.join(format!("{}.json", snapshot.id));
        if !path.exists() {
            let file = File::create(&path)?;
            serde_json::to_writer(BufWriter::new(file), snapshot)?;
        }
    }

    Ok(())
}

fn load_from_disk_internal(history: &mut BaselineHistory) -> Result<(), Box<dyn std::error::Error>> {
    let dir = get_snapshot_dir()?;
    let index_path = dir.join("index.json");

    if !index_path.exists() {
        return Ok(());
    }

    // Load index
    let index_file = File::open(&index_path)?;
    let index: Vec<String> = serde_json::from_reader(BufReader::new(index_file))?;

    // Load snapshots
    history.snapshots.clear();
    for id in index {
        let path = dir.join(format!("{}.json", id));
        if path.exists() {
            let file = File::open(&path)?;
            if let Ok(snapshot) = serde_json::from_reader::<_, BaselineSnapshot>(BufReader::new(file)) {
                history.snapshots.push(snapshot);
            }
        }
    }

    // Update last snapshot time
    if let Some(last) = history.snapshots.last() {
        history.last_snapshot_time = last.timestamp;
    }

    Ok(())
}

fn delete_snapshot_file(id: &str) -> Result<(), std::io::Error> {
    let dir = get_snapshot_dir()?;
    let path = dir.join(format!("{}.json", id));
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

fn get_disk_usage() -> Result<u64, std::io::Error> {
    let dir = get_snapshot_dir()?;
    let mut total = 0u64;

    for entry in fs::read_dir(&dir)? {
        if let Ok(entry) = entry {
            if let Ok(metadata) = entry.metadata() {
                total += metadata.len();
            }
        }
    }

    Ok(total)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_creation() {
        let baseline = VersionedBaseline::new("test");
        let snapshot = BaselineSnapshot::new(baseline.clone(), SnapshotTrigger::Scheduled);

        assert!(!snapshot.id.is_empty());
        assert!(snapshot.age_hours() < 0.01); // Just created
    }

    #[test]
    fn test_find_snapshot() {
        // Clear first
        clear();

        let baseline = VersionedBaseline::new("test");
        let id = create_snapshot(&baseline, SnapshotTrigger::Scheduled);

        let found = get_snapshot(&id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, id);
    }
}
