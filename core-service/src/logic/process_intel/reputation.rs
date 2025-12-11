//! Process Reputation Module - Điểm tin cậy dựa trên lịch sử (Phase 2)
//!
//! Mục đích: Xây dựng reputation database cho các executables dựa trên:
//! - Thời gian đã biết (age)
//! - Tần suất xuất hiện
//! - Số lần gây anomaly
//! - Chữ ký số
//!
//! Persistence: Lưu vào JSON file để không mất sau restart

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use parking_lot::RwLock;
use sha2::{Sha256, Digest};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, Ordering};

use super::types::{ReputationEntry, ReputationFlags, SignatureStatus};
use super::signature;

// ============================================================================
// CONSTANTS
// ============================================================================

const REPUTATION_FILE_NAME: &str = "process_reputation.json";
const MAX_ENTRIES: usize = 10_000;
const SAVE_INTERVAL: u64 = 100; // Save after every N updates

// Reputation thresholds
const HIGH_TRUST_THRESHOLD: f32 = 0.7;
const LOW_TRUST_THRESHOLD: f32 = 0.3;

// ============================================================================
// STATE
// ============================================================================

static REPUTATION_DB: Lazy<RwLock<ReputationDatabase>> =
    Lazy::new(|| RwLock::new(ReputationDatabase::new()));
static UPDATE_COUNTER: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// REPUTATION DATABASE
// ============================================================================

pub struct ReputationDatabase {
    entries: HashMap<String, ReputationEntry>,  // hash -> entry
    path_to_hash: HashMap<String, String>,      // path -> hash (quick lookup)
    loaded: bool,
}

impl ReputationDatabase {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            path_to_hash: HashMap::new(),
            loaded: false,
        }
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Khởi tạo và load từ disk
pub fn init() {
    let mut db = REPUTATION_DB.write();
    if db.loaded {
        return;
    }

    if let Err(e) = load_internal(&mut db) {
        log::warn!("Failed to load reputation database: {}", e);
    }

    db.loaded = true;
    log::info!("Reputation database initialized with {} entries", db.entries.len());
}

/// Lấy reputation của một executable
pub fn get_reputation(exe_path: &Path) -> Option<ReputationEntry> {
    init();

    let db = REPUTATION_DB.read();
    let path_str = exe_path.to_string_lossy().to_lowercase();

    // Try path lookup first
    if let Some(hash) = db.path_to_hash.get(&path_str) {
        return db.entries.get(hash).cloned();
    }

    None
}

/// Lấy reputation bằng hash
pub fn get_reputation_by_hash(exe_hash: &str) -> Option<ReputationEntry> {
    init();
    REPUTATION_DB.read().entries.get(exe_hash).cloned()
}

/// Cập nhật reputation (gọi mỗi khi thấy process)
pub fn update_reputation(exe_path: &Path, is_anomaly: bool, is_alert: bool) -> ReputationEntry {
    init();

    let mut db = REPUTATION_DB.write();
    let path_str = exe_path.to_string_lossy().to_lowercase();

    // Get or create entry
    let hash = db.path_to_hash.get(&path_str).cloned();

    if let Some(hash) = hash {
        // Existing entry
        if let Some(entry) = db.entries.get_mut(&hash) {
            entry.record_seen();
            if is_alert {
                entry.record_alert();
            } else if is_anomaly {
                entry.record_anomaly();
            }
            return entry.clone();
        }
    }

    // New entry - need to compute hash
    drop(db); // Release lock before I/O

    let hash = compute_file_hash(exe_path).unwrap_or_else(|_| {
        // Fallback: use path as "hash" if file can't be read
        format!("path:{}", path_str)
    });

    let name = exe_path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let mut entry = ReputationEntry::new(hash.clone(), name, exe_path.to_path_buf());

    // Check signature
    let sig_result = signature::verify_signature(exe_path);
    entry.signature = sig_result.status;

    // Check if LOLBin
    entry.flags.is_lolbin = super::spawn::is_lolbin(
        &entry.exe_name
    );

    if is_alert {
        entry.record_alert();
    } else if is_anomaly {
        entry.record_anomaly();
    }

    // Store entry
    let mut db = REPUTATION_DB.write();
    db.path_to_hash.insert(path_str, hash.clone());

    // Evict if too many entries
    if db.entries.len() >= MAX_ENTRIES {
        evict_old_entries(&mut db);
    }

    db.entries.insert(hash, entry.clone());

    // Maybe save
    let counter = UPDATE_COUNTER.fetch_add(1, Ordering::SeqCst);

    if counter % SAVE_INTERVAL == 0 {
        drop(db);
        let _ = save();
    }

    entry
}

/// Whitelist một executable (trusted)
pub fn whitelist(exe_hash: &str) {
    init();
    let mut db = REPUTATION_DB.write();
    if let Some(entry) = db.entries.get_mut(exe_hash) {
        entry.flags.is_whitelisted = true;
        entry.flags.is_blacklisted = false;
        entry.reputation_score = 1.0;
    }
}

/// Blacklist một executable (untrusted)
pub fn blacklist(exe_hash: &str) {
    init();
    let mut db = REPUTATION_DB.write();
    if let Some(entry) = db.entries.get_mut(exe_hash) {
        entry.flags.is_blacklisted = true;
        entry.flags.is_whitelisted = false;
        entry.reputation_score = 0.0;
    }
}

/// Xóa whitelist/blacklist
pub fn clear_list(exe_hash: &str) {
    init();
    let mut db = REPUTATION_DB.write();
    if let Some(entry) = db.entries.get_mut(exe_hash) {
        entry.flags.is_whitelisted = false;
        entry.flags.is_blacklisted = false;
        // Recalculate score
        entry.record_seen(); // This triggers recalculation
    }
}

/// Kiểm tra executable có trusted không
pub fn is_trusted(exe_path: &Path) -> bool {
    if let Some(entry) = get_reputation(exe_path) {
        if entry.flags.is_whitelisted {
            return true;
        }
        if entry.flags.is_blacklisted {
            return false;
        }
        entry.reputation_score >= HIGH_TRUST_THRESHOLD
    } else {
        // Unknown - check signature
        signature::is_trusted_publisher(exe_path)
    }
}

/// Kiểm tra executable có untrusted không
pub fn is_untrusted(exe_path: &Path) -> bool {
    if let Some(entry) = get_reputation(exe_path) {
        if entry.flags.is_blacklisted {
            return true;
        }
        if entry.flags.is_whitelisted {
            return false;
        }
        entry.reputation_score <= LOW_TRUST_THRESHOLD
    } else {
        false
    }
}

/// Process reputation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ProcessReputation {
    Trusted,
    Neutral,
    Suspicious,
    Untrusted,
    Unknown,
}

/// Lấy reputation status
pub fn get_reputation_status(exe_path: &Path) -> ProcessReputation {
    if let Some(entry) = get_reputation(exe_path) {
        if entry.flags.is_whitelisted {
            ProcessReputation::Trusted
        } else if entry.flags.is_blacklisted {
            ProcessReputation::Untrusted
        } else if entry.reputation_score >= HIGH_TRUST_THRESHOLD {
            ProcessReputation::Trusted
        } else if entry.reputation_score <= LOW_TRUST_THRESHOLD {
            ProcessReputation::Untrusted
        } else if entry.anomaly_count > 0 {
            ProcessReputation::Suspicious
        } else {
            ProcessReputation::Neutral
        }
    } else {
        ProcessReputation::Unknown
    }
}

// ============================================================================
// PERSISTENCE
// ============================================================================

/// Save database to disk
pub fn save() -> Result<(), Box<dyn std::error::Error>> {
    let db = REPUTATION_DB.read();
    let path = get_db_path();

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(&path)?;
    let writer = BufWriter::new(file);

    // Only save entries, path_to_hash can be rebuilt
    serde_json::to_writer_pretty(writer, &db.entries)?;

    log::debug!("Saved {} reputation entries", db.entries.len());
    Ok(())
}

/// Load database from disk
fn load_internal(db: &mut ReputationDatabase) -> Result<(), Box<dyn std::error::Error>> {
    let path = get_db_path();

    if !path.exists() {
        return Ok(());
    }

    let file = File::open(&path)?;
    let reader = BufReader::new(file);

    db.entries = serde_json::from_reader(reader)?;

    // Rebuild path_to_hash
    for (hash, entry) in &db.entries {
        let path_str = entry.exe_path.to_string_lossy().to_lowercase();
        db.path_to_hash.insert(path_str, hash.clone());
    }

    Ok(())
}

/// Get database file path
fn get_db_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("OneShield")
        .join(REPUTATION_FILE_NAME)
}

/// Evict old/unused entries
fn evict_old_entries(db: &mut ReputationDatabase) {
    // Sort by last_seen and remove oldest 10%
    let mut entries: Vec<_> = db.entries.iter()
        .map(|(k, v)| (k.clone(), v.last_seen))
        .collect();

    entries.sort_by(|a, b| a.1.cmp(&b.1));

    let remove_count = MAX_ENTRIES / 10;
    for (hash, _) in entries.into_iter().take(remove_count) {
        if let Some(entry) = db.entries.remove(&hash) {
            let path_str = entry.exe_path.to_string_lossy().to_lowercase();
            db.path_to_hash.remove(&path_str);
        }
    }
}

// ============================================================================
// UTILITIES
// ============================================================================

/// Compute SHA256 hash of file
fn compute_file_hash(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReputationStats {
    pub total_entries: usize,
    pub trusted_count: usize,
    pub neutral_count: usize,
    pub suspicious_count: usize,
    pub untrusted_count: usize,
    pub whitelisted_count: usize,
    pub blacklisted_count: usize,
    pub signed_count: usize,
    pub lolbin_count: usize,
    pub avg_reputation_score: f32,
}

pub fn get_stats() -> ReputationStats {
    init();
    let db = REPUTATION_DB.read();

    let mut stats = ReputationStats {
        total_entries: db.entries.len(),
        trusted_count: 0,
        neutral_count: 0,
        suspicious_count: 0,
        untrusted_count: 0,
        whitelisted_count: 0,
        blacklisted_count: 0,
        signed_count: 0,
        lolbin_count: 0,
        avg_reputation_score: 0.0,
    };

    let mut total_score = 0.0;

    for entry in db.entries.values() {
        total_score += entry.reputation_score;

        if entry.flags.is_whitelisted {
            stats.whitelisted_count += 1;
            stats.trusted_count += 1;
        } else if entry.flags.is_blacklisted {
            stats.blacklisted_count += 1;
            stats.untrusted_count += 1;
        } else if entry.reputation_score >= HIGH_TRUST_THRESHOLD {
            stats.trusted_count += 1;
        } else if entry.reputation_score <= LOW_TRUST_THRESHOLD {
            stats.untrusted_count += 1;
        } else if entry.anomaly_count > 0 {
            stats.suspicious_count += 1;
        } else {
            stats.neutral_count += 1;
        }

        if entry.signature.is_signed() {
            stats.signed_count += 1;
        }

        if entry.flags.is_lolbin {
            stats.lolbin_count += 1;
        }
    }

    if stats.total_entries > 0 {
        stats.avg_reputation_score = total_score / stats.total_entries as f32;
    }

    stats
}

/// Lấy entries với reputation thấp nhất
pub fn get_lowest_reputation(limit: usize) -> Vec<ReputationEntry> {
    init();
    let db = REPUTATION_DB.read();

    let mut entries: Vec<_> = db.entries.values().cloned().collect();
    entries.sort_by(|a, b| a.reputation_score.partial_cmp(&b.reputation_score).unwrap());
    entries.truncate(limit);
    entries
}

/// Lấy entries với nhiều anomaly nhất
pub fn get_most_anomalies(limit: usize) -> Vec<ReputationEntry> {
    init();
    let db = REPUTATION_DB.read();

    let mut entries: Vec<_> = db.entries.values().cloned().collect();
    entries.sort_by(|a, b| b.anomaly_count.cmp(&a.anomaly_count));
    entries.truncate(limit);
    entries
}

/// Clear database
pub fn clear() {
    let mut db = REPUTATION_DB.write();
    db.entries.clear();
    db.path_to_hash.clear();

    // Delete file
    let _ = fs::remove_file(get_db_path());

    log::info!("Reputation database cleared");
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_reputation_entry() {
        let mut entry = ReputationEntry::new(
            "test_hash".to_string(),
            "test.exe".to_string(),
            PathBuf::from("C:\\test.exe"),
        );

        // Initial score is 0.5 (neutral)
        // But after first recalculate with unsigned + no age = ~0.4
        let initial_score = entry.reputation_score;
        assert!(initial_score >= 0.0 && initial_score <= 1.0);

        // Record some clean runs
        for _ in 0..10 {
            entry.record_seen();
        }

        // Score should stay similar or increase (unsigned file, no age)
        // clean_factor should remain 0.4 for all clean runs
        let score_after_clean = entry.reputation_score;
        assert!(score_after_clean >= 0.3);

        // Record anomaly
        entry.record_anomaly();

        // Score should decrease after anomaly (anomaly_rate increases)
        let score_after_anomaly = entry.reputation_score;
        assert!(score_after_anomaly < score_after_clean);
    }

    #[test]
    fn test_reputation_status() {
        // Clear first
        clear();

        let path = PathBuf::from("C:\\Windows\\System32\\notepad.exe");
        if path.exists() {
            let status = get_reputation_status(&path);
            // Unknown at first
            assert_eq!(status, ProcessReputation::Unknown);
        }
    }
}
