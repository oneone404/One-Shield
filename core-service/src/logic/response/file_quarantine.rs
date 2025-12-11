//! File Quarantine Module (Phase 5)
//!
//! Mục đích: Di chuyển files nghi ngờ vào quarantine folder
//!
//! Features:
//! - Move files to secure quarantine location
//! - Track metadata for restore
//! - Secure deletion

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use chrono::Utc;
use sha2::{Sha256, Digest};
use uuid::Uuid;

use super::types::{QuarantineEntry, ActionResult, ActionError, ActionStatus, ResponseAction};

// ============================================================================
// CONSTANTS
// ============================================================================

const QUARANTINE_FOLDER: &str = "quarantine";
const METADATA_FILE: &str = "quarantine_metadata.json";
const MAX_QUARANTINE_SIZE_MB: u64 = 500;

// ============================================================================
// STATE
// ============================================================================

static QUARANTINE_MANAGER: Lazy<RwLock<QuarantineManager>> =
    Lazy::new(|| RwLock::new(QuarantineManager::new()));

// ============================================================================
// QUARANTINE MANAGER
// ============================================================================

pub struct QuarantineManager {
    entries: HashMap<String, QuarantineEntry>,
    quarantine_dir: PathBuf,
    total_size: u64,
}

impl QuarantineManager {
    pub fn new() -> Self {
        let quarantine_dir = get_quarantine_dir();

        // Create directory if not exists
        if !quarantine_dir.exists() {
            let _ = fs::create_dir_all(&quarantine_dir);
        }

        let mut manager = Self {
            entries: HashMap::new(),
            quarantine_dir,
            total_size: 0,
        };

        // Load existing entries
        manager.load_metadata();
        manager
    }

    /// Quarantine a file
    pub fn quarantine(&mut self, path: &Path, reason: &str, incident_id: Option<String>)
        -> Result<QuarantineEntry, ActionError>
    {
        // Check if file exists
        if !path.exists() {
            return Err(ActionError::FileNotFound {
                path: path.to_string_lossy().to_string()
            });
        }

        // Get file metadata
        let metadata = fs::metadata(path)
            .map_err(|e| ActionError::Other { message: e.to_string() })?;

        let file_size = metadata.len();

        // Check quarantine size limit
        if self.total_size + file_size > MAX_QUARANTINE_SIZE_MB * 1024 * 1024 {
            return Err(ActionError::Other {
                message: "Quarantine folder size limit reached".to_string(),
            });
        }

        // Calculate SHA256
        let sha256 = calculate_file_hash(path)?;

        // Generate quarantine ID
        let id = Uuid::new_v4().to_string();

        // Get file name
        let file_name = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Destination path (use ID to prevent name collisions)
        let quarantine_path = self.quarantine_dir.join(format!("{}.quarantine", id));

        // Move file to quarantine
        fs::rename(path, &quarantine_path)
            .or_else(|_| {
                // If rename fails (cross-device), try copy + delete
                fs::copy(path, &quarantine_path)
                    .and_then(|_| fs::remove_file(path))
            })
            .map_err(|e| ActionError::Other {
                message: format!("Failed to quarantine file: {}", e)
            })?;

        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: path.to_path_buf(),
            quarantine_path: quarantine_path.clone(),
            file_name,
            file_size,
            sha256,
            quarantine_time: Utc::now().timestamp(),
            reason: reason.to_string(),
            source_incident: incident_id,
            can_restore: true,
        };

        self.entries.insert(id.clone(), entry.clone());
        self.total_size += file_size;
        self.save_metadata();

        log::warn!("Quarantined file: {} -> {}", path.display(), quarantine_path.display());

        Ok(entry)
    }

    /// Restore a quarantined file
    pub fn restore(&mut self, quarantine_id: &str) -> Result<PathBuf, ActionError> {
        let entry = self.entries.get(quarantine_id)
            .ok_or_else(|| ActionError::Other {
                message: format!("Quarantine entry not found: {}", quarantine_id),
            })?
            .clone();

        if !entry.can_restore {
            return Err(ActionError::Other {
                message: "This file cannot be restored".to_string(),
            });
        }

        // Check quarantine file exists
        if !entry.quarantine_path.exists() {
            return Err(ActionError::FileNotFound {
                path: entry.quarantine_path.to_string_lossy().to_string(),
            });
        }

        // Restore to original location
        let restore_path = if entry.original_path.exists() {
            // Original exists, add suffix
            let mut new_path = entry.original_path.clone();
            let stem = new_path.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".to_string());
            let ext = new_path.extension()
                .map(|s| format!(".{}", s.to_string_lossy()))
                .unwrap_or_default();
            new_path.set_file_name(format!("{}_restored{}", stem, ext));
            new_path
        } else {
            entry.original_path.clone()
        };

        // Move back
        fs::rename(&entry.quarantine_path, &restore_path)
            .or_else(|_| {
                fs::copy(&entry.quarantine_path, &restore_path)
                    .and_then(|_| fs::remove_file(&entry.quarantine_path))
            })
            .map_err(|e| ActionError::Other {
                message: format!("Failed to restore file: {}", e),
            })?;

        self.total_size = self.total_size.saturating_sub(entry.file_size);
        self.entries.remove(quarantine_id);
        self.save_metadata();

        log::info!("Restored file: {} -> {}", entry.quarantine_path.display(), restore_path.display());

        Ok(restore_path)
    }

    /// Delete a quarantined file permanently
    pub fn delete(&mut self, quarantine_id: &str) -> Result<(), ActionError> {
        let entry = self.entries.get(quarantine_id)
            .ok_or_else(|| ActionError::Other {
                message: format!("Quarantine entry not found: {}", quarantine_id),
            })?
            .clone();

        if entry.quarantine_path.exists() {
            // Secure delete - overwrite before delete
            if let Ok(mut file) = fs::OpenOptions::new()
                .write(true)
                .open(&entry.quarantine_path)
            {
                use std::io::Write;
                let zeros = vec![0u8; 4096];
                for _ in 0..(entry.file_size / 4096 + 1) {
                    let _ = file.write_all(&zeros);
                }
            }

            fs::remove_file(&entry.quarantine_path)
                .map_err(|e| ActionError::Other {
                    message: format!("Failed to delete file: {}", e),
                })?;
        }

        self.total_size = self.total_size.saturating_sub(entry.file_size);
        self.entries.remove(quarantine_id);
        self.save_metadata();

        log::info!("Deleted quarantined file: {}", entry.file_name);

        Ok(())
    }

    /// Get all entries
    pub fn list(&self) -> Vec<QuarantineEntry> {
        self.entries.values().cloned().collect()
    }

    /// Get entry by ID
    pub fn get(&self, id: &str) -> Option<QuarantineEntry> {
        self.entries.get(id).cloned()
    }

    /// Load metadata from disk
    fn load_metadata(&mut self) {
        let metadata_path = self.quarantine_dir.join(METADATA_FILE);

        if let Ok(content) = fs::read_to_string(&metadata_path) {
            if let Ok(entries) = serde_json::from_str::<Vec<QuarantineEntry>>(&content) {
                for entry in entries {
                    if entry.quarantine_path.exists() {
                        self.total_size += entry.file_size;
                        self.entries.insert(entry.id.clone(), entry);
                    }
                }
            }
        }
    }

    /// Save metadata to disk
    fn save_metadata(&self) {
        let metadata_path = self.quarantine_dir.join(METADATA_FILE);
        let entries: Vec<_> = self.entries.values().collect();

        if let Ok(json) = serde_json::to_string_pretty(&entries) {
            let _ = fs::write(&metadata_path, json);
        }
    }

    /// Get stats
    pub fn stats(&self) -> QuarantineStats {
        QuarantineStats {
            total_files: self.entries.len(),
            total_size_bytes: self.total_size,
            total_size_mb: self.total_size as f64 / (1024.0 * 1024.0),
            oldest_entry: self.entries.values()
                .map(|e| e.quarantine_time)
                .min(),
            newest_entry: self.entries.values()
                .map(|e| e.quarantine_time)
                .max(),
        }
    }
}

impl Default for QuarantineManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UTILITIES
// ============================================================================

fn get_quarantine_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("OneShield")
        .join(QUARANTINE_FOLDER)
}

fn calculate_file_hash(path: &Path) -> Result<String, ActionError> {
    use std::io::Read;

    let mut file = fs::File::open(path)
        .map_err(|e| ActionError::Other { message: e.to_string() })?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)
            .map_err(|e| ActionError::Other { message: e.to_string() })?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Quarantine a file
pub fn quarantine_file(path: &Path, reason: &str, incident_id: Option<String>)
    -> Result<QuarantineEntry, ActionError>
{
    QUARANTINE_MANAGER.write().quarantine(path, reason, incident_id)
}

/// Restore a quarantined file
pub fn restore_file(quarantine_id: &str) -> Result<PathBuf, ActionError> {
    QUARANTINE_MANAGER.write().restore(quarantine_id)
}

/// Delete a quarantined file
pub fn delete_quarantined(quarantine_id: &str) -> Result<(), ActionError> {
    QUARANTINE_MANAGER.write().delete(quarantine_id)
}

/// Get all quarantined files
pub fn get_quarantine_list() -> Vec<QuarantineEntry> {
    QUARANTINE_MANAGER.read().list()
}

/// Get a specific entry
pub fn get_quarantine_entry(id: &str) -> Option<QuarantineEntry> {
    QUARANTINE_MANAGER.read().get(id)
}

/// Get stats
pub fn get_stats() -> QuarantineStats {
    QUARANTINE_MANAGER.read().stats()
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct QuarantineStats {
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub total_size_mb: f64,
    pub oldest_entry: Option<i64>,
    pub newest_entry: Option<i64>,
}
