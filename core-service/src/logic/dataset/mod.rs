//! Dataset Module - AI Training Data Collection (P1.3)
//!
//! Records high-quality, versioned feature vectors and decisions for offline AI training.
//! Stores data in JSONL format with automatic rotation.

pub mod record;
pub mod writer;
pub mod export;

#[cfg(test)]
mod tests;

use parking_lot::Mutex;
use writer::DatasetWriter;
pub use record::DatasetRecord;
use std::path::PathBuf;

/// Get the base directory for dataset storage
pub fn get_dataset_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ai-security")
        .join("dataset")
}

// Global singleton writer
static WRITER: Mutex<Option<DatasetWriter>> = Mutex::new(None);
static TOTAL_RECORDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BENIGN_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SUSPICIOUS_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static MALICIOUS_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// Use threat class for matching
use crate::logic::threat::ThreatClass;

/// Initialize the dataset logger
pub fn init() {
    let mut writer = WRITER.lock();
    if writer.is_none() {
        *writer = Some(DatasetWriter::new());
        log::info!("Dataset logging initialized");
    }
}

/// Log a record to the dataset
/// Thread-safe and non-blocking (file IO lock)
pub fn log(record: DatasetRecord) {
    let mut guard = WRITER.lock();

    // Lazy init if needed
    if guard.is_none() {
        *guard = Some(DatasetWriter::new());
    }

    if let Some(w) = guard.as_ref() {
        if let Err(e) = w.append(&record) {
            log::error!("Failed to append to dataset: {}", e);
        } else {
            TOTAL_RECORDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            match record.threat {
                ThreatClass::Benign => BENIGN_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                ThreatClass::Suspicious => SUSPICIOUS_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                ThreatClass::Malicious => MALICIOUS_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            };
        }
    }
}

pub fn get_status() -> crate::api::engine_status::DatasetStatus {
    let guard = WRITER.lock();

    let current_records = TOTAL_RECORDS.load(std::sync::atomic::Ordering::Relaxed);
    let benign = BENIGN_COUNT.load(std::sync::atomic::Ordering::Relaxed);
    let suspicious = SUSPICIOUS_COUNT.load(std::sync::atomic::Ordering::Relaxed);
    let malicious = MALICIOUS_COUNT.load(std::sync::atomic::Ordering::Relaxed);

    if let Some(writer) = guard.as_ref() {
        if let Ok((count, size, current)) = writer.get_stats() {
            return crate::api::engine_status::DatasetStatus {
                total_files: count,
                total_size_mb: size,
                current_file: current,
                total_records: current_records,
                benign_count: benign,
                suspicious_count: suspicious,
                malicious_count: malicious,
            };
        }
    }
    crate::api::engine_status::DatasetStatus {
        total_files: 0,
        total_size_mb: 0.0,
        current_file: "Not initialized".to_string(),
        total_records: 0,
        benign_count: 0,
        suspicious_count: 0,
        malicious_count: 0,
    }
}
