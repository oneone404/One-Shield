//! Dataset Module - AI Training Data Collection (P1.3)
//!
//! Records high-quality, versioned feature vectors and decisions for offline AI training.
//! Stores data in JSONL format with automatic rotation.

pub mod record;
pub mod writer;

#[cfg(test)]
mod tests;

use parking_lot::Mutex;
use writer::DatasetWriter;
pub use record::DatasetRecord;

// Global singleton writer
static WRITER: Mutex<Option<DatasetWriter>> = Mutex::new(None);

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
        }
    }
}
