//! Security Event Recorder
//!
//! Append-only JSONL writer for security events.
//! Thread-safe, persistent, and crash-resistant.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::Mutex;
use chrono::{Utc, Datelike, Timelike};

use super::event::SecurityEvent;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Maximum file size before rotation (50 MB)
const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// Default log directory name
const LOG_DIR: &str = "security_logs";

/// Log file extension
const LOG_EXT: &str = ".jsonl";

// ============================================================================
// RECORDER STATE
// ============================================================================

/// Global recorder instance
static RECORDER: Mutex<Option<Recorder>> = Mutex::new(None);

/// Total events recorded in this session
static EVENTS_RECORDED: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// RECORDER
// ============================================================================

/// Append-only JSONL recorder
pub struct Recorder {
    writer: BufWriter<File>,
    current_file: PathBuf,
    current_size: u64,
    base_dir: PathBuf,
}

impl Recorder {
    /// Create a new recorder in the given directory
    pub fn new(base_dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&base_dir)?;
        let (file_path, file) = Self::open_new_file(&base_dir)?;

        Ok(Self {
            writer: BufWriter::new(file),
            current_file: file_path,
            current_size: 0,
            base_dir,
        })
    }

    /// Open a new log file with timestamp
    fn open_new_file(base_dir: &PathBuf) -> std::io::Result<(PathBuf, File)> {
        let now = Utc::now();
        let filename = format!(
            "security_{}_{:02}_{:02}_{:02}{:02}{:02}{}",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            LOG_EXT
        );
        let file_path = base_dir.join(&filename);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;

        log::info!("Opened security log: {:?}", file_path);
        Ok((file_path, file))
    }

    /// Record a security event
    pub fn record(&mut self, event: &SecurityEvent) -> std::io::Result<()> {
        let line = event.to_jsonl();
        let bytes = line.as_bytes();

        // Check if rotation needed
        if self.current_size + bytes.len() as u64 > MAX_FILE_SIZE {
            self.rotate()?;
        }

        // Write line + newline
        self.writer.write_all(bytes)?;
        self.writer.write_all(b"\n")?;
        self.current_size += bytes.len() as u64 + 1;

        // Flush for durability
        self.writer.flush()?;

        EVENTS_RECORDED.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Rotate to a new file
    fn rotate(&mut self) -> std::io::Result<()> {
        self.writer.flush()?;

        let (new_path, new_file) = Self::open_new_file(&self.base_dir)?;
        self.writer = BufWriter::new(new_file);

        log::info!("Rotated from {:?} to {:?}", self.current_file, new_path);
        self.current_file = new_path;
        self.current_size = 0;

        Ok(())
    }

    /// Get current log file path
    pub fn current_file(&self) -> &PathBuf {
        &self.current_file
    }

    /// Get total events recorded
    pub fn events_count(&self) -> u64 {
        EVENTS_RECORDED.load(Ordering::SeqCst)
    }
}

// ============================================================================
// GLOBAL API
// ============================================================================

/// Initialize the global recorder
pub fn init(base_dir: Option<PathBuf>) -> std::io::Result<()> {
    let dir = base_dir.unwrap_or_else(|| {
        // Default: app data directory
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ai-security")
            .join(LOG_DIR)
    });

    let recorder = Recorder::new(dir)?;
    *RECORDER.lock() = Some(recorder);

    // Record system start
    record(SecurityEvent::system_start(env!("CARGO_PKG_VERSION")));

    Ok(())
}

/// Record a security event (global function)
pub fn record(event: SecurityEvent) {
    let mut guard = RECORDER.lock();
    if let Some(recorder) = guard.as_mut() {
        if let Err(e) = recorder.record(&event) {
            log::error!("Failed to record security event: {}", e);
        }
    } else {
        // Recorder not initialized, just log
        log::warn!("Security recorder not initialized, event dropped: {}", event.description);
    }
}

/// Get total events recorded in this session
pub fn events_recorded() -> u64 {
    EVENTS_RECORDED.load(Ordering::SeqCst)
}

/// Get current log file path
pub fn current_log_file() -> Option<PathBuf> {
    RECORDER.lock().as_ref().map(|r| r.current_file().clone())
}

/// Flush and close the recorder
pub fn shutdown() {
    let mut guard = RECORDER.lock();
    if let Some(mut recorder) = guard.take() {
        let uptime = 0; // TODO: Calculate actual uptime
        let _ = recorder.record(&SecurityEvent::system_stop(uptime));
        let _ = recorder.writer.flush();
        log::info!("Security recorder shutdown. Total events: {}", events_recorded());
    }
}

// ============================================================================
// QUERY API (for reading logs)
// ============================================================================

use std::io::{BufRead, BufReader};

/// Read all events from a log file
pub fn read_events(file_path: &PathBuf) -> std::io::Result<Vec<SecurityEvent>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if !line.is_empty() {
            if let Ok(event) = serde_json::from_str::<SecurityEvent>(&line) {
                events.push(event);
            }
        }
    }

    Ok(events)
}

/// Count events by type in a log file
pub fn count_events_by_type(file_path: &PathBuf) -> std::io::Result<std::collections::HashMap<String, u64>> {
    let events = read_events(file_path)?;
    let mut counts = std::collections::HashMap::new();

    for event in events {
        *counts.entry(event.event_type.as_str().to_string()).or_insert(0) += 1;
    }

    Ok(counts)
}

/// Find user override events (for training data)
pub fn find_overrides(file_path: &PathBuf) -> std::io::Result<Vec<SecurityEvent>> {
    let events = read_events(file_path)?;
    Ok(events.into_iter().filter(|e| e.is_override()).collect())
}

/// Get list of all log files in directory
pub fn list_log_files(dir: &PathBuf) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "jsonl") {
                files.push(path);
            }
        }
    }

    // Sort by name (which includes timestamp)
    files.sort();
    Ok(files)
}

// ============================================================================
// STATS
// ============================================================================

/// Statistics about logged events
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecorderStats {
    pub events_recorded: u64,
    pub current_file: Option<String>,
    pub session_id: String,
}

/// Get recorder statistics
pub fn stats() -> RecorderStats {
    RecorderStats {
        events_recorded: events_recorded(),
        current_file: current_log_file().map(|p| p.to_string_lossy().to_string()),
        session_id: super::event::get_session_id(),
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::event::{EventType, ProcessInfo};
    use tempfile::TempDir;

    #[test]
    fn test_recorder_creation() {
        let temp_dir = TempDir::new().unwrap();
        let recorder = Recorder::new(temp_dir.path().to_path_buf()).unwrap();
        assert!(recorder.current_file().exists());
    }

    #[test]
    fn test_record_event() {
        let temp_dir = TempDir::new().unwrap();
        let mut recorder = Recorder::new(temp_dir.path().to_path_buf()).unwrap();

        let event = SecurityEvent::new(EventType::SystemStart, "Test start");
        recorder.record(&event).unwrap();

        // Read back
        let events = read_events(&recorder.current_file).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::SystemStart);
    }

    #[test]
    fn test_jsonl_format() {
        let temp_dir = TempDir::new().unwrap();
        let mut recorder = Recorder::new(temp_dir.path().to_path_buf()).unwrap();

        // Write multiple events
        for i in 0..3 {
            let event = SecurityEvent::new(EventType::ThreatDetected, &format!("Threat {}", i));
            recorder.record(&event).unwrap();
        }

        // Verify file format (one JSON per line)
        let content = std::fs::read_to_string(&recorder.current_file).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);

        for line in lines {
            assert!(serde_json::from_str::<SecurityEvent>(line).is_ok());
        }
    }

    #[test]
    fn test_find_overrides() {
        let temp_dir = TempDir::new().unwrap();
        let mut recorder = Recorder::new(temp_dir.path().to_path_buf()).unwrap();

        // Write mixed events
        recorder.record(&SecurityEvent::new(EventType::ThreatDetected, "Threat")).unwrap();
        recorder.record(&SecurityEvent::user_override_event(
            ProcessInfo::new(123, "test.exe"),
            "Kill",
            "Allow",
            Some("User knows this".to_string()),
            5000,
        )).unwrap();
        recorder.record(&SecurityEvent::new(EventType::ThreatDetected, "Another")).unwrap();

        let overrides = find_overrides(&recorder.current_file).unwrap();
        assert_eq!(overrides.len(), 1);
        assert!(overrides[0].user_override.is_some());
    }
}
