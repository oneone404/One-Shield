use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use chrono::Utc;
use crate::logic::dataset::record::DatasetRecord;

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

pub struct DatasetWriter {
    file: Mutex<Option<File>>,
    base_dir: PathBuf,
}

impl DatasetWriter {
    pub fn new() -> Self {
        let base_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ai-security")
            .join("dataset");
        Self::from_path(base_dir)
    }

    pub fn from_path(base_dir: PathBuf) -> Self {
        if let Err(e) = fs::create_dir_all(&base_dir) {
            // In test env, log might not be init, use println or ignore
            eprintln!("Failed to create dataset directory: {}", e);
        }

        Self {
            file: Mutex::new(None),
            base_dir,
        }
    }

    /// Append record to dataset log
    /// Handles file rotation automatically
    pub fn append(&self, record: &DatasetRecord) -> io::Result<()> {
        let mut file_guard = self.file.lock().unwrap();

        // If file not open, try to find latest or create new
        if file_guard.is_none() {
            let latest = self.find_latest_log_file()?;
            if let Some(path) = latest {
                 let f = OpenOptions::new().create(true).append(true).open(&path)?;
                 // Check size immediately
                 if f.metadata()?.len() < MAX_FILE_SIZE {
                     *file_guard = Some(f);
                 } else {
                     // Too big, create new
                     *file_guard = Some(self.create_new_file()?);
                 }
            } else {
                 // No files, create first
                 *file_guard = Some(self.create_new_file()?);
            }
        }

        // Check size of currently open file
        // (Double check in case we just opened it and it's full, though logic above handles it,
        // this handles the case where it becomes full during runtime)
        let should_rotate = if let Some(f) = file_guard.as_ref() {
            f.metadata()?.len() >= MAX_FILE_SIZE
        } else {
            false
        };

        if should_rotate {
            *file_guard = Some(self.create_new_file()?);
        }

        // Write content
        if let Some(file) = file_guard.as_mut() {
            let json = serde_json::to_string(record)?;
            writeln!(file, "{}", json)?;
        }

        Ok(())
    }

    pub fn get_stats(&self) -> io::Result<(usize, f32, String)> {
        let mut count = 0;
        let mut size = 0u64;
        let mut latest_file = String::from("None");

        let entries = fs::read_dir(&self.base_dir)?;
        let mut entry_paths = Vec::new();

        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "jsonl") {
                    count += 1;
                    if let Ok(meta) = entry.metadata() {
                        size += meta.len();
                    }
                    entry_paths.push(path);
                }
            }
        }

        if let Some(last) = entry_paths.iter().max() {
            latest_file = last.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Unknown")
                .to_string();
        }

        Ok((count, size as f32 / 1024.0 / 1024.0, latest_file))
    }

    fn create_new_file(&self) -> io::Result<File> {
        let now = Utc::now();
        // timestamp format: YYYY-MM-DD-HHMMSS
        let filename = format!("dataset-{}.jsonl", now.format("%Y-%m-%d-%H%M%S"));
        let path = self.base_dir.join(filename);

        OpenOptions::new().create(true).append(true).open(path)
    }

    fn find_latest_log_file(&self) -> io::Result<Option<PathBuf>> {
        let mut entries = fs::read_dir(&self.base_dir)?
            .filter_map(|res| res.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map_or(false, |ext| ext == "jsonl"))
            .collect::<Vec<_>>();

        if entries.is_empty() {
            return Ok(None);
        }

        // Sort by filename (timestamp ensures order)
        entries.sort();
        Ok(entries.last().cloned())
    }
}
