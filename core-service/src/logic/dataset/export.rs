use std::fs::{self, File};
use std::io::{self, Write};
use crate::logic::dataset::get_dataset_dir;

/// Export all dataset files to a single JSONL file
/// Returns the number of source files merged
pub fn to_jsonl(target_path: &str) -> io::Result<usize> {
    let source_dir = get_dataset_dir();

    if !source_dir.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Dataset directory not found"));
    }

    // Create target file (truncate if exists)
    let mut output_file = File::create(target_path)?;
    let mut file_count = 0;

    // Get all .jsonl files
    let mut paths: Vec<_> = fs::read_dir(source_dir)?
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |e| e == "jsonl"))
        .collect();

    // Sort by timestamp (filename) to maintain chronological order
    paths.sort();

    for path in paths {
        // Read file content and append to output
        let content = fs::read(&path)?;
        output_file.write_all(&content)?;

        // Ensure newline between files if not present (simple check)
        if let Some(&last_byte) = content.last() {
            if last_byte != b'\n' {
                output_file.write_all(b"\n")?;
            }
        }

        file_count += 1;
    }

    output_file.flush()?;
    log::info!("Exported {} dataset files to {}", file_count, target_path);
    Ok(file_count)
}
