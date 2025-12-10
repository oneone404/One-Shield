use std::path::{Path, PathBuf};
use std::fs;
use crate::logic::features::layout::FEATURE_COUNT;
use super::types::VersionedBaseline;
use super::validate::{validate_baseline, BaselineError};

/// Get default baseline path
pub fn get_default_baseline_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ai-security") // App name
        .join("baseline_v1.json")
}

/// Save baseline to disk
pub fn save_baseline(baseline: &VersionedBaseline, path: &Path) -> Result<(), BaselineError> {
    // Ensure directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_vec_pretty(baseline)?;
    fs::write(path, json)?;
    Ok(())
}

/// Load baseline from disk with validation
pub fn load_baseline(path: &Path) -> Result<VersionedBaseline, BaselineError> {
    if !path.exists() {
        return Err(BaselineError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Baseline file not found",
        )));
    }

    let data = fs::read(path)?;
    let baseline: VersionedBaseline = serde_json::from_slice(&data)?;

    // Validate version/layout
    validate_baseline(&baseline)?;

    Ok(baseline)
}

/// Helper to create a new empty baseline
pub fn new_baseline(name: &str) -> VersionedBaseline {
    VersionedBaseline::new(name)
}
