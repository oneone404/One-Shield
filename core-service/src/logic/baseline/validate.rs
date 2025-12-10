use crate::logic::features::layout::validate_layout;
use super::types::VersionedBaseline;

#[derive(Debug)]
pub enum BaselineError {
    IoError(std::io::Error),
    SerializationError(serde_json::Error),
    LayoutMismatch {
        expected_version: u8,
        expected_hash: u32,
        actual_version: u8,
        actual_hash: u32,
    },
    Other(String),
}

impl std::fmt::Display for BaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaselineError::IoError(e) => write!(f, "IO Error: {}", e),
            BaselineError::SerializationError(e) => write!(f, "Serialization Error: {}", e),
            BaselineError::LayoutMismatch { expected_version, expected_hash, actual_version, actual_hash } => {
                write!(f, "Baseline Layout Mismatch: Expected v{} ({:x}), Got v{} ({:x})",
                    expected_version, expected_hash, actual_version, actual_hash)
            },
            BaselineError::Other(msg) => write!(f, "Baseline Error: {}", msg),
        }
    }
}

impl std::error::Error for BaselineError {}

impl From<std::io::Error> for BaselineError {
    fn from(err: std::io::Error) -> Self {
        BaselineError::IoError(err)
    }
}

impl From<serde_json::Error> for BaselineError {
    fn from(err: serde_json::Error) -> Self {
        BaselineError::SerializationError(err)
    }
}

/// Validate baseline compatibility with current engine
pub fn validate_baseline(baseline: &VersionedBaseline) -> Result<(), BaselineError> {
    match validate_layout(baseline.feature_version, baseline.layout_hash) {
        Ok(_) => Ok(()),
        Err(e) => Err(BaselineError::LayoutMismatch {
            expected_version: e.expected_version,
            expected_hash: e.expected_hash,
            actual_version: e.actual_version,
            actual_hash: e.actual_hash,
        }),
    }
}
