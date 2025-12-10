//! Feature Layout - Centralized Feature Definition
//!
//! **CRITICAL: This file controls the feature schema**
//!
//! ## Rules (NEVER break these):
//! 1. Add feature → increment FEATURE_VERSION
//! 2. Change order → increment FEATURE_VERSION
//! 3. Remove feature → increment FEATURE_VERSION
//!
//! ## Why versioning matters:
//! - Baseline compatibility
//! - AI model compatibility
//! - Log replay / training data
//! - Cross-version migrations

use crc32fast::Hasher;
use serde::{Deserialize, Serialize};

// ============================================================================
// FEATURE VERSION
// ============================================================================

/// Current feature layout version
/// MUST be incremented when layout changes
pub const FEATURE_VERSION: u8 = 1;

// ============================================================================
// FEATURE LAYOUT (Authoritative source)
// ============================================================================

/// Feature names in exact order they appear in the vector
/// This is the SINGLE SOURCE OF TRUTH for feature layout
pub const FEATURE_LAYOUT: &[&str] = &[
    // === CPU (0-1) ===
    "cpu_percent",           // 0: Current CPU usage percent
    "cpu_spike_rate",        // 1: Rate of CPU spikes per minute

    // === Memory (2-3) ===
    "memory_percent",        // 2: Current memory usage percent
    "memory_spike_rate",     // 3: Rate of memory spikes per minute

    // === Network (4-6) ===
    "network_sent_rate",     // 4: Network bytes sent per second
    "network_recv_rate",     // 5: Network bytes received per second
    "network_ratio",         // 6: Ratio of sent/recv (asymmetry indicator)

    // === Disk (7-9) ===
    "disk_read_rate",        // 7: Disk read bytes per second
    "disk_write_rate",       // 8: Disk write bytes per second
    "combined_io",           // 9: Combined disk I/O rate

    // === Process (10-12) ===
    "unique_processes",      // 10: Count of unique processes
    "new_process_rate",      // 11: Rate of new process creation
    "process_churn_rate",    // 12: Rate of process creation/termination

    // === Derived/Correlations (13-14) ===
    "cpu_memory_product",    // 13: CPU * Memory (resource pressure)
    "spike_correlation",     // 14: Correlation of CPU/Memory spikes
];

/// Total number of features
/// IMPORTANT: Must match FEATURE_LAYOUT.len()!
pub const FEATURE_COUNT: usize = 15;

// ============================================================================
// LAYOUT HASH
// ============================================================================

/// Compute CRC32 hash of the feature layout
/// Used to detect layout mismatches at runtime
pub fn compute_layout_hash() -> u32 {
    let mut hasher = Hasher::new();

    // Include version in hash
    hasher.update(&[FEATURE_VERSION]);

    // Hash all feature names in order
    for name in FEATURE_LAYOUT {
        hasher.update(name.as_bytes());
        hasher.update(&[0]); // Separator
    }

    hasher.finalize()
}

/// Get layout hash (cached for performance)
pub fn layout_hash() -> u32 {
    // Computed at compile time effectively since inputs are const
    compute_layout_hash()
}

// ============================================================================
// LAYOUT INFO
// ============================================================================

/// Complete layout information for serialization/logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutInfo {
    pub version: u8,
    pub hash: u32,
    pub feature_count: usize,
    pub feature_names: Vec<String>,
}

impl LayoutInfo {
    pub fn current() -> Self {
        Self {
            version: FEATURE_VERSION,
            hash: layout_hash(),
            feature_count: FEATURE_COUNT,
            feature_names: FEATURE_LAYOUT.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Default for LayoutInfo {
    fn default() -> Self {
        Self::current()
    }
}

// ============================================================================
// LAYOUT VALIDATION
// ============================================================================

/// Error when feature layout doesn't match expected
#[derive(Debug, Clone)]
pub struct LayoutMismatchError {
    pub expected_version: u8,
    pub expected_hash: u32,
    pub actual_version: u8,
    pub actual_hash: u32,
}

impl std::fmt::Display for LayoutMismatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Feature layout mismatch: expected v{} (hash: {:08x}), got v{} (hash: {:08x})",
            self.expected_version,
            self.expected_hash,
            self.actual_version,
            self.actual_hash
        )
    }
}

impl std::error::Error for LayoutMismatchError {}

/// Validate that incoming data matches current layout
pub fn validate_layout(incoming_version: u8, incoming_hash: u32) -> Result<(), LayoutMismatchError> {
    let current_hash = layout_hash();

    if incoming_version != FEATURE_VERSION || incoming_hash != current_hash {
        return Err(LayoutMismatchError {
            expected_version: FEATURE_VERSION,
            expected_hash: current_hash,
            actual_version: incoming_version,
            actual_hash: incoming_hash,
        });
    }

    Ok(())
}

/// Check if layout is compatible (same version, same hash)
pub fn is_layout_compatible(version: u8, hash: u32) -> bool {
    version == FEATURE_VERSION && hash == layout_hash()
}

// ============================================================================
// FEATURE INDEX LOOKUP
// ============================================================================

/// Get feature index by name (O(n) but features are few)
pub fn feature_index(name: &str) -> Option<usize> {
    FEATURE_LAYOUT.iter().position(|&n| n == name)
}

/// Get feature name by index
pub fn feature_name(index: usize) -> Option<&'static str> {
    FEATURE_LAYOUT.get(index).copied()
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_count() {
        assert_eq!(FEATURE_COUNT, 15);
        assert_eq!(FEATURE_LAYOUT.len(), FEATURE_COUNT);
    }

    #[test]
    fn test_layout_hash_consistency() {
        // Hash should be consistent across calls
        let hash1 = compute_layout_hash();
        let hash2 = compute_layout_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_layout_hash_non_zero() {
        let hash = layout_hash();
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_validate_layout_success() {
        let result = validate_layout(FEATURE_VERSION, layout_hash());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_layout_version_mismatch() {
        let result = validate_layout(FEATURE_VERSION + 1, layout_hash());
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_layout_hash_mismatch() {
        let result = validate_layout(FEATURE_VERSION, layout_hash() + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_feature_index() {
        assert_eq!(feature_index("cpu_percent"), Some(0));
        assert_eq!(feature_index("memory_percent"), Some(2));
        assert_eq!(feature_index("spike_correlation"), Some(14));
        assert_eq!(feature_index("nonexistent"), None);
    }

    #[test]
    fn test_feature_name() {
        assert_eq!(feature_name(0), Some("cpu_percent"));
        assert_eq!(feature_name(14), Some("spike_correlation"));
        assert_eq!(feature_name(100), None);
    }

    #[test]
    fn test_layout_info() {
        let info = LayoutInfo::current();
        assert_eq!(info.version, FEATURE_VERSION);
        assert_eq!(info.feature_count, FEATURE_COUNT);
        assert_eq!(info.feature_names.len(), FEATURE_COUNT);
    }
}
