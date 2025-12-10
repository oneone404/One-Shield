//! Feature Vector - Core data structure for ML input
//!
//! **Versioned feature vector with layout validation**
//!
//! Uses centralized layout from `layout.rs` for:
//! - Consistent feature ordering
//! - Version tracking
//! - Layout hash for compatibility checks

use serde::{Deserialize, Serialize};
use super::layout::{
    FEATURE_COUNT, FEATURE_VERSION, FEATURE_LAYOUT,
    layout_hash, validate_layout, LayoutMismatchError,
};

// ============================================================================
// VERSIONED FEATURE VECTOR
// ============================================================================

/// Versioned Feature Vector with layout metadata
///
/// This struct MUST be used for all feature data to ensure compatibility.
/// Never use raw `Vec<f32>` or `[f32; N]` for features anymore!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    /// Feature layout version
    pub version: u8,
    /// CRC32 hash of the feature layout (for mismatch detection)
    pub layout_hash: u32,
    /// Feature values in order defined by FEATURE_LAYOUT
    pub values: [f32; FEATURE_COUNT],
}

impl FeatureVector {
    /// Create a new zeroed feature vector with current version
    pub fn new() -> Self {
        Self {
            version: FEATURE_VERSION,
            layout_hash: layout_hash(),
            values: [0.0; FEATURE_COUNT],
        }
    }

    /// Create from raw values with current version
    pub fn from_values(values: [f32; FEATURE_COUNT]) -> Self {
        Self {
            version: FEATURE_VERSION,
            layout_hash: layout_hash(),
            values,
        }
    }

    /// Create from a Vec<f32> (truncates or pads if wrong size)
    pub fn from_vec(values: Vec<f32>) -> Self {
        let mut array = [0.0f32; FEATURE_COUNT];
        for (i, v) in values.into_iter().take(FEATURE_COUNT).enumerate() {
            array[i] = v;
        }
        Self::from_values(array)
    }

    /// Get values as array reference
    pub fn as_array(&self) -> &[f32; FEATURE_COUNT] {
        &self.values
    }

    /// Get values as slice
    pub fn as_slice(&self) -> &[f32] {
        &self.values
    }

    /// Get feature by index
    pub fn get(&self, index: usize) -> Option<f32> {
        self.values.get(index).copied()
    }

    /// Get feature by name
    pub fn get_by_name(&self, name: &str) -> Option<f32> {
        super::layout::feature_index(name).and_then(|i| self.get(i))
    }

    /// Set feature by index
    pub fn set(&mut self, index: usize, value: f32) {
        if index < FEATURE_COUNT {
            self.values[index] = value;
        }
    }

    /// Set feature by name
    pub fn set_by_name(&mut self, name: &str, value: f32) -> bool {
        if let Some(index) = super::layout::feature_index(name) {
            self.set(index, value);
            true
        } else {
            false
        }
    }

    /// Validate that this vector is compatible with current layout
    pub fn validate(&self) -> Result<(), LayoutMismatchError> {
        validate_layout(self.version, self.layout_hash)
    }

    /// Check if this vector is compatible with current layout
    pub fn is_compatible(&self) -> bool {
        self.validate().is_ok()
    }

    /// Get feature names for this vector
    pub fn feature_names(&self) -> &'static [&'static str] {
        FEATURE_LAYOUT
    }

    /// Convert to JSON-serializable format for logging
    pub fn to_log_entry(&self) -> serde_json::Value {
        serde_json::json!({
            "feature_version": self.version,
            "layout_hash": self.layout_hash,
            "values": self.values,
            "named_values": FEATURE_LAYOUT.iter()
                .zip(self.values.iter())
                .map(|(name, value)| (name.to_string(), *value))
                .collect::<std::collections::HashMap<_, _>>(),
        })
    }
}

impl Default for FeatureVector {
    fn default() -> Self {
        Self::new()
    }
}

// For backward compatibility - convert old array to new versioned format
impl From<[f32; FEATURE_COUNT]> for FeatureVector {
    fn from(values: [f32; FEATURE_COUNT]) -> Self {
        Self::from_values(values)
    }
}

impl From<Vec<f32>> for FeatureVector {
    fn from(values: Vec<f32>) -> Self {
        Self::from_vec(values)
    }
}

// ============================================================================
// FEATURE EXTRACTOR TRAIT
// ============================================================================

/// Trait for feature extractors
pub trait FeatureExtractor {
    /// Extract features and update the vector
    fn extract(&self, vector: &mut FeatureVector);
}

// ============================================================================
// BUILDER PATTERN
// ============================================================================

/// Builder for creating FeatureVector with named setters
pub struct FeatureVectorBuilder {
    vector: FeatureVector,
}

impl FeatureVectorBuilder {
    pub fn new() -> Self {
        Self { vector: FeatureVector::new() }
    }

    // CPU features
    pub fn cpu_percent(mut self, value: f32) -> Self {
        self.vector.set_by_name("cpu_percent", value);
        self
    }

    pub fn cpu_spike_rate(mut self, value: f32) -> Self {
        self.vector.set_by_name("cpu_spike_rate", value);
        self
    }

    // Memory features
    pub fn memory_percent(mut self, value: f32) -> Self {
        self.vector.set_by_name("memory_percent", value);
        self
    }

    pub fn memory_spike_rate(mut self, value: f32) -> Self {
        self.vector.set_by_name("memory_spike_rate", value);
        self
    }

    // Network features
    pub fn network_sent_rate(mut self, value: f32) -> Self {
        self.vector.set_by_name("network_sent_rate", value);
        self
    }

    pub fn network_recv_rate(mut self, value: f32) -> Self {
        self.vector.set_by_name("network_recv_rate", value);
        self
    }

    pub fn network_ratio(mut self, value: f32) -> Self {
        self.vector.set_by_name("network_ratio", value);
        self
    }

    // Disk features
    pub fn disk_read_rate(mut self, value: f32) -> Self {
        self.vector.set_by_name("disk_read_rate", value);
        self
    }

    pub fn disk_write_rate(mut self, value: f32) -> Self {
        self.vector.set_by_name("disk_write_rate", value);
        self
    }

    pub fn combined_io(mut self, value: f32) -> Self {
        self.vector.set_by_name("combined_io", value);
        self
    }

    // Process features
    pub fn unique_processes(mut self, value: f32) -> Self {
        self.vector.set_by_name("unique_processes", value);
        self
    }

    pub fn new_process_rate(mut self, value: f32) -> Self {
        self.vector.set_by_name("new_process_rate", value);
        self
    }

    pub fn process_churn_rate(mut self, value: f32) -> Self {
        self.vector.set_by_name("process_churn_rate", value);
        self
    }

    // Derived features
    pub fn cpu_memory_product(mut self, value: f32) -> Self {
        self.vector.set_by_name("cpu_memory_product", value);
        self
    }

    pub fn spike_correlation(mut self, value: f32) -> Self {
        self.vector.set_by_name("spike_correlation", value);
        self
    }

    /// Set feature by name dynamically
    pub fn set(mut self, name: &str, value: f32) -> Self {
        self.vector.set_by_name(name, value);
        self
    }

    pub fn build(self) -> FeatureVector {
        self.vector
    }
}

impl Default for FeatureVectorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_vector_new() {
        let vector = FeatureVector::new();
        assert_eq!(vector.version, FEATURE_VERSION);
        assert_eq!(vector.layout_hash, layout_hash());
        assert_eq!(vector.values.len(), FEATURE_COUNT);
    }

    #[test]
    fn test_feature_vector_builder() {
        let vector = FeatureVectorBuilder::new()
            .cpu_percent(50.0)
            .memory_percent(75.0)
            .build();

        assert_eq!(vector.get_by_name("cpu_percent"), Some(50.0));
        assert_eq!(vector.get_by_name("memory_percent"), Some(75.0));
    }

    #[test]
    fn test_feature_vector_set_by_name() {
        let mut vector = FeatureVector::new();
        assert!(vector.set_by_name("cpu_percent", 42.0));
        assert_eq!(vector.get_by_name("cpu_percent"), Some(42.0));

        assert!(!vector.set_by_name("nonexistent", 0.0));
    }

    #[test]
    fn test_feature_vector_validation() {
        let vector = FeatureVector::new();
        assert!(vector.is_compatible());
        assert!(vector.validate().is_ok());
    }

    #[test]
    fn test_feature_vector_from_array() {
        let array = [1.0; FEATURE_COUNT];
        let vector: FeatureVector = array.into();

        assert_eq!(vector.version, FEATURE_VERSION);
        assert_eq!(vector.values, array);
    }

    #[test]
    fn test_to_log_entry() {
        let vector = FeatureVectorBuilder::new()
            .cpu_percent(50.0)
            .build();

        let log = vector.to_log_entry();
        assert_eq!(log["feature_version"], FEATURE_VERSION);
        assert!(log["layout_hash"].as_u64().is_some());
    }
}
