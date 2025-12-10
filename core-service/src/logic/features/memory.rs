//! Memory Feature Extraction
//!
//! Trích xuất các features liên quan đến Memory usage.

use super::vector::FeatureExtractor;

/// Ngưỡng Memory spike (MB)
pub const MEMORY_SPIKE_THRESHOLD: f64 = 500.0;

/// Memory Features từ raw metrics
#[derive(Debug, Clone, Default)]
pub struct MemoryFeatures {
    pub avg_usage_mb: f32,
    pub max_usage_mb: f32,
    pub spike_count: u32,
    pub total_samples: u32,
    total_sum: f64,
}

impl MemoryFeatures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Thêm sample Memory usage (MB)
    pub fn add_sample(&mut self, usage_mb: f64) {
        self.total_samples += 1;
        self.total_sum += usage_mb;

        // Update average
        self.avg_usage_mb = (self.total_sum / self.total_samples as f64) as f32;

        // Update max
        if usage_mb as f32 > self.max_usage_mb {
            self.max_usage_mb = usage_mb as f32;
        }

        // Check spike
        if usage_mb > MEMORY_SPIKE_THRESHOLD {
            self.spike_count += 1;
        }
    }

    /// Tính spike rate
    pub fn spike_rate(&self) -> f32 {
        if self.total_samples > 0 {
            self.spike_count as f32 / self.total_samples as f32
        } else {
            0.0
        }
    }

    /// Reset for new window
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

impl FeatureExtractor for MemoryFeatures {
    fn extract(&self, vector: &mut super::vector::FeatureVector) {
        vector.values[2] = self.avg_usage_mb;    // avg_memory
        vector.values[3] = self.max_usage_mb;    // max_memory
        vector.values[11] = self.spike_rate();   // memory_spike_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_features() {
        let mut mem = MemoryFeatures::new();
        mem.add_sample(200.0);
        mem.add_sample(600.0);
        mem.add_sample(400.0);

        assert_eq!(mem.avg_usage_mb, 400.0);
        assert_eq!(mem.max_usage_mb, 600.0);
        assert_eq!(mem.spike_count, 1); // Only 600.0 > 500.0
    }
}
