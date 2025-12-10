//! CPU Feature Extraction
//!
//! Trích xuất các features liên quan đến CPU usage.

use super::vector::FeatureExtractor;

/// Ngưỡng CPU spike (%)
pub const CPU_SPIKE_THRESHOLD: f32 = 50.0;

/// CPU Features từ raw metrics
#[derive(Debug, Clone, Default)]
pub struct CpuFeatures {
    pub avg_usage: f32,
    pub max_usage: f32,
    pub spike_count: u32,
    pub total_samples: u32,
}

impl CpuFeatures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Thêm sample CPU usage
    pub fn add_sample(&mut self, usage: f32) {
        self.total_samples += 1;

        // Update average (running average)
        let old_sum = self.avg_usage * (self.total_samples - 1) as f32;
        self.avg_usage = (old_sum + usage) / self.total_samples as f32;

        // Update max
        if usage > self.max_usage {
            self.max_usage = usage;
        }

        // Check spike
        if usage > CPU_SPIKE_THRESHOLD {
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

impl FeatureExtractor for CpuFeatures {
    fn extract(&self, vector: &mut super::vector::FeatureVector) {
        vector.values[0] = self.avg_usage;      // avg_cpu
        vector.values[1] = self.max_usage;      // max_cpu
        vector.values[10] = self.spike_rate();  // cpu_spike_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_features() {
        let mut cpu = CpuFeatures::new();
        cpu.add_sample(30.0);
        cpu.add_sample(60.0);
        cpu.add_sample(45.0);

        assert_eq!(cpu.avg_usage, 45.0);
        assert_eq!(cpu.max_usage, 60.0);
        assert_eq!(cpu.spike_count, 1); // Only 60.0 > 50.0
    }
}
