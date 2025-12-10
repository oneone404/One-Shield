//! Feature Vector - Core data structure for ML input
//!
//! Định nghĩa FeatureVector với 15 features chuẩn.

use serde::{Deserialize, Serialize};

/// Số lượng features trong mỗi vector
pub const FEATURE_COUNT: usize = 15;

/// Feature Vector - Input cho ML model
///
/// Features:
/// 0.  avg_cpu - CPU trung bình (%)
/// 1.  max_cpu - CPU cao nhất (%)
/// 2.  avg_memory - Memory trung bình (MB)
/// 3.  max_memory - Memory cao nhất (MB)
/// 4.  total_network_sent - Tổng bytes gửi (log)
/// 5.  total_network_recv - Tổng bytes nhận (log)
/// 6.  total_disk_read - Tổng bytes đọc (log)
/// 7.  total_disk_write - Tổng bytes ghi (log)
/// 8.  unique_processes - Số process unique
/// 9.  network_ratio - Tỷ lệ sent/recv
/// 10. cpu_spike_rate - Tỷ lệ CPU spikes
/// 11. memory_spike_rate - Tỷ lệ Memory spikes
/// 12. new_process_rate - Tỷ lệ processes mới
/// 13. avg_disk_io_rate - I/O rate trung bình
/// 14. process_churn_rate - Tỷ lệ thay đổi processes
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct FeatureVector {
    pub values: [f32; FEATURE_COUNT],
}

impl FeatureVector {
    pub fn new() -> Self {
        Self { values: [0.0; FEATURE_COUNT] }
    }

    pub fn from_array(values: [f32; FEATURE_COUNT]) -> Self {
        Self { values }
    }

    pub fn as_array(&self) -> &[f32; FEATURE_COUNT] {
        &self.values
    }

    pub fn as_slice(&self) -> &[f32] {
        &self.values
    }

    /// Get feature by index with name
    pub fn get(&self, index: usize) -> Option<f32> {
        self.values.get(index).copied()
    }

    /// Set feature by index
    pub fn set(&mut self, index: usize, value: f32) {
        if index < FEATURE_COUNT {
            self.values[index] = value;
        }
    }
}

/// Feature names for debugging/logging
pub const FEATURE_NAMES: [&str; FEATURE_COUNT] = [
    "avg_cpu",
    "max_cpu",
    "avg_memory",
    "max_memory",
    "network_sent_log",
    "network_recv_log",
    "disk_read_log",
    "disk_write_log",
    "unique_processes",
    "network_ratio",
    "cpu_spike_rate",
    "memory_spike_rate",
    "new_process_rate",
    "disk_io_rate_log",
    "process_churn_rate",
];

/// Trait for feature extractors
pub trait FeatureExtractor {
    /// Extract features and update the vector
    fn extract(&self, vector: &mut FeatureVector);
}

/// Builder pattern for creating FeatureVector
pub struct FeatureVectorBuilder {
    vector: FeatureVector,
}

impl FeatureVectorBuilder {
    pub fn new() -> Self {
        Self { vector: FeatureVector::new() }
    }

    pub fn cpu_avg(mut self, value: f32) -> Self {
        self.vector.values[0] = value;
        self
    }

    pub fn cpu_max(mut self, value: f32) -> Self {
        self.vector.values[1] = value;
        self
    }

    pub fn memory_avg(mut self, value: f32) -> Self {
        self.vector.values[2] = value;
        self
    }

    pub fn memory_max(mut self, value: f32) -> Self {
        self.vector.values[3] = value;
        self
    }

    pub fn network_sent(mut self, value: f32) -> Self {
        self.vector.values[4] = value;
        self
    }

    pub fn network_recv(mut self, value: f32) -> Self {
        self.vector.values[5] = value;
        self
    }

    pub fn disk_read(mut self, value: f32) -> Self {
        self.vector.values[6] = value;
        self
    }

    pub fn disk_write(mut self, value: f32) -> Self {
        self.vector.values[7] = value;
        self
    }

    pub fn unique_processes(mut self, value: f32) -> Self {
        self.vector.values[8] = value;
        self
    }

    pub fn network_ratio(mut self, value: f32) -> Self {
        self.vector.values[9] = value;
        self
    }

    pub fn cpu_spike_rate(mut self, value: f32) -> Self {
        self.vector.values[10] = value;
        self
    }

    pub fn memory_spike_rate(mut self, value: f32) -> Self {
        self.vector.values[11] = value;
        self
    }

    pub fn new_process_rate(mut self, value: f32) -> Self {
        self.vector.values[12] = value;
        self
    }

    pub fn disk_io_rate(mut self, value: f32) -> Self {
        self.vector.values[13] = value;
        self
    }

    pub fn process_churn_rate(mut self, value: f32) -> Self {
        self.vector.values[14] = value;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_vector_builder() {
        let vector = FeatureVectorBuilder::new()
            .cpu_avg(50.0)
            .memory_avg(1024.0)
            .build();

        assert_eq!(vector.values[0], 50.0);
        assert_eq!(vector.values[2], 1024.0);
    }
}
