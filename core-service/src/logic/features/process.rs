//! Process Feature Extraction
//!
//! Trích xuất các features liên quan đến Process behavior.

use std::collections::HashSet;
use super::vector::FeatureExtractor;

/// Process Features từ raw metrics
#[derive(Debug, Clone, Default)]
pub struct ProcessFeatures {
    pub unique_pids: HashSet<u32>,
    pub new_process_count: u32,
    pub total_samples: u32,
}

impl ProcessFeatures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Thêm process sample
    pub fn add_process(&mut self, pid: u32, is_new: bool) {
        self.unique_pids.insert(pid);
        self.total_samples += 1;

        if is_new {
            self.new_process_count += 1;
        }
    }

    /// Số unique processes
    pub fn unique_count(&self) -> usize {
        self.unique_pids.len()
    }

    /// Tính new process rate
    pub fn new_process_rate(&self) -> f32 {
        if self.total_samples > 0 {
            self.new_process_count as f32 / self.total_samples as f32
        } else {
            0.0
        }
    }

    /// Tính process churn rate (unique / total)
    pub fn churn_rate(&self) -> f32 {
        if self.total_samples > 0 {
            self.unique_pids.len() as f32 / self.total_samples as f32
        } else {
            0.0
        }
    }

    /// Get unique PIDs as vector
    pub fn get_unique_pids(&self) -> Vec<u32> {
        self.unique_pids.iter().copied().collect()
    }

    /// Reset for new window
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

impl FeatureExtractor for ProcessFeatures {
    fn extract(&self, vector: &mut super::vector::FeatureVector) {
        vector.values[8] = self.unique_count() as f32;  // unique_processes
        vector.values[12] = self.new_process_rate();    // new_process_rate
        vector.values[14] = self.churn_rate();          // process_churn_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_features() {
        let mut proc = ProcessFeatures::new();
        proc.add_process(1234, true);
        proc.add_process(5678, false);
        proc.add_process(1234, false); // Duplicate PID

        assert_eq!(proc.unique_count(), 2);
        assert_eq!(proc.total_samples, 3);
        assert_eq!(proc.new_process_count, 1);
    }
}
