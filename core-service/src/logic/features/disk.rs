//! Disk Feature Extraction
//!
//! Trích xuất các features liên quan đến Disk I/O.

use super::vector::FeatureExtractor;

/// Disk Features từ raw metrics
#[derive(Debug, Clone, Default)]
pub struct DiskFeatures {
    pub total_read_bytes: u64,
    pub total_write_bytes: u64,
    pub total_io_rate: f64,
    pub sample_count: u32,
}

impl DiskFeatures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Thêm sample disk I/O
    pub fn add_sample(&mut self, read_bytes: u64, write_bytes: u64, read_rate: f64, write_rate: f64) {
        self.total_read_bytes += read_bytes;
        self.total_write_bytes += write_bytes;
        self.total_io_rate += read_rate + write_rate;
        self.sample_count += 1;
    }

    /// Tính log-scaled read bytes
    pub fn read_log(&self) -> f32 {
        ((self.total_read_bytes as f64) + 1.0).ln() as f32
    }

    /// Tính log-scaled write bytes
    pub fn write_log(&self) -> f32 {
        ((self.total_write_bytes as f64) + 1.0).ln() as f32
    }

    /// Tính average I/O rate (log-scaled)
    pub fn avg_io_rate_log(&self) -> f32 {
        if self.sample_count > 0 {
            let avg = self.total_io_rate / self.sample_count as f64;
            (avg + 1.0).ln() as f32
        } else {
            0.0
        }
    }

    /// Reset for new window
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

impl FeatureExtractor for DiskFeatures {
    fn extract(&self, vector: &mut super::vector::FeatureVector) {
        vector.values[6] = self.read_log();         // disk_read_log
        vector.values[7] = self.write_log();        // disk_write_log
        vector.values[13] = self.avg_io_rate_log(); // disk_io_rate_log
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_features() {
        let mut disk = DiskFeatures::new();
        disk.add_sample(1000, 500, 100.0, 50.0);
        disk.add_sample(2000, 1000, 200.0, 100.0);

        assert_eq!(disk.total_read_bytes, 3000);
        assert_eq!(disk.total_write_bytes, 1500);
        assert!(disk.avg_io_rate_log() > 0.0);
    }
}
