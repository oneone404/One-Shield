//! Network Feature Extraction
//!
//! Trích xuất các features liên quan đến Network I/O.

use super::vector::FeatureExtractor;

/// Network Features từ raw metrics
#[derive(Debug, Clone, Default)]
pub struct NetworkFeatures {
    pub total_sent_bytes: u64,
    pub total_recv_bytes: u64,
}

impl NetworkFeatures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cập nhật network stats
    pub fn update(&mut self, sent: u64, recv: u64) {
        // Lấy giá trị max (cumulative)
        self.total_sent_bytes = self.total_sent_bytes.max(sent);
        self.total_recv_bytes = self.total_recv_bytes.max(recv);
    }

    /// Tính log-scaled sent bytes
    pub fn sent_log(&self) -> f32 {
        ((self.total_sent_bytes as f64) + 1.0).ln() as f32
    }

    /// Tính log-scaled recv bytes
    pub fn recv_log(&self) -> f32 {
        ((self.total_recv_bytes as f64) + 1.0).ln() as f32
    }

    /// Tính network ratio (sent / total)
    pub fn ratio(&self) -> f32 {
        let total = self.total_sent_bytes + self.total_recv_bytes;
        if total > 0 {
            self.total_sent_bytes as f32 / total as f32
        } else {
            0.5
        }
    }

    /// Reset for new window
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

impl FeatureExtractor for NetworkFeatures {
    fn extract(&self, vector: &mut super::vector::FeatureVector) {
        vector.values[4] = self.sent_log();   // network_sent_log
        vector.values[5] = self.recv_log();   // network_recv_log
        vector.values[9] = self.ratio();      // network_ratio
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_features() {
        let mut net = NetworkFeatures::new();
        net.update(1000, 2000);
        net.update(1500, 2500);

        assert_eq!(net.total_sent_bytes, 1500);
        assert_eq!(net.total_recv_bytes, 2500);

        let ratio = net.ratio();
        assert!(ratio > 0.3 && ratio < 0.4);
    }
}
