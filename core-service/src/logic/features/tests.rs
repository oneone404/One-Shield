//! Integration Tests for Feature Extraction Modules
//!
//! Tests các feature extractors hoạt động đúng khi kết hợp với nhau.

#[cfg(test)]
mod integration_tests {
    use crate::logic::features::{
        cpu::CpuFeatures,
        memory::MemoryFeatures,
        network::NetworkFeatures,
        disk::DiskFeatures,
        process::ProcessFeatures,
        vector::{FeatureExtractor, FeatureVector, FEATURE_COUNT},
    };

    /// Test tất cả extractors hoạt động cùng nhau
    #[test]
    fn test_all_extractors_combined() {
        let mut cpu = CpuFeatures::new();
        let mut memory = MemoryFeatures::new();
        let mut network = NetworkFeatures::new();
        let mut disk = DiskFeatures::new();
        let mut process = ProcessFeatures::new();

        // Simulate some events
        for i in 0..10 {
            cpu.add_sample(20.0 + i as f32 * 5.0);
            memory.add_sample(200.0 + i as f64 * 50.0);
            network.update(1000 * (i + 1) as u64, 2000 * (i + 1) as u64);
            disk.add_sample(
                1000 * i as u64,
                500 * i as u64,
                100.0 * i as f64,
                50.0 * i as f64,
            );
            process.add_process(1000 + i as u32, i < 3);
        }

        // Build feature vector
        let mut vector = FeatureVector::new();
        cpu.extract(&mut vector);
        memory.extract(&mut vector);
        network.extract(&mut vector);
        disk.extract(&mut vector);
        process.extract(&mut vector);

        // Verify all features are set
        let features = vector.as_array();

        // CPU features (0, 1, 10)
        assert!(features[0] > 0.0, "avg_cpu should be > 0");
        assert!(features[1] > 0.0, "max_cpu should be > 0");

        // Memory features (2, 3, 11)
        assert!(features[2] > 0.0, "avg_memory should be > 0");
        assert!(features[3] > 0.0, "max_memory should be > 0");

        // Network features (4, 5, 9)
        assert!(features[4] > 0.0, "network_sent_log should be > 0");
        assert!(features[5] > 0.0, "network_recv_log should be > 0");

        // Disk features (6, 7, 13)
        assert!(features[6] >= 0.0, "disk_read_log should be >= 0");
        assert!(features[7] >= 0.0, "disk_write_log should be >= 0");

        // Process features (8, 12, 14)
        assert!(features[8] == 10.0, "unique_processes should be 10");
        assert!(features[12] > 0.0, "new_process_rate should be > 0");
        assert!(features[14] > 0.0, "process_churn_rate should be > 0");
    }

    /// Test CPU spike detection accuracy
    #[test]
    fn test_cpu_spike_detection() {
        let mut cpu = CpuFeatures::new();

        // Normal values
        cpu.add_sample(10.0);
        cpu.add_sample(20.0);
        cpu.add_sample(30.0);

        // Spikes (> 50%)
        cpu.add_sample(60.0);
        cpu.add_sample(80.0);

        assert_eq!(cpu.spike_count, 2);
        assert_eq!(cpu.total_samples, 5);
        assert!((cpu.spike_rate() - 0.4).abs() < 0.01);
    }

    /// Test memory spike detection
    #[test]
    fn test_memory_spike_detection() {
        let mut memory = MemoryFeatures::new();

        // Normal values
        memory.add_sample(100.0);
        memory.add_sample(200.0);

        // Spikes (> 500 MB)
        memory.add_sample(600.0);
        memory.add_sample(1000.0);

        assert_eq!(memory.spike_count, 2);
        assert_eq!(memory.total_samples, 4);
        assert_eq!(memory.spike_rate(), 0.5);
    }

    /// Test network ratio calculation
    #[test]
    fn test_network_ratio() {
        let mut network = NetworkFeatures::new();

        // Equal sent/recv
        network.update(1000, 1000);
        assert_eq!(network.ratio(), 0.5);

        // More sent than recv
        let mut network2 = NetworkFeatures::new();
        network2.update(3000, 1000);
        assert_eq!(network2.ratio(), 0.75);

        // More recv than sent
        let mut network3 = NetworkFeatures::new();
        network3.update(1000, 3000);
        assert_eq!(network3.ratio(), 0.25);
    }

    /// Test process churn rate
    #[test]
    fn test_process_churn_rate() {
        let mut process = ProcessFeatures::new();

        // 5 unique PIDs, 10 samples
        for i in 0..10 {
            process.add_process(1000 + (i % 5) as u32, false);
        }

        assert_eq!(process.unique_count(), 5);
        assert_eq!(process.total_samples, 10);
        assert_eq!(process.churn_rate(), 0.5);
    }

    /// Test FeatureVector bounds
    #[test]
    fn test_feature_vector_bounds() {
        let vector = FeatureVector::new();

        assert_eq!(vector.as_array().len(), FEATURE_COUNT);
        assert_eq!(FEATURE_COUNT, 15);

        for &val in vector.as_slice() {
            assert!(val >= 0.0);
        }
    }
}
