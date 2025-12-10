//! Dynamic Threshold Configuration
//!
//! Quản lý ngưỡng phát hiện anomaly.
//! Hỗ trợ dynamic threshold dựa trên baseline.

use serde::{Deserialize, Serialize};

/// Threshold Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Base threshold (0.0 - 1.0)
    pub base_threshold: f32,

    /// Minimum threshold (floor)
    pub min_threshold: f32,

    /// Maximum threshold (ceiling)
    pub max_threshold: f32,

    /// Sensitivity multiplier
    pub sensitivity: f32,

    /// Enable dynamic adjustment
    pub dynamic: bool,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            base_threshold: 0.7,
            min_threshold: 0.3,
            max_threshold: 0.95,
            sensitivity: 1.0,
            dynamic: false,
        }
    }
}

impl ThresholdConfig {
    pub fn new(base: f32) -> Self {
        Self {
            base_threshold: base,
            ..Default::default()
        }
    }

    /// High sensitivity (lower threshold)
    pub fn high_sensitivity() -> Self {
        Self {
            base_threshold: 0.5,
            sensitivity: 1.5,
            ..Default::default()
        }
    }

    /// Low sensitivity (higher threshold)
    pub fn low_sensitivity() -> Self {
        Self {
            base_threshold: 0.85,
            sensitivity: 0.7,
            ..Default::default()
        }
    }
}

/// Dynamic Threshold - Adjusts based on recent predictions
#[derive(Debug, Clone)]
pub struct DynamicThreshold {
    config: ThresholdConfig,
    recent_scores: Vec<f32>,
    max_history: usize,
    current_threshold: f32,
}

impl DynamicThreshold {
    pub fn new(config: ThresholdConfig) -> Self {
        let initial = config.base_threshold;
        Self {
            config,
            recent_scores: Vec::new(),
            max_history: 100,
            current_threshold: initial,
        }
    }

    /// Add a score and update threshold
    pub fn update(&mut self, score: f32) {
        self.recent_scores.push(score);

        if self.recent_scores.len() > self.max_history {
            self.recent_scores.remove(0);
        }

        if self.config.dynamic && self.recent_scores.len() >= 10 {
            self.recalculate();
        }
    }

    /// Recalculate dynamic threshold
    fn recalculate(&mut self) {
        if self.recent_scores.is_empty() {
            return;
        }

        // Calculate mean and std
        let n = self.recent_scores.len() as f32;
        let mean: f32 = self.recent_scores.iter().sum::<f32>() / n;
        let variance: f32 = self.recent_scores.iter()
            .map(|s| (s - mean).powi(2))
            .sum::<f32>() / n;
        let std = variance.sqrt();

        // Dynamic threshold = mean + 2*std (adjusted by sensitivity)
        let dynamic = mean + (2.0 * std * self.config.sensitivity);

        // Clamp to bounds
        self.current_threshold = dynamic
            .max(self.config.min_threshold)
            .min(self.config.max_threshold);
    }

    /// Get current threshold
    pub fn get(&self) -> f32 {
        self.current_threshold
    }

    /// Check if score exceeds threshold
    pub fn is_anomaly(&self, score: f32) -> bool {
        score > self.current_threshold
    }

    /// Reset threshold to base
    pub fn reset(&mut self) {
        self.recent_scores.clear();
        self.current_threshold = self.config.base_threshold;
    }

    /// Get statistics
    pub fn stats(&self) -> ThresholdStats {
        let n = self.recent_scores.len();
        let mean = if n > 0 {
            self.recent_scores.iter().sum::<f32>() / n as f32
        } else {
            0.0
        };

        ThresholdStats {
            current: self.current_threshold,
            base: self.config.base_threshold,
            mean_score: mean,
            sample_count: n,
        }
    }
}

impl Default for DynamicThreshold {
    fn default() -> Self {
        Self::new(ThresholdConfig::default())
    }
}

/// Threshold statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdStats {
    pub current: f32,
    pub base: f32,
    pub mean_score: f32,
    pub sample_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_config() {
        let config = ThresholdConfig::default();
        assert_eq!(config.base_threshold, 0.7);
    }

    #[test]
    fn test_dynamic_threshold() {
        let config = ThresholdConfig {
            dynamic: true,
            ..Default::default()
        };
        let mut dt = DynamicThreshold::new(config);

        // Add some scores
        for i in 0..20 {
            dt.update(0.3 + (i as f32) * 0.01);
        }

        // Threshold should have adjusted
        assert!(dt.get() != 0.7);
    }
}
