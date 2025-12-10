//! GPU Feature Extraction
//!
//! Trích xuất các features liên quan đến GPU usage.
//! Sử dụng nvidia-smi cho NVIDIA GPUs.

use super::vector::FeatureExtractor;
use std::process::Command;

/// GPU Features từ metrics
#[derive(Debug, Clone, Default)]
pub struct GpuFeatures {
    pub gpu_usage: f32,           // %
    pub memory_usage: f32,        // %
    pub memory_used_mb: f32,
    pub memory_total_mb: f32,
    pub temperature: f32,         // Celsius
    pub power_draw: f32,          // Watts
    pub fan_speed: f32,           // % 🆕
    pub gpu_available: bool,
}

impl GpuFeatures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fetch GPU metrics từ nvidia-smi
    pub fn fetch() -> Self {
        match fetch_nvidia_smi() {
            Ok(features) => features,
            Err(e) => {
                log::debug!("Failed to fetch GPU metrics: {}", e);
                Self::default()
            }
        }
    }

    /// Check if GPU is available
    pub fn is_available(&self) -> bool {
        self.gpu_available
    }

    /// Get memory usage percentage
    pub fn memory_percent(&self) -> f32 {
        if self.memory_total_mb > 0.0 {
            (self.memory_used_mb / self.memory_total_mb) * 100.0
        } else {
            0.0
        }
    }
}

/// Fetch GPU metrics via nvidia-smi
fn fetch_nvidia_smi() -> Result<GpuFeatures, String> {
    let output = Command::new("nvidia-smi")
        .args([
            "--query-gpu=utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu,power.draw,fan.speed",
            "--format=csv,noheader,nounits"
        ])
        .output()
        .map_err(|e| format!("nvidia-smi not found: {}", e))?;

    if !output.status.success() {
        return Err("nvidia-smi failed".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().ok_or("No output")?;
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();

    if parts.len() < 6 {
        return Err(format!("Unexpected format: {}", line));
    }

    Ok(GpuFeatures {
        gpu_usage: parts[0].parse().unwrap_or(0.0),
        memory_usage: parts[1].parse().unwrap_or(0.0),
        memory_used_mb: parts[2].parse().unwrap_or(0.0),
        memory_total_mb: parts[3].parse().unwrap_or(0.0),
        temperature: parts[4].parse().unwrap_or(0.0),
        power_draw: parts[5].parse().unwrap_or(0.0),
        fan_speed: parts.get(6).and_then(|s| s.parse().ok()).unwrap_or(0.0),
        gpu_available: true,
    })
}

// Note: GPU features are NOT part of the standard 15-feature vector
// They are additional features for extended monitoring
impl FeatureExtractor for GpuFeatures {
    fn extract(&self, _vector: &mut super::vector::FeatureVector) {
        // GPU features are separate from the 15-feature ML vector
        // They are used for display/monitoring only
        // In future: could add to extended feature vector
    }
}

/// GPU info for display (not ML)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct GpuInfo {
    pub name: String,
    pub driver_version: String,
    pub cuda_version: String,
    pub memory_total_mb: u64,
}

impl GpuInfo {
    /// Fetch static GPU info
    pub fn fetch() -> Option<Self> {
        let output = Command::new("nvidia-smi")
            .args([
                "--query-gpu=name,driver_version,memory.total",
                "--format=csv,noheader,nounits"
            ])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout.lines().next()?;
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();

        if parts.len() < 3 {
            return None;
        }

        // Get CUDA version separately
        let cuda_output = Command::new("nvidia-smi")
            .output()
            .ok()?;

        let cuda_stdout = String::from_utf8_lossy(&cuda_output.stdout);
        let cuda_version = cuda_stdout
            .lines()
            .find(|l| l.contains("CUDA Version"))
            .and_then(|l| l.split("CUDA Version:").nth(1))
            .map(|s| s.split_whitespace().next().unwrap_or("").to_string())
            .unwrap_or_default();

        Some(GpuInfo {
            name: parts[0].to_string(),
            driver_version: parts[1].to_string(),
            cuda_version,
            memory_total_mb: parts[2].parse().unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_features_default() {
        let gpu = GpuFeatures::new();
        assert_eq!(gpu.gpu_usage, 0.0);
        assert!(!gpu.gpu_available);
    }

    #[test]
    fn test_gpu_memory_percent() {
        let gpu = GpuFeatures {
            memory_used_mb: 4000.0,
            memory_total_mb: 8000.0,
            ..Default::default()
        };
        assert_eq!(gpu.memory_percent(), 50.0);
    }
}
