#![allow(dead_code)]

//! AI Bridge - Native ONNX Runtime Integration (Phase IV)
//!
//! 🆕 v0.5.0: This module is now a thin wrapper around `model/inference`
//! for backward compatibility. New code should use `model/` directly.
//!
//! Load và chạy ONNX model trực tiếp trong Rust.
//! Không cần Python runtime - prediction trong microseconds.

// Re-export from model module for backward compatibility
pub use super::model::inference::{
    PredictionResult,
    load_onnx_model,
    is_model_loaded,
    get_metadata,
    load_normalization,
    predict_onnx,
    predict,
};

pub use super::model::buffer::{
    has_enough_data,
    clear_buffer,
    get_buffer_status,
    push_and_predict,
};

pub use super::features::FEATURE_COUNT;

// ============================================================================
// LEGACY COMPATIBILITY LAYER
// ============================================================================

/// Initialize AI Bridge với default paths
///
/// 🆕 Now delegates to model/inference
pub fn init() -> Result<(), super::model::inference::InferenceError> {
    // Try to load from common paths
    let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
    let model_paths = [
        format!("{}/AISecurityApp/models/model.onnx", app_data),
        "models/model.onnx".to_string(),
        "../assets/data/models/model.onnx".to_string(),
    ];

    for path in &model_paths {
        if std::path::Path::new(path).exists() {
            load_onnx_model(path)?;

            // Try to load metadata
            let metadata_path = format!("{}.json", path);
            if std::path::Path::new(&metadata_path).exists() {
                let _ = load_metadata(&metadata_path);
            }

            return Ok(());
        }
    }

    log::warn!("No ONNX model found. Using fallback heuristics.");
    Ok(())
}

/// Load metadata từ JSON file
pub fn load_metadata(metadata_path: &str) -> Result<(), super::model::inference::InferenceError> {
    use super::model::inference::InferenceError;

    let content = std::fs::read_to_string(metadata_path)
        .map_err(|e| InferenceError(format!("Failed to read metadata: {}", e)))?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| InferenceError(format!("Failed to parse metadata: {}", e)))?;

    // Extract normalization
    if let Some(norm) = json.get("normalization") {
        let min_vals: Vec<f32> = norm.get("min_vals")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_f64().map(|f| f as f32)).collect())
            .unwrap_or_else(|| vec![0.0; FEATURE_COUNT]);

        let max_vals: Vec<f32> = norm.get("max_vals")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_f64().map(|f| f as f32)).collect())
            .unwrap_or_else(|| vec![1.0; FEATURE_COUNT]);

        load_normalization(min_vals, max_vals);
    }

    log::info!("Model metadata loaded from: {}", metadata_path);
    Ok(())
}

/// Async prediction
pub async fn predict_async(sequence: Vec<[f32; FEATURE_COUNT]>) -> Result<PredictionResult, super::model::inference::InferenceError> {
    use super::model::inference::InferenceError;
    use crate::logic::config::SafetyConfig;

    if !SafetyConfig::is_ai_enabled() {
        return Err(InferenceError("AI Engine Disabled by Safety Config".to_string()));
    }

    tokio::task::spawn_blocking(move || {
        predict_onnx(&sequence)
    })
    .await
    .map_err(|e| InferenceError(format!("Task failed: {}", e)))?
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logic::model::inference::{predict_fallback, normalize_features};

    #[test]
    fn test_fallback_prediction() {
        let sequence = vec![
            [25.0, 40.0, 200.0, 300.0, 5.0, 5.0, 3.0, 3.0, 50.0, 0.5, 0.1, 0.1, 0.1, 5.0, 0.5],
            [30.0, 45.0, 250.0, 350.0, 6.0, 6.0, 4.0, 4.0, 55.0, 0.55, 0.12, 0.12, 0.12, 6.0, 0.6],
        ];

        let result = predict_fallback(&sequence);

        assert!(result.score >= 0.0 && result.score <= 1.0);
        assert!(result.inference_time_us < 1000); // Should be fast
        assert_eq!(result.method, "fallback");
    }

    #[test]
    fn test_normalization() {
        load_normalization(
            vec![0.0; FEATURE_COUNT],
            vec![100.0; FEATURE_COUNT],
        );

        let features = [50.0; FEATURE_COUNT];
        let normalized = normalize_features(&features);

        assert!((normalized[0] - 0.5).abs() < 0.01);
    }
}
