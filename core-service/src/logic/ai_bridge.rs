//! AI Bridge - Native ONNX Runtime Integration (Phase IV)
//!
//! Load và chạy ONNX model trực tiếp trong Rust.
//! Không cần Python runtime - prediction trong microseconds.

use ndarray::Array3;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use ort::session::{Session, builder::GraphOptimizationLevel};
use ort::value::Value;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Độ dài sequence mặc định (L)
pub const DEFAULT_SEQUENCE_LENGTH: usize = 5;

/// Số features trong mỗi Summary Vector
pub const FEATURE_COUNT: usize = 15;

/// Default anomaly threshold
pub const DEFAULT_THRESHOLD: f32 = 0.7;

// ============================================================================
// STATE
// ============================================================================

/// ONNX Session (loaded model)
static ONNX_SESSION: RwLock<Option<Session>> = RwLock::new(None);

/// Model metadata
static MODEL_METADATA: RwLock<Option<ModelMetadata>> = RwLock::new(None);

/// Normalization parameters
static NORMALIZATION: RwLock<Option<NormalizationParams>> = RwLock::new(None);

/// Sequence buffer cho recent vectors
static SEQUENCE_BUFFER: RwLock<Vec<[f32; FEATURE_COUNT]>> = RwLock::new(Vec::new());

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Model metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    pub model_path: String,
    pub model_type: String,       // "lstm" hoặc "gru"
    pub sequence_length: usize,
    pub features: usize,
    pub threshold: f32,
    pub loaded_at: chrono::DateTime<chrono::Utc>,
}

/// Normalization parameters từ training
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizationParams {
    pub min_vals: Vec<f32>,
    pub max_vals: Vec<f32>,
}

impl Default for NormalizationParams {
    fn default() -> Self {
        Self {
            min_vals: vec![0.0; FEATURE_COUNT],
            max_vals: vec![1.0; FEATURE_COUNT],
        }
    }
}

/// Prediction output
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PredictionResult {
    pub score: f32,              // 0.0 - 1.0
    pub is_anomaly: bool,
    pub confidence: f32,
    pub raw_mse: f32,           // Mean Squared Error
    pub threshold: f32,
    pub inference_time_us: u64,  // Microseconds
    pub method: String,          // "onnx" or "fallback"
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

#[derive(Debug)]
pub struct AIBridgeError(pub String);

impl std::fmt::Display for AIBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AIBridgeError: {}", self.0)
    }
}

impl std::error::Error for AIBridgeError {}

// ============================================================================
// MODEL LOADING
// ============================================================================

/// Load ONNX model từ file
pub fn load_onnx_model(model_path: &str) -> Result<(), AIBridgeError> {
    log::info!("Loading ONNX model from: {}", model_path);

    if !std::path::Path::new(model_path).exists() {
        return Err(AIBridgeError(format!("Model not found: {}", model_path)));
    }

    // Create ONNX Runtime session
    let session = Session::builder()
        .map_err(|e| AIBridgeError(format!("Failed to create session builder: {}", e)))?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|e| AIBridgeError(format!("Failed to set optimization: {}", e)))?
        .commit_from_file(model_path)
        .map_err(|e| AIBridgeError(format!("Failed to load model: {}", e)))?;

    log::info!("ONNX model loaded successfully");

    // Store session
    *ONNX_SESSION.write() = Some(session);

    // Set default metadata
    let metadata = ModelMetadata {
        model_path: model_path.to_string(),
        model_type: "lstm".to_string(),
        sequence_length: DEFAULT_SEQUENCE_LENGTH,
        features: FEATURE_COUNT,
        threshold: DEFAULT_THRESHOLD,
        loaded_at: chrono::Utc::now(),
    };
    *MODEL_METADATA.write() = Some(metadata);

    Ok(())
}

/// Load ONNX model từ bytes (decrypted from RAM)
pub fn load_onnx_from_bytes(model_bytes: &[u8]) -> Result<(), AIBridgeError> {
    log::info!("Loading ONNX model from memory ({} bytes)", model_bytes.len());

    let session = Session::builder()
        .map_err(|e| AIBridgeError(format!("Failed to create session builder: {}", e)))?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|e| AIBridgeError(format!("Failed to set optimization: {}", e)))?
        .commit_from_memory(model_bytes)
        .map_err(|e| AIBridgeError(format!("Failed to load model from memory: {}", e)))?;

    log::info!("ONNX model loaded from memory successfully");

    *ONNX_SESSION.write() = Some(session);

    let metadata = ModelMetadata {
        model_path: "<memory>".to_string(),
        model_type: "lstm".to_string(),
        sequence_length: DEFAULT_SEQUENCE_LENGTH,
        features: FEATURE_COUNT,
        threshold: DEFAULT_THRESHOLD,
        loaded_at: chrono::Utc::now(),
    };
    *MODEL_METADATA.write() = Some(metadata);

    Ok(())
}

/// Load metadata từ JSON file
pub fn load_metadata(metadata_path: &str) -> Result<(), AIBridgeError> {
    let content = std::fs::read_to_string(metadata_path)
        .map_err(|e| AIBridgeError(format!("Failed to read metadata: {}", e)))?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| AIBridgeError(format!("Failed to parse metadata: {}", e)))?;

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

        *NORMALIZATION.write() = Some(NormalizationParams { min_vals, max_vals });
    }

    // Update metadata
    if let Some(metadata) = MODEL_METADATA.write().as_mut() {
        if let Some(threshold) = json.get("threshold").and_then(|v| v.as_f64()) {
            metadata.threshold = threshold as f32;
        }
        if let Some(seq_len) = json.get("config")
            .and_then(|c| c.get("sequence_length"))
            .and_then(|v| v.as_u64()) {
            metadata.sequence_length = seq_len as usize;
        }
    }

    log::info!("Model metadata loaded from: {}", metadata_path);
    Ok(())
}

/// Check if model is loaded
pub fn is_model_loaded() -> bool {
    ONNX_SESSION.read().is_some()
}

/// Unload model
pub fn unload_model() {
    *ONNX_SESSION.write() = None;
    *MODEL_METADATA.write() = None;
    log::info!("ONNX model unloaded");
}

/// Get model metadata
pub fn get_metadata() -> Option<ModelMetadata> {
    MODEL_METADATA.read().clone()
}

// ============================================================================
// NORMALIZATION
// ============================================================================

/// Normalize features với min/max từ training
fn normalize_features(features: &[f32; FEATURE_COUNT]) -> [f32; FEATURE_COUNT] {
    let norm = NORMALIZATION.read();
    let default_params = NormalizationParams::default();
    let params = norm.as_ref().unwrap_or(&default_params);

    let mut normalized = [0.0f32; FEATURE_COUNT];

    for i in 0..FEATURE_COUNT {
        let min_val = params.min_vals.get(i).copied().unwrap_or(0.0);
        let max_val = params.max_vals.get(i).copied().unwrap_or(1.0);
        let range = (max_val - min_val).max(1e-8);

        normalized[i] = ((features[i] - min_val) / range).clamp(0.0, 1.0);
    }

    normalized
}

/// Normalize a sequence
fn normalize_sequence(sequence: &[[f32; FEATURE_COUNT]]) -> Vec<[f32; FEATURE_COUNT]> {
    sequence.iter().map(normalize_features).collect()
}

// ============================================================================
// SEQUENCE BUFFER
// ============================================================================

/// Push vector vào buffer
pub fn push_to_buffer(features: [f32; FEATURE_COUNT]) {
    let metadata = MODEL_METADATA.read();
    let max_len = metadata.as_ref()
        .map(|m| m.sequence_length * 2)
        .unwrap_or(DEFAULT_SEQUENCE_LENGTH * 2);

    let mut buffer = SEQUENCE_BUFFER.write();
    buffer.push(features);

    while buffer.len() > max_len {
        buffer.remove(0);
    }
}

/// Get recent sequence từ buffer
pub fn get_sequence_from_buffer() -> Option<Vec<[f32; FEATURE_COUNT]>> {
    let metadata = MODEL_METADATA.read();
    let seq_len = metadata.as_ref()
        .map(|m| m.sequence_length)
        .unwrap_or(DEFAULT_SEQUENCE_LENGTH);

    let buffer = SEQUENCE_BUFFER.read();

    if buffer.len() < seq_len {
        return None;
    }

    let start = buffer.len() - seq_len;
    Some(buffer[start..].to_vec())
}

/// Check if buffer has enough data
pub fn has_enough_data() -> bool {
    let metadata = MODEL_METADATA.read();
    let seq_len = metadata.as_ref()
        .map(|m| m.sequence_length)
        .unwrap_or(DEFAULT_SEQUENCE_LENGTH);

    SEQUENCE_BUFFER.read().len() >= seq_len
}

/// Clear buffer
pub fn clear_buffer() {
    SEQUENCE_BUFFER.write().clear();
}

// ============================================================================
// PREDICTION - ONNX NATIVE
// ============================================================================

/// Run ONNX inference on sequence
pub fn predict_onnx(sequence: &[[f32; FEATURE_COUNT]]) -> Result<PredictionResult, AIBridgeError> {
    let start_time = std::time::Instant::now();

    // Get session (write lock for mutable run)
    let mut session_guard = ONNX_SESSION.write();
    let session = session_guard.as_mut()
        .ok_or_else(|| AIBridgeError("Model not loaded".to_string()))?;

    // Get metadata
    let metadata = MODEL_METADATA.read();
    let threshold = metadata.as_ref()
        .map(|m| m.threshold)
        .unwrap_or(DEFAULT_THRESHOLD);
    let expected_len = metadata.as_ref()
        .map(|m| m.sequence_length)
        .unwrap_or(DEFAULT_SEQUENCE_LENGTH);
    drop(metadata);

    // Normalize sequence
    let normalized = normalize_sequence(sequence);

    // Prepare sequence (pad/truncate if needed)
    let prepared: Vec<[f32; FEATURE_COUNT]> = if normalized.len() < expected_len {
        let mut padded = normalized.clone();
        while padded.len() < expected_len {
            padded.push(padded.last().cloned().unwrap_or([0.0; FEATURE_COUNT]));
        }
        padded
    } else {
        normalized[normalized.len() - expected_len..].to_vec()
    };

    // Create input tensor: shape (1, seq_len, features)
    let seq_len = prepared.len();
    let mut input_data = Vec::with_capacity(seq_len * FEATURE_COUNT);
    for vec in &prepared {
        input_data.extend_from_slice(vec);
    }

    // Create ndarray and then tensor
    let input_array = Array3::<f32>::from_shape_vec(
        (1, seq_len, FEATURE_COUNT),
        input_data,
    ).map_err(|e| AIBridgeError(format!("Failed to create array: {}", e)))?;

    // Get output name BEFORE run to avoid borrow conflict
    let output_name = session.outputs.first()
        .map(|o| o.name.clone())
        .ok_or_else(|| AIBridgeError("No output defined".to_string()))?;

    // Run inference
    let input_tensor = Value::from_array(input_array)
        .map_err(|e| AIBridgeError(format!("Failed to create tensor: {}", e)))?;

    let outputs = session.run(ort::inputs![input_tensor])
        .map_err(|e| AIBridgeError(format!("Inference failed: {}", e)))?;

    let output = outputs.get(&output_name)
        .ok_or_else(|| AIBridgeError("No output from model".to_string()))?;

    // Extract output values using new API
    let output_tensor = output.try_extract_tensor::<f32>()
        .map_err(|e| AIBridgeError(format!("Failed to extract output: {}", e)))?;

    let data = output_tensor.1; // (shape, data) tuple

    // Calculate MSE (reconstruction error)
    let mut mse = 0.0f32;
    let mut count = 0;

    // shape is (1, seq_len, features)
    for i in 0..seq_len {
        for j in 0..FEATURE_COUNT {
            let idx = i * FEATURE_COUNT + j;
            if idx < data.len() {
                let original = prepared[i][j];
                let reconstructed = data[idx];
                mse += (original - reconstructed).powi(2);
                count += 1;
            }
        }
    }
    if count > 0 {
        mse /= count as f32;
    }

    let inference_time = start_time.elapsed().as_micros() as u64;

    // Calculate score (0-1)
    let score = (mse / (threshold * 2.0)).min(1.0);

    // Confidence
    let distance = (mse - threshold).abs() / threshold;
    let confidence = (0.5 + distance * 0.5).min(1.0);

    Ok(PredictionResult {
        score,
        is_anomaly: mse > threshold,
        confidence,
        raw_mse: mse,
        threshold,
        inference_time_us: inference_time,
        method: "onnx".to_string(),
    })
}

/// Predict from buffer (auto)
pub fn predict_from_buffer() -> Result<PredictionResult, AIBridgeError> {
    let sequence = get_sequence_from_buffer()
        .ok_or_else(|| AIBridgeError("Not enough data in buffer".to_string()))?;

    predict_onnx(&sequence)
}

// ============================================================================
// FALLBACK PREDICTION (Heuristic - no model)
// ============================================================================

/// Fallback heuristic prediction
pub fn predict_fallback(sequence: &[[f32; FEATURE_COUNT]]) -> PredictionResult {
    let start_time = std::time::Instant::now();

    if sequence.is_empty() {
        return PredictionResult::default();
    }

    // Feature thresholds
    let thresholds: [f32; FEATURE_COUNT] = [
        50.0, 80.0, 500.0, 1000.0,  // CPU, Memory
        15.0, 15.0, 10.0, 10.0,     // Network, Disk
        100.0, 0.9,                  // Processes, Network ratio
        0.2, 0.2, 0.3, 10.0, 1.0,   // Feature crosses
    ];

    let last = &sequence[sequence.len() - 1];
    let mut anomaly_count = 0;
    let mut max_dev = 0.0f32;

    for (i, &val) in last.iter().enumerate() {
        if val > thresholds[i] {
            anomaly_count += 1;
            max_dev = max_dev.max((val - thresholds[i]) / thresholds[i]);
        }
    }

    // Check trends
    if sequence.len() > 1 {
        let first = &sequence[0];
        let increasing = last.iter().zip(first.iter())
            .filter(|(l, f)| *l > *f)
            .count();

        if increasing > FEATURE_COUNT * 7 / 10 {
            anomaly_count += 2;
        }
    }

    let score = ((anomaly_count as f32 / 10.0) + max_dev * 0.3).min(1.0);
    let inference_time = start_time.elapsed().as_micros() as u64;

    PredictionResult {
        score,
        is_anomaly: score > 0.6,
        confidence: if anomaly_count >= 3 { 0.7 } else { 0.5 },
        raw_mse: 0.0,
        threshold: 0.6,
        inference_time_us: inference_time,
        method: "fallback".to_string(),
    }
}

// ============================================================================
// HIGH-LEVEL API
// ============================================================================

/// Auto predict: uses ONNX if loaded, fallback otherwise
pub fn predict(sequence: &[[f32; FEATURE_COUNT]]) -> PredictionResult {
    match predict_onnx(sequence) {
        Ok(result) => result,
        Err(e) => {
            log::debug!("ONNX prediction failed ({}), using fallback", e);
            predict_fallback(sequence)
        }
    }
}

/// Push and predict: add to buffer, predict if ready
pub fn push_and_predict(features: [f32; FEATURE_COUNT]) -> Option<PredictionResult> {
    push_to_buffer(features);

    if has_enough_data() {
        Some(predict(&get_sequence_from_buffer().unwrap()))
    } else {
        None
    }
}

/// Async prediction
pub async fn predict_async(sequence: Vec<[f32; FEATURE_COUNT]>) -> Result<PredictionResult, AIBridgeError> {
    tokio::task::spawn_blocking(move || {
        predict_onnx(&sequence)
    })
    .await
    .map_err(|e| AIBridgeError(format!("Task failed: {}", e)))?
}

// ============================================================================
// INITIALIZATION
// ============================================================================

/// Initialize AI Bridge với default paths
pub fn init() -> Result<(), AIBridgeError> {
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

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        *NORMALIZATION.write() = Some(NormalizationParams {
            min_vals: vec![0.0; FEATURE_COUNT],
            max_vals: vec![100.0; FEATURE_COUNT],
        });

        let features = [50.0; FEATURE_COUNT];
        let normalized = normalize_features(&features);

        assert!((normalized[0] - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_buffer() {
        clear_buffer();

        // Set metadata for sequence length
        *MODEL_METADATA.write() = Some(ModelMetadata {
            model_path: "test".to_string(),
            model_type: "lstm".to_string(),
            sequence_length: 3,
            features: FEATURE_COUNT,
            threshold: 0.7,
            loaded_at: chrono::Utc::now(),
        });

        assert!(!has_enough_data());

        push_to_buffer([1.0; FEATURE_COUNT]);
        push_to_buffer([2.0; FEATURE_COUNT]);
        assert!(!has_enough_data());

        push_to_buffer([3.0; FEATURE_COUNT]);
        assert!(has_enough_data());

        let seq = get_sequence_from_buffer().unwrap();
        assert_eq!(seq.len(), 3);
    }
}
