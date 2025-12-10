//! Inference Engine - ONNX Runtime Integration
//!
//! Load và chạy ONNX model.
//! Tách riêng khỏi ai_bridge để dễ swap model.

use std::sync::atomic::{AtomicU64, Ordering};
use ndarray::Array3;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use ort::session::{Session, builder::GraphOptimizationLevel};
use ort::value::Value;

use crate::logic::features::FEATURE_COUNT;
use super::threshold::ThresholdConfig;

// ...

// ============================================================================
// STATE
// ============================================================================

/// Latency stats
static LATENCY_SUM: AtomicU64 = AtomicU64::new(0);
static INFERENCE_COUNT: AtomicU64 = AtomicU64::new(0);

/// ONNX Session (loaded model)
static ONNX_SESSION: RwLock<Option<Session>> = RwLock::new(None);
// ...

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/// Engine Status for UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub model_loaded: bool,
    pub model_name: String,
    pub inference_device: String,
    pub avg_latency_ms: f32,
    pub inference_count: u64,
}

// ...

// ============================================================================
// HELPERS
// ============================================================================

pub fn get_status() -> EngineStatus {
    let metadata = MODEL_METADATA.read();
    let (loaded, name) = if let Some(meta) = metadata.as_ref() {
        (true, meta.model_path.clone())
    } else {
        (false, "None".to_string())
    };

    let sum = LATENCY_SUM.load(Ordering::Relaxed);
    let count = INFERENCE_COUNT.load(Ordering::Relaxed);
    let avg = if count > 0 { (sum as f32 / count as f32) / 1000.0 } else { 0.0 };

    EngineStatus {
        model_loaded: loaded,
        model_name: name,
        inference_device: "ONNX Runtime (CPU)".to_string(),
        avg_latency_ms: avg,
        inference_count: count,
    }
}

// ...

/// Auto predict: ONNX if loaded, fallback otherwise
pub fn predict(sequence: &[[f32; FEATURE_COUNT]]) -> PredictionResult {
    let result = match predict_onnx(sequence) {
        Ok(result) => result,
        Err(e) => {
            log::debug!("ONNX failed ({}), using fallback", e);
            predict_fallback(sequence)
        }
    };

    // Track metrics
    LATENCY_SUM.fetch_add(result.inference_time_us, Ordering::Relaxed);
    INFERENCE_COUNT.fetch_add(1, Ordering::Relaxed);

    result
}

/// Model metadata
static MODEL_METADATA: RwLock<Option<ModelMetadata>> = RwLock::new(None);

/// Normalization parameters
static NORMALIZATION: RwLock<Option<NormalizationParams>> = RwLock::new(None);

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

/// Default sequence length
pub const DEFAULT_SEQUENCE_LENGTH: usize = 5;

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
pub struct InferenceError(pub String);

impl std::fmt::Display for InferenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InferenceError: {}", self.0)
    }
}

impl std::error::Error for InferenceError {}

// ============================================================================
// INFERENCE ENGINE TRAIT
// ============================================================================

/// Trait cho inference engines (ONNX, TensorRT, etc.)
pub trait InferenceEngine {
    fn load(&mut self, path: &str) -> Result<(), InferenceError>;
    fn predict(&self, sequence: &[[f32; FEATURE_COUNT]]) -> Result<PredictionResult, InferenceError>;
    fn is_loaded(&self) -> bool;
    fn unload(&mut self);
}

// ============================================================================
// ONNX IMPLEMENTATION
// ============================================================================

/// Load ONNX model từ file
pub fn load_onnx_model(model_path: &str) -> Result<(), InferenceError> {
    log::info!("Loading ONNX model from: {}", model_path);

    if !std::path::Path::new(model_path).exists() {
        return Err(InferenceError(format!("Model not found: {}", model_path)));
    }

    let session = Session::builder()
        .map_err(|e| InferenceError(format!("Failed to create session builder: {}", e)))?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|e| InferenceError(format!("Failed to set optimization: {}", e)))?
        .commit_from_file(model_path)
        .map_err(|e| InferenceError(format!("Failed to load model: {}", e)))?;

    log::info!("ONNX model loaded successfully");

    *ONNX_SESSION.write() = Some(session);

    let metadata = ModelMetadata {
        model_path: model_path.to_string(),
        model_type: "lstm".to_string(),
        sequence_length: DEFAULT_SEQUENCE_LENGTH,
        features: FEATURE_COUNT,
        threshold: ThresholdConfig::default().base_threshold,
        loaded_at: chrono::Utc::now(),
    };
    *MODEL_METADATA.write() = Some(metadata);

    Ok(())
}

/// Load ONNX model từ bytes
pub fn load_onnx_from_bytes(model_bytes: &[u8]) -> Result<(), InferenceError> {
    log::info!("Loading ONNX model from memory ({} bytes)", model_bytes.len());

    let session = Session::builder()
        .map_err(|e| InferenceError(format!("Session builder error: {}", e)))?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|e| InferenceError(format!("Optimization error: {}", e)))?
        .commit_from_memory(model_bytes)
        .map_err(|e| InferenceError(format!("Load from memory error: {}", e)))?;

    *ONNX_SESSION.write() = Some(session);

    let metadata = ModelMetadata {
        model_path: "<memory>".to_string(),
        model_type: "lstm".to_string(),
        sequence_length: DEFAULT_SEQUENCE_LENGTH,
        features: FEATURE_COUNT,
        threshold: ThresholdConfig::default().base_threshold,
        loaded_at: chrono::Utc::now(),
    };
    *MODEL_METADATA.write() = Some(metadata);

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

/// Get sequence length
pub fn get_sequence_length() -> usize {
    MODEL_METADATA.read()
        .as_ref()
        .map(|m| m.sequence_length)
        .unwrap_or(DEFAULT_SEQUENCE_LENGTH)
}

// ============================================================================
// NORMALIZATION
// ============================================================================

/// Load normalization parameters
pub fn load_normalization(min_vals: Vec<f32>, max_vals: Vec<f32>) {
    *NORMALIZATION.write() = Some(NormalizationParams { min_vals, max_vals });
}

/// Normalize features
pub fn normalize_features(features: &[f32; FEATURE_COUNT]) -> [f32; FEATURE_COUNT] {
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
pub fn normalize_sequence(sequence: &[[f32; FEATURE_COUNT]]) -> Vec<[f32; FEATURE_COUNT]> {
    sequence.iter().map(normalize_features).collect()
}

// ============================================================================
// PREDICTION
// ============================================================================

/// Run ONNX inference on sequence
pub fn predict_onnx(sequence: &[[f32; FEATURE_COUNT]]) -> Result<PredictionResult, InferenceError> {
    let start_time = std::time::Instant::now();

    let mut session_guard = ONNX_SESSION.write();
    let session = session_guard.as_mut()
        .ok_or_else(|| InferenceError("Model not loaded".to_string()))?;

    let metadata = MODEL_METADATA.read();
    let threshold = metadata.as_ref()
        .map(|m| m.threshold)
        .unwrap_or(ThresholdConfig::default().base_threshold);
    let expected_len = metadata.as_ref()
        .map(|m| m.sequence_length)
        .unwrap_or(DEFAULT_SEQUENCE_LENGTH);
    drop(metadata);

    // Normalize
    let normalized = normalize_sequence(sequence);

    // Prepare sequence (pad/truncate)
    let prepared: Vec<[f32; FEATURE_COUNT]> = if normalized.len() < expected_len {
        let mut padded = normalized.clone();
        while padded.len() < expected_len {
            padded.push(padded.last().cloned().unwrap_or([0.0; FEATURE_COUNT]));
        }
        padded
    } else {
        normalized[normalized.len() - expected_len..].to_vec()
    };

    // Create input tensor
    let seq_len = prepared.len();
    let mut input_data = Vec::with_capacity(seq_len * FEATURE_COUNT);
    for vec in &prepared {
        input_data.extend_from_slice(vec);
    }

    let input_array = Array3::<f32>::from_shape_vec(
        (1, seq_len, FEATURE_COUNT),
        input_data,
    ).map_err(|e| InferenceError(format!("Array error: {}", e)))?;

    let output_name = session.outputs.first()
        .map(|o| o.name.clone())
        .ok_or_else(|| InferenceError("No output defined".to_string()))?;

    let input_tensor = Value::from_array(input_array)
        .map_err(|e| InferenceError(format!("Tensor error: {}", e)))?;

    let outputs = session.run(ort::inputs![input_tensor])
        .map_err(|e| InferenceError(format!("Inference failed: {}", e)))?;

    let output = outputs.get(&output_name)
        .ok_or_else(|| InferenceError("No output".to_string()))?;

    let output_tensor = output.try_extract_tensor::<f32>()
        .map_err(|e| InferenceError(format!("Extract error: {}", e)))?;

    let data = output_tensor.1;

    // Calculate MSE
    let mut mse = 0.0f32;
    let mut count = 0;

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

    let score = (mse / (threshold * 2.0)).min(1.0);
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

/// Fallback heuristic prediction (no model)
pub fn predict_fallback(sequence: &[[f32; FEATURE_COUNT]]) -> PredictionResult {
    let start_time = std::time::Instant::now();

    if sequence.is_empty() {
        return PredictionResult::default();
    }

    let thresholds: [f32; FEATURE_COUNT] = [
        50.0, 80.0, 500.0, 1000.0,
        15.0, 15.0, 10.0, 10.0,
        100.0, 0.9,
        0.2, 0.2, 0.3, 10.0, 1.0,
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


