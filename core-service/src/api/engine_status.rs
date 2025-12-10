use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub feature_version: u8,
    pub layout_hash: u32,
    pub feature_count: usize,

    pub baseline: BaselineStatus,
    pub dataset: DatasetStatus,
    pub model: ModelStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStatus {
    pub samples: u64,
    pub mode: String, // Learning, Stable, Safe
    pub last_reset_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetStatus {
    pub current_file: String,
    pub total_files: usize,
    pub total_size_mb: f32,
    pub total_records: u64,
    pub benign_count: u64,
    pub suspicious_count: u64,
    pub malicious_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelStatus {
    pub engine: String, // "onnx" | "heuristic"
    pub model_version: Option<String>,
    pub loaded: bool,
    pub trained_on_records: Option<u64>,
}
