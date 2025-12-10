use crate::api::engine_status::{EngineStatus, BaselineStatus, ModelStatus};
use crate::logic::{baseline, dataset, features, ai_bridge};

pub fn collect() -> EngineStatus {
    let feature_version = features::layout::FEATURE_VERSION;
    let layout_hash = features::layout::layout_hash();
    let feature_count = features::layout::FEATURE_COUNT;

    let b_status = if let Some(b) = baseline::get_versioned_baseline() {
        BaselineStatus {
            samples: b.samples,
            mode: if b.samples < 50 { "Learning".to_string() } else { "Stable".to_string() },
            last_reset_reason: None,
        }
    } else {
        BaselineStatus {
            samples: 0,
            mode: "Uninitialized".to_string(),
            last_reset_reason: None,
        }
    };

    let d_status = dataset::get_status();

    let (model_version, trained_on_records) = get_model_meta();

    let m_status = ModelStatus {
        engine: if ai_bridge::is_model_loaded() { "ONNX".to_string() } else { "Heuristic Fallback".to_string() },
        model_version,
        loaded: ai_bridge::is_model_loaded(),
        trained_on_records,
    };

    EngineStatus {
        feature_version,
        layout_hash,
        feature_count,
        baseline: b_status,
        dataset: d_status,
        model: m_status,
    }
}

fn get_model_meta() -> (Option<String>, Option<u64>) {
    // Try to find metadata sidecar in standard location
    let meta_path = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ai-security")
        .join("core.meta");

    if let Ok(content) = std::fs::read_to_string(meta_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            let v = json.get("version").and_then(|s| s.as_str()).map(|s| s.to_string());
            let r = json.get("records").and_then(|n| n.as_u64());
            return (v, r);
        }
    }
    (None, None)
}
