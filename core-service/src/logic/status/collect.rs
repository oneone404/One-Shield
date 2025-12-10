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

    let m_status = ModelStatus {
        engine: if ai_bridge::is_model_loaded() { "ONNX".to_string() } else { "Heuristic Fallback".to_string() },
        model_version: None, // TODO: Extract from metadata if available
        loaded: ai_bridge::is_model_loaded(),
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
