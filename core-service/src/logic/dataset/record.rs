use serde::{Deserialize, Serialize};
use crate::logic::threat::ThreatClass;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DatasetRecord {
    pub timestamp: u64,

    // ✅ Feature contract (P1.1)
    pub feature_version: u8,
    pub layout_hash: u32,
    pub features: Vec<f32>,

    // ✅ Context (Deviation vector)
    pub baseline_diff: Vec<f32>,

    // ✅ AI output
    pub score: f32,
    pub confidence: f32,

    // ✅ Final decision
    pub threat: ThreatClass,
}
