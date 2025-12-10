use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureContribution {
    pub name: String,
    pub delta: f32,
    pub weight: f32,
    pub importance: f32, // delta * weight
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainResult {
    pub contributions: Vec<FeatureContribution>,
}
