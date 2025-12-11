//! Model Module - AI/ML Inference Engine
//!
//! Tách logic inference khỏi data collection.
//! Dễ dàng swap model, multi-model, ensemble.

// Allow unused - some exports for future use
#![allow(unused)]

pub mod inference;
pub mod threshold;
pub mod buffer;

// Re-export common types
pub use inference::{InferenceEngine, PredictionResult};
pub use threshold::{ThresholdConfig, DynamicThreshold};
pub use buffer::BufferStatus;

