//! Features Module - Feature Extraction Engine
//!
//! Tách logic trích xuất features từ raw metrics.
//! Dễ dàng mở rộng, thêm/sửa features mà không ảnh hưởng collector.

pub mod cpu;
pub mod memory;
pub mod network;
pub mod disk;
pub mod process;
pub mod vector;
pub mod gpu;

#[cfg(test)]
mod tests;

// Re-export common types
pub use vector::{FeatureVector, FEATURE_COUNT, FeatureExtractor};
pub use gpu::{GpuFeatures, GpuInfo};
