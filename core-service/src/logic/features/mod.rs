//! Features Module - Feature Extraction Engine
//!
//! Tách logic trích xuất features từ raw metrics.
//! Dễ dàng mở rộng, thêm/sửa features mà không ảnh hưởng collector.
//!
//! ## Feature Versioning (P1.1)
//! - `layout.rs` - Centralized feature schema (authoritative)
//! - `vector.rs` - Versioned FeatureVector with validation

// Allow unused - some exports for future use
#![allow(unused)]

// Feature layout (MUST be first - others depend on it)
pub mod layout;

// Individual feature extractors
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
pub use layout::{
    FEATURE_VERSION, FEATURE_COUNT, FEATURE_LAYOUT,
    layout_hash, compute_layout_hash,
    validate_layout, is_layout_compatible,
    LayoutInfo, LayoutMismatchError,
    feature_index, feature_name,
};
pub use vector::{FeatureVector, FeatureExtractor, FeatureVectorBuilder};
pub use gpu::{GpuFeatures, GpuInfo};

