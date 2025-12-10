//! Logic Module - Business Logic & Engines
//!
//! Chứa các engines xử lý: Collector, Baseline, Guard, AI Bridge, Action Guard.
//!
//! ## New Architecture (v0.5.0)
//! - `features/` - Feature extraction (CPU, Memory, Network, Disk, Process)
//! - `model/` - AI/ML inference (ONNX, threshold, buffer)

// Core modules
pub mod collector;
pub mod baseline;
pub mod guard;
pub mod ai_bridge;
pub mod action_guard;
pub mod events;

// New modular architecture
pub mod features;
pub mod model;

