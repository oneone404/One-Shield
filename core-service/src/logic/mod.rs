//! Logic Module - Business Logic & Engines
//!
//! Complete EDR-style pipeline:
//! - Collector → Feature → Baseline → AI → Threat → Policy → Action
//!
//! ## Architecture (v0.6.0) - Modular Design
//!
//! ### Threat Classification (`threat/`)
//! - `types.rs` - Core types (ThreatClass, AnomalyScore, BaselineDiff)
//! - `context.rs` - Context information for classification
//! - `rules.rs` - Thresholds and constants
//! - `classifier.rs` - Classification logic with Confidence Guard
//!
//! ### Policy Decision (`policy/`)
//! - `types.rs` - Decision types (Decision, Severity, ActionType)
//! - `config.rs` - Policy configuration
//! - `engine.rs` - Decision engine
//! - `rules.rs` - Extensible policy rules

// Core modules
pub mod collector;
pub mod baseline;
pub mod guard;
pub mod ai_bridge;
pub mod action_guard;
pub mod events;

// Threat & Policy (EDR pipeline) - Modular
pub mod threat;
pub mod policy;

// Feature extraction
pub mod features;

// AI/ML inference
pub mod model;
