//! Logic Module - Business Logic & Engines
//!
//! Complete EDR-style pipeline:
//! - Collector → Feature → Baseline → AI → Threat → Policy → Action
//!
//! ## Architecture (v0.6.1) - Modular Design
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
//!
//! ### Telemetry (`telemetry/`) - NEW
//! - `event.rs` - SecurityEvent struct (audit trail)
//! - `recorder.rs` - Append-only JSONL writer
//! - `exporter.rs` - Export & analytics

// Core modules
pub mod collector;
pub mod baseline;
pub mod dataset;
pub mod guard;
pub mod ai_bridge;
pub mod action_guard;
pub mod events;

// Threat & Policy (EDR pipeline) - Modular
pub mod threat;
pub mod policy;

// Telemetry & Logging (NEW)
pub mod telemetry;

// Feature extraction
pub mod features;

// AI/ML inference
pub mod model;

