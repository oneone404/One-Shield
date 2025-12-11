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
//!
//! ### Process Intelligence (`process_intel/`) - Phase 2
//! - `signature.rs` - Authenticode signature verification
//! - `tree.rs` - Process tree analysis
//! - `spawn.rs` - LOLBin & suspicious spawn detection
//! - `reputation.rs` - Executable reputation database
//!
//! ### Behavioral Signatures (`behavioral_sigs/`) - Phase 3
//! - `beaconing.rs` - C2 beaconing detection
//! - `persistence.rs` - Registry persistence monitoring
//! - `never_learn.rs` - Never-learn blacklist
//! - `rules.rs` - Behavioral rules engine
//!
//! ### External Intelligence (`external_intel/`) - Phase 4
//! - `virustotal.rs` - VirusTotal API integration
//! - `threat_feed.rs` - Cloud threat feed sync
//! - `mitre.rs` - MITRE ATT&CK mapping

// Core modules
pub mod collector;
pub mod baseline;
pub mod dataset;
pub mod status;
pub mod guard;
pub mod ai_bridge;
pub mod action_guard;
pub mod events;

// Threat & Policy (EDR pipeline) - Modular
pub mod threat;
pub mod policy;

// Telemetry & Logging (NEW)
pub mod telemetry;
pub mod incident;
pub mod explain;
pub mod config;
pub mod analysis_loop;

// Feature extraction
pub mod features;

// AI/ML inference
pub mod model;

// Process Intelligence (Phase 2)
pub mod process_intel;

// Behavioral Signatures (Phase 3)
pub mod behavioral_sigs;

// External Intelligence (Phase 4)
pub mod external_intel;

// Response & Automation (Phase 5)
pub mod response;

// Enterprise Features (Phase 6)
pub mod enterprise;

// Advanced Detection (Phase 8)
pub mod advanced_detection;


