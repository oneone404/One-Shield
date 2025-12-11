//! Telemetry Module
//!
//! Security event logging, recording, and analytics.
//! This is the **backbone of EDR** - without logs, you can't:
//! - Trace why decisions were made
//! - Improve the AI model
//! - Audit security events
//!
//! ## Structure
//! - `event.rs` - SecurityEvent struct (immutable, timestamped)
//! - `recorder.rs` - Append-only JSONL writer (thread-safe)
//! - `exporter.rs` - Export to formats (CSV, JSON) + training data
//!
//! ## Usage
//! ```ignore
//! use crate::logic::telemetry::{self, SecurityEvent, ProcessInfo};
//!
//! // Initialize at app start
//! telemetry::init(None)?;
//!
//! // Record events throughout the app
//! telemetry::record(SecurityEvent::threat_detected(...));
//!
//! // Shutdown at app exit
//! telemetry::shutdown();
//! ```

// Allow unused - some exports for future use
#![allow(unused)]

pub mod event;
pub mod recorder;
pub mod exporter;

// Re-export main types and functions
pub use event::{
    SecurityEvent,
    EventType,
    ProcessInfo,
    AiContext,
    UserOverride,
    get_session_id,
};

pub use recorder::{
    init,
    record,
    shutdown,
    events_recorded,
    current_log_file,
    stats,
    RecorderStats,
    read_events,
    find_overrides,
    list_log_files,
};

pub use exporter::{
    ExportFormat,
    export_file,
    export_events,
    export_training_data,
    generate_analytics,
    AnalyticsSummary,
    TrainingRecord,
};
