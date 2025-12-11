//! Advanced Detection Module - Enhanced Threat Detection (Phase 8)
//!
//! Mục đích: Nâng cao khả năng phát hiện với heuristic patterns và memory scanning
//!
//! # Components
//! - `amsi.rs`: Script scanning (PowerShell, VBScript, JavaScript)
//! - `injection.rs`: DLL injection detection
//! - `memory.rs`: Shellcode pattern scanning
//! - `types.rs`: Shared types for AMSI detection
//! - `injection_types.rs`: Types for injection detection
//! - `memory_types.rs`: Types for memory scanning
//!
//! # Future
//! - `etw.rs`: Event Tracing for Windows

// Allow unused for now - incrementally integrated
#![allow(unused)]

pub mod amsi;
pub mod types;
pub mod injection;
pub mod injection_types;
pub mod memory;
pub mod memory_types;

// Re-exports - AMSI
pub use amsi::{init as init_amsi, scan, scan_file, is_malicious, is_available as amsi_available, get_stats as amsi_stats};
pub use types::{ScanResult, ThreatLevel, AmsiError, AmsiStats};

// Re-exports - Injection
pub use injection::{init as init_injection, analyze_process, is_suspicious, get_recent_alerts, get_stats as injection_stats};
pub use injection_types::{InjectionType, InjectionAlert, InjectionStats, InjectionError};

// Re-exports - Memory
pub use memory::{init as init_memory, scan_buffer, scan_file as scan_file_memory, contains_shellcode, contains_critical_shellcode, get_stats as memory_stats};
pub use memory_types::{ShellcodeType, MemoryScanResult, MemoryScanStats, MemoryScanError};

/// Initialize all advanced detection modules
pub fn init() {
    if let Err(e) = amsi::init() {
        log::warn!("AMSI init failed: {}", e);
    }
    injection::init();
    memory::init();
    log::info!("Advanced Detection fully initialized (AMSI + Injection + Memory)");
}
