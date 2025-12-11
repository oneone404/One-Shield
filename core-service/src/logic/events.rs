#![allow(dead_code)]

//! Event Emitter - Global Tauri Event System
//!
//! Cho phép emit events từ bất kỳ đâu trong codebase.

use parking_lot::RwLock;
use tauri::{AppHandle, Emitter};
use serde::Serialize;

/// Global AppHandle reference
static APP_HANDLE: RwLock<Option<AppHandle>> = RwLock::new(None);

/// Event names
pub mod events {
    pub const PENDING_ACTION: &str = "action-guard:pending";
    pub const ACTION_EXECUTED: &str = "action-guard:executed";
    pub const ANOMALY_DETECTED: &str = "anomaly:detected";
    pub const SYSTEM_STATUS: &str = "system:status";

    // Phase 8: Advanced Detection Events
    pub const INJECTION_DETECTED: &str = "advanced:injection";
    pub const MEMORY_ALERT: &str = "advanced:memory";
    pub const SCRIPT_BLOCKED: &str = "advanced:script";
    pub const THREAT_ALERT: &str = "advanced:threat";
}

/// Initialize event system with AppHandle
pub fn init(app_handle: AppHandle) {
    let mut handle = APP_HANDLE.write();
    *handle = Some(app_handle);
    log::info!("Event emitter initialized");
}

/// Check if event system is initialized
pub fn is_initialized() -> bool {
    APP_HANDLE.read().is_some()
}

/// Emit event to all listeners
pub fn emit<S: Serialize + Clone>(event: &str, payload: S) -> Result<(), String> {
    let handle = APP_HANDLE.read();
    if let Some(app) = handle.as_ref() {
        app.emit(event, payload)
            .map_err(|e| format!("Emit error: {}", e))
    } else {
        log::warn!("Event system not initialized, event '{}' dropped", event);
        Ok(()) // Silent fail - don't crash if not initialized
    }
}

/// Emit pending action event
pub fn emit_pending_action<S: Serialize + Clone>(payload: S) {
    if let Err(e) = emit(events::PENDING_ACTION, payload) {
        log::error!("Failed to emit pending action: {}", e);
    }
}

/// Emit action executed event
pub fn emit_action_executed<S: Serialize + Clone>(payload: S) {
    if let Err(e) = emit(events::ACTION_EXECUTED, payload) {
        log::error!("Failed to emit action executed: {}", e);
    }
}

/// Emit anomaly detected event
pub fn emit_anomaly_detected<S: Serialize + Clone>(payload: S) {
    if let Err(e) = emit(events::ANOMALY_DETECTED, payload) {
        log::error!("Failed to emit anomaly: {}", e);
    }
}

// ============================================================================
// PHASE 8: ADVANCED DETECTION EVENTS
// ============================================================================

/// Emit injection detection event
pub fn emit_injection_detected<S: Serialize + Clone>(payload: S) {
    if let Err(e) = emit(events::INJECTION_DETECTED, payload) {
        log::error!("Failed to emit injection alert: {}", e);
    }
}

/// Emit memory scan alert event
pub fn emit_memory_alert<S: Serialize + Clone>(payload: S) {
    if let Err(e) = emit(events::MEMORY_ALERT, payload) {
        log::error!("Failed to emit memory alert: {}", e);
    }
}

/// Emit script blocked event
pub fn emit_script_blocked<S: Serialize + Clone>(payload: S) {
    if let Err(e) = emit(events::SCRIPT_BLOCKED, payload) {
        log::error!("Failed to emit script blocked: {}", e);
    }
}

/// Emit unified threat alert event
pub fn emit_threat_alert<S: Serialize + Clone>(payload: S) {
    if let Err(e) = emit(events::THREAT_ALERT, payload) {
        log::error!("Failed to emit threat alert: {}", e);
    }
}
