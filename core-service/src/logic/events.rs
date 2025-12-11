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
