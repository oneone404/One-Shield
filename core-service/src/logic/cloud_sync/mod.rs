//! Cloud Sync Module - Agent to Cloud Communication
//!
//! This module handles:
//! - Agent registration with cloud server
//! - Periodic heartbeats
//! - Incident synchronization
//! - Policy updates

pub mod client;
pub mod sync;

pub use client::CloudClient;
pub use sync::{start_sync_loop, reload_credentials, SyncConfig, SyncStatus};

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global cloud sync status
static CLOUD_CONNECTED: AtomicBool = AtomicBool::new(false);
static SYNC_STATUS: Lazy<RwLock<SyncStatus>> = Lazy::new(|| RwLock::new(SyncStatus::default()));

/// Check if cloud sync is enabled and connected
pub fn is_connected() -> bool {
    CLOUD_CONNECTED.load(Ordering::Relaxed)
}

/// Get current sync status
pub fn get_status() -> SyncStatus {
    SYNC_STATUS.read().clone()
}

/// Update sync status
pub(crate) fn set_status(status: SyncStatus) {
    let is_connected = status.is_connected;
    *SYNC_STATUS.write() = status;
    CLOUD_CONNECTED.store(is_connected, Ordering::Relaxed);
}

/// Initialize cloud sync (call from main)
pub fn init() {
    log::info!("Cloud Sync module initialized");
}

// ==========================================
// Agent Mode Detection (Phase 13)
// ==========================================

/// Agent operating mode
/// Determines how the agent authenticates and whether login UI is shown
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentMode {
    /// Organization mode: Has enrollment token, no login UI
    /// Used by enterprise deployments
    Organization,
    /// Personal mode: Needs user login/register
    /// Used by individual users (Free/Pro)
    Personal,
}

impl AgentMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentMode::Organization => "organization",
            AgentMode::Personal => "personal",
        }
    }
}

/// Detect agent mode based on enrollment token presence
///
/// Rule:
/// - Has enrollment token → Organization mode (no login UI)
/// - No enrollment token → Personal mode (show login UI)
pub fn detect_mode() -> AgentMode {
    if crate::constants::get_enrollment_token_any().is_some() {
        AgentMode::Organization
    } else {
        AgentMode::Personal
    }
}

/// Check if agent needs user login
pub fn needs_login() -> bool {
    detect_mode() == AgentMode::Personal
}
