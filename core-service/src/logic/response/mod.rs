//! Response & Automation Module - Automated Threat Response (Phase 5)
//!
//! Mục đích: Tự động phản ứng với threats
//!
//! # Components
//! - `actions.rs`: Process actions (suspend, kill, quarantine)
//! - `network.rs`: Network isolation via Windows Firewall
//! - `file_quarantine.rs`: File quarantine management
//! - `webhook.rs`: Alert integration (Slack, Discord, Teams)

// Allow unused for now - will be fully integrated in future phases
#![allow(unused)]

pub mod actions;
pub mod network;
pub mod file_quarantine;
pub mod webhook;
pub mod types;

// Re-exports from types
pub use types::{
    ResponseAction, ActionResult, ActionError, ActionStatus,
    QuarantineEntry, WebhookConfig, WebhookPlatform, AlertPayload,
};

// Re-exports from submodules
pub use actions::{
    suspend_process, resume_process, kill_process,
    execute_action, get_action_history,
};
pub use network::{
    block_network, unblock_network, is_network_blocked,
    get_blocked_processes,
};
pub use file_quarantine::{
    quarantine_file, restore_file, delete_quarantined,
    get_quarantine_list, QuarantineManager,
};
pub use webhook::{
    send_alert, add_webhook, remove_webhook, test_webhook,
    get_webhooks, AlertManager,
};
