//! Cloud Sync Loop
//!
//! Background task for periodic cloud synchronization.

use super::client::{CloudClient, CloudConfig, CloudError, SyncIncidentRequest};
use super::set_status;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

/// Sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Cloud server URL
    pub server_url: String,
    /// Registration key
    pub registration_key: String,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// Incident sync interval in seconds
    pub incident_sync_interval_secs: u64,
    /// Enable cloud sync
    pub enabled: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        use crate::constants;

        Self {
            server_url: constants::get_cloud_url(),
            registration_key: constants::get_registration_key(),
            heartbeat_interval_secs: constants::get_heartbeat_interval(),
            incident_sync_interval_secs: constants::get_incident_sync_interval(),
            enabled: constants::is_cloud_sync_enabled(),
        }
    }
}

/// Sync status
#[derive(Debug, Clone, Default, Serialize)]
pub struct SyncStatus {
    pub is_connected: bool,
    pub is_registered: bool,
    pub agent_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub last_sync: Option<DateTime<Utc>>,
    pub last_success_sync: Option<DateTime<Utc>>,  // Hardening: last successful operation
    pub heartbeat_count: u64,
    pub incident_sync_count: u64,
    pub consecutive_failures: u32,  // Hardening: track failures
    pub next_retry_delay_secs: u64, // Hardening: current backoff delay
    pub last_error_type: Option<String>, // Hardening: distinguish error types
    pub errors: Vec<String>,
    pub server_version: Option<String>,
}

/// Pending incidents queue
static PENDING_INCIDENTS: once_cell::sync::Lazy<RwLock<Vec<SyncIncidentRequest>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(Vec::new()));

/// Global cloud client for token updates
static CLOUD_CLIENT: once_cell::sync::Lazy<RwLock<Option<Arc<RwLock<CloudClient>>>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(None));

/// Reload cloud client credentials from identity storage
/// Call this after login/logout to update the token
pub fn reload_credentials() {
    use crate::logic::identity::{self, IdentityState, get_identity_manager};

    log::info!("Reloading cloud sync credentials...");

    // Re-init identity
    match identity::init() {
        Ok(IdentityState::Loaded(identity)) => {
            // Update client token if available
            if let Some(client) = CLOUD_CLIENT.read().as_ref() {
                client.write().set_token(identity.agent_token.clone());
                log::info!("✅ Cloud client credentials reloaded: agent={}", identity.agent_id);

                // Update status
                let mut status = super::get_status();
                status.is_registered = true;
                status.is_connected = true;
                status.agent_id = Some(identity.agent_id);
                status.org_id = Some(identity.org_id);
                set_status(status);
            }
        }
        Ok(IdentityState::NeedsRegistration { .. }) => {
            log::info!("Identity cleared, waiting for new login");
            let mut status = super::get_status();
            status.is_registered = false;
            status.is_connected = false;
            status.agent_id = None;
            status.org_id = None;
            set_status(status);
        }
        Ok(IdentityState::Invalid { .. }) => {
            log::warn!("Identity invalid after reload");
        }
        Err(e) => {
            log::error!("Failed to reload identity: {:?}", e);
        }
    }
}

/// Add incident to sync queue
pub fn queue_incident(
    id: Uuid,
    severity: String,
    title: String,
    description: Option<String>,
    mitre_techniques: Option<Vec<String>>,
    threat_class: Option<String>,
    confidence: Option<f32>,
) {
    let incident = SyncIncidentRequest {
        id,
        severity,
        title,
        description,
        mitre_techniques,
        threat_class,
        confidence,
        created_at: Utc::now().timestamp(),
    };

    PENDING_INCIDENTS.write().push(incident);
    log::debug!("Incident queued for cloud sync: {}", id);
}

/// Get pending incidents count
pub fn pending_incidents_count() -> usize {
    PENDING_INCIDENTS.read().len()
}

/// Start the cloud sync background loop
pub async fn start_sync_loop(config: SyncConfig) {
    if !config.enabled {
        log::info!("Cloud sync is disabled");
        return;
    }

    log::info!("Starting cloud sync loop...");
    log::info!("  Server: {}", config.server_url);
    log::info!("  Heartbeat interval: {}s", config.heartbeat_interval_secs);

    let cloud_config = CloudConfig {
        server_url: config.server_url.clone(),
        registration_key: config.registration_key.clone(),
        timeout_seconds: 30,
    };

    let client = Arc::new(RwLock::new(CloudClient::new(cloud_config)));

    // Save to global for credential reloading
    *CLOUD_CLIENT.write() = Some(client.clone());

    // Initial status
    set_status(SyncStatus {
        is_connected: false,
        is_registered: false,
        ..Default::default()
    });

    // Health check first
    log::info!("Checking cloud server health...");
    match client.read().health_check().await {
        Ok(health) => {
            log::info!("Cloud server healthy: v{}", health.version);
            let mut status = super::get_status();
            status.is_connected = true;
            status.server_version = Some(health.version);
            set_status(status);
        }
        Err(e) => {
            log::warn!("Cloud server not reachable: {}", e);
            // Continue anyway, will retry
        }
    }

    // ========== Enterprise Identity Integration ==========
    use crate::logic::identity::{self, IdentityState, get_identity_manager};

    // Initialize identity manager
    let identity_state = match identity::init() {
        Ok(state) => state,
        Err(e) => {
            log::error!("Failed to initialize identity: {}", e);
            IdentityState::NeedsRegistration { hwid: identity::get_hwid() }
        }
    };

    match identity_state {
        IdentityState::Loaded(existing) => {
            // Use existing identity
            log::info!("Using existing identity: agent={}", existing.agent_id);

            // Set credentials on client
            client.write().set_token(existing.agent_token.clone());

            let mut status = super::get_status();
            status.is_registered = true;
            status.agent_id = Some(existing.agent_id);
            status.org_id = Some(existing.org_id);
            set_status(status);

            // TODO: Verify with cloud in future (anti-rollback)
            log::info!("✅ Identity loaded from storage (HWID-bound)");
        }
        IdentityState::NeedsRegistration { hwid } | IdentityState::Invalid { hwid, .. } => {
            // Check for enrollment token (Phase 12)
            let enrollment_token = crate::constants::get_enrollment_token_any();

            if let Some(token) = enrollment_token {
                // Use new Phase 12 enrollment flow
                log::info!("Enrolling agent with token: {}... (HWID: {}...)",
                    &token[..token.len().min(15)],
                    &hwid[..8]
                );

                match client.write().enroll(&token, &hwid).await {
                    Ok(result) => {
                        log::info!("✅ Agent enrolled: {} (org: {})", result.agent_id, result.org_name);

                        // Save identity to storage
                        {
                            let mut identity_mgr = get_identity_manager().write();
                            if let Err(e) = identity_mgr.save_identity(
                                result.agent_id,
                                result.agent_token.clone(),
                                result.org_id,
                                &config.server_url,
                            ) {
                                log::error!("Failed to save identity: {}", e);
                            } else {
                                log::info!("Identity saved to secure storage");
                            }
                        }

                        let mut status = super::get_status();
                        status.is_registered = true;
                        status.agent_id = Some(result.agent_id);
                        status.org_id = Some(result.org_id);
                        set_status(status);
                    }
                    Err(e) => {
                        log::error!("Enrollment failed: {}", e);
                        let mut status = super::get_status();
                        status.errors.push(format!("Enrollment failed: {}", e));
                        set_status(status);
                    }
                }
            } else {
                // Phase 13: Personal mode - wait for user login via AuthModal
                // Do NOT use legacy registration anymore
                log::info!("🔐 Personal mode detected, waiting for user login...");
                log::info!("   HWID: {}...", &hwid[..8]);
                log::info!("   Please login/register in the app to continue.");

                let mut status = super::get_status();
                status.errors.push("Waiting for user authentication".to_string());
                set_status(status);

                // Stay in this state - the sync loop will continue but heartbeat will fail
                // User needs to call personal_enroll() via AuthModal
            }
        }
    }

    // Main sync loop
    let heartbeat_interval = Duration::from_secs(config.heartbeat_interval_secs);
    let incident_interval = Duration::from_secs(config.incident_sync_interval_secs);

    let mut heartbeat_timer = tokio::time::Instant::now();
    let mut incident_timer = tokio::time::Instant::now();

    loop {
        sleep(Duration::from_secs(5)).await;

        // Check if identity was added (from personal_enroll)
        if !client.read().is_registered() {
            // Re-check identity file
            let current = get_identity_manager().read().current().cloned();
            if let Some(existing) = current {
                log::info!("🔐 New identity detected from personal_enroll!");
                log::info!("   Agent: {}", existing.agent_id);

                // Set credentials on client
                client.write().set_token(existing.agent_token.clone());

                let mut status = super::get_status();
                status.is_registered = true;
                status.agent_id = Some(existing.agent_id);
                status.org_id = Some(existing.org_id);
                set_status(status);

                log::info!("✅ Cloud sync activated!");
            }
        }

        // Heartbeat
        if heartbeat_timer.elapsed() >= heartbeat_interval {
            heartbeat_timer = tokio::time::Instant::now();

            if client.read().is_registered() {
                // Get current metrics
                let (cpu, mem) = get_system_metrics();
                let incident_count = pending_incidents_count() as i32;

                match client.read().heartbeat(cpu, mem, incident_count).await {
                    Ok(response) => {
                        log::debug!("Heartbeat sent. Server time: {}, Policy v{}",
                            response.server_time, response.policy_version);

                        let mut status = super::get_status();
                        status.last_heartbeat = Some(Utc::now());
                        status.last_success_sync = Some(Utc::now()); // Hardening
                        status.heartbeat_count += 1;
                        status.is_connected = true;
                        status.consecutive_failures = 0; // Reset on success
                        status.next_retry_delay_secs = 1; // Reset backoff
                        status.last_error_type = None;
                        set_status(status);

                        // Handle commands
                        for cmd in response.commands {
                            handle_command(cmd).await;
                        }
                    }
                    Err(e) => {
                        let mut status = super::get_status();
                        status.consecutive_failures += 1;

                        // Classify error type for hardening
                        let error_type = match &e {
                            CloudError::Unauthorized => {
                                // 401 = token expired, need re-login
                                log::warn!("⚠️ Heartbeat 401 Unauthorized - token may be expired");
                                "auth_expired".to_string()
                            }
                            CloudError::ServerError(code) if *code >= 500 => {
                                // 5xx = server issue, will retry
                                log::warn!("⚠️ Server error {}, will retry with backoff", code);
                                format!("server_{}", code)
                            }
                            CloudError::NetworkError(_) => {
                                // Network = temporary, will retry
                                log::warn!("⚠️ Network unreachable, will retry");
                                "network".to_string()
                            }
                            _ => {
                                log::warn!("Heartbeat failed: {}", e);
                                "other".to_string()
                            }
                        };

                        status.last_error_type = Some(error_type.clone());

                        // Exponential backoff: 1s -> 5s -> 30s -> 60s (max)
                        let new_delay = match status.consecutive_failures {
                            1 => 1,
                            2 => 5,
                            3 => 30,
                            _ => 60,
                        };
                        status.next_retry_delay_secs = new_delay;

                        // Server unreachable ≠ logout (hardening)
                        // Only mark as disconnected if network/server error
                        // 401 Unauthorized should trigger re-auth flow, not disconnect
                        if error_type != "auth_expired" {
                            status.is_connected = false;
                        }

                        set_status(status);
                    }
                }
            }
        }

        // Incident sync
        if incident_timer.elapsed() >= incident_interval {
            incident_timer = tokio::time::Instant::now();

            if client.read().is_registered() {
                let incidents: Vec<SyncIncidentRequest> = {
                    let mut queue = PENDING_INCIDENTS.write();
                    std::mem::take(&mut *queue)
                };

                if !incidents.is_empty() {
                    log::info!("Syncing {} incidents to cloud...", incidents.len());

                    match client.read().sync_incidents(incidents.clone()).await {
                        Ok(response) => {
                            log::info!("✅ Synced {} incidents", response.synced_count);
                            let mut status = super::get_status();
                            status.last_sync = Some(Utc::now());
                            status.last_success_sync = Some(Utc::now()); // Hardening
                            status.incident_sync_count += response.synced_count as u64;
                            status.consecutive_failures = 0; // Reset on success
                            set_status(status);
                        }
                        Err(e) => {
                            log::error!("Incident sync failed: {}", e);
                            // Re-queue incidents
                            PENDING_INCIDENTS.write().extend(incidents);
                        }
                    }
                }
            }
        }
    }
}

/// Get system metrics for heartbeat
fn get_system_metrics() -> (f32, f32) {
    // Simple implementation - can be enhanced
    use sysinfo::System;

    let mut sys = System::new();
    sys.refresh_all();
    sys.refresh_memory();

    let cpu = sys.cpus().iter()
        .map(|c| c.cpu_usage())
        .sum::<f32>() / sys.cpus().len().max(1) as f32;

    let mem = (sys.used_memory() as f64 / sys.total_memory() as f64 * 100.0) as f32;

    (cpu, mem)
}

/// Handle command from server
async fn handle_command(cmd: super::client::AgentCommand) {
    match cmd {
        super::client::AgentCommand::UpdatePolicy { version } => {
            log::info!("📋 Received UpdatePolicy command: v{}", version);
            // TODO: Fetch and apply new policy
        }
        super::client::AgentCommand::CollectDiagnostics => {
            log::info!("🔍 Received CollectDiagnostics command");
            // TODO: Collect and upload diagnostics
        }
        super::client::AgentCommand::RestartService => {
            log::warn!("🔄 Received RestartService command");
            // TODO: Restart service
        }
        super::client::AgentCommand::UpdateAgent { url, checksum } => {
            log::info!("⬆️ Received UpdateAgent command: {}", url);
            // TODO: Download and install update
        }
    }
}
