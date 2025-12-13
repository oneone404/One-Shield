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
        Self {
            // Read from environment, fallback to production URL
            server_url: std::env::var("CLOUD_SERVER_URL")
                .unwrap_or_else(|_| "https://api.accone.vn".to_string()),
            registration_key: std::env::var("CLOUD_REGISTRATION_KEY")
                .unwrap_or_else(|_| "dev-agent-secret-change-in-production-789012".to_string()),
            heartbeat_interval_secs: std::env::var("CLOUD_HEARTBEAT_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            incident_sync_interval_secs: std::env::var("CLOUD_INCIDENT_SYNC_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
            enabled: std::env::var("CLOUD_SYNC_ENABLED")
                .map(|s| s.to_lowercase() != "false" && s != "0")
                .unwrap_or(true),
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
    pub heartbeat_count: u64,
    pub incident_sync_count: u64,
    pub errors: Vec<String>,
    pub server_version: Option<String>,
}

/// Pending incidents queue
static PENDING_INCIDENTS: once_cell::sync::Lazy<RwLock<Vec<SyncIncidentRequest>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(Vec::new()));

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
            // Register new agent with HWID
            log::info!("Registering agent with cloud server (HWID: {}...)", &hwid[..8]);

            match client.write().register_with_hwid(&hwid).await {
                Ok(result) => {
                    log::info!("✅ Agent registered: {}", result.agent_id);

                    // Save identity to storage
                    {
                        let mut identity_mgr = get_identity_manager().write();
                        if let Err(e) = identity_mgr.save_identity(
                            result.agent_id,
                            result.token.clone(),
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
                    log::error!("Failed to register agent: {}", e);
                    let mut status = super::get_status();
                    status.errors.push(format!("Registration failed: {}", e));
                    set_status(status);
                    // Don't return, keep trying in the loop
                }
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
                        status.heartbeat_count += 1;
                        status.is_connected = true;
                        set_status(status);

                        // Handle commands
                        for cmd in response.commands {
                            handle_command(cmd).await;
                        }
                    }
                    Err(e) => {
                        log::warn!("Heartbeat failed: {}", e);
                        let mut status = super::get_status();
                        status.is_connected = false;
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
                            status.incident_sync_count += response.synced_count as u64;
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
