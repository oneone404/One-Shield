//! Enterprise Agent Identity Module
//!
//! Provides secure, hardware-bound agent identity management following
//! enterprise EDR standards (CrowdStrike, SentinelOne, Defender ATP).
//!
//! Features:
//! - Hardware-bound identity (HWID)
//! - DPAPI-style encryption with HMAC signing
//! - Anti-rollback protection
//! - Cloud verification support

pub mod hwid;
pub mod storage;

pub use hwid::generate_hwid;
pub use storage::{AgentIdentity, IdentityStorage, IdentityError};

use uuid::Uuid;
use chrono::Utc;
use once_cell::sync::OnceCell;
use parking_lot::RwLock;

/// Global identity manager instance
static IDENTITY_MANAGER: OnceCell<RwLock<IdentityManager>> = OnceCell::new();

/// Get the global identity manager
pub fn get_identity_manager() -> &'static RwLock<IdentityManager> {
    IDENTITY_MANAGER.get_or_init(|| {
        RwLock::new(IdentityManager::new())
    })
}

/// Initialize identity on startup
pub fn init() -> Result<IdentityState, IdentityError> {
    let mut manager = get_identity_manager().write();
    manager.initialize()
}

/// Get current agent ID (if registered)
pub fn get_agent_id() -> Option<Uuid> {
    let manager = get_identity_manager().read();
    manager.current_identity.as_ref().map(|i| i.agent_id)
}

/// Get current HWID
pub fn get_hwid() -> String {
    let manager = get_identity_manager().read();
    manager.hwid.clone()
}

/// Identity manager state
pub struct IdentityManager {
    /// Current HWID
    hwid: String,

    /// Storage handler
    storage: IdentityStorage,

    /// Current loaded identity (if any)
    current_identity: Option<AgentIdentity>,
}

/// Result of identity initialization
#[derive(Debug, Clone)]
pub enum IdentityState {
    /// Identity loaded from file, ready to verify with cloud
    Loaded(AgentIdentity),

    /// No identity found, needs registration
    NeedsRegistration { hwid: String },

    /// Identity invalid, needs re-registration
    Invalid { hwid: String, reason: String },
}

impl IdentityManager {
    /// Create new identity manager
    pub fn new() -> Self {
        let hwid = generate_hwid();
        let storage = IdentityStorage::new(&hwid);

        Self {
            hwid,
            storage,
            current_identity: None,
        }
    }

    /// Initialize identity on startup
    ///
    /// Enterprise EDR behavior:
    /// - If config tampered → emit incident + self-heal
    /// - User sửa file = vô nghĩa
    pub fn initialize(&mut self) -> Result<IdentityState, IdentityError> {
        log::info!("Initializing agent identity...");
        log::info!("HWID: {}...{}", &self.hwid[..8], &self.hwid[self.hwid.len()-8..]);

        if !self.storage.exists() {
            log::info!("No identity file found, registration required");
            return Ok(IdentityState::NeedsRegistration {
                hwid: self.hwid.clone()
            });
        }

        // Try to load existing identity
        match self.storage.load(&self.hwid) {
            Ok(identity) => {
                log::info!("Identity loaded: agent={}", identity.agent_id);
                self.current_identity = Some(identity.clone());
                Ok(IdentityState::Loaded(identity))
            }
            Err(IdentityError::InvalidSignature) => {
                // 🛡️ CONFIG TAMPERING DETECTED!
                log::error!("🚨 CONFIG TAMPERING DETECTED: Invalid signature!");
                log::warn!("Identity file has been modified by user/attacker");

                // Emit tamper incident (MITRE T1562 - Impair Defenses)
                Self::emit_tamper_incident("invalid_signature", "Identity file signature mismatch - file was modified");

                // Self-heal: Delete corrupted file, force re-registration
                if let Err(e) = self.storage.delete() {
                    log::error!("Failed to delete tampered config: {}", e);
                }

                log::info!("Self-healing: Deleted tampered config, will re-register");

                Ok(IdentityState::Invalid {
                    hwid: self.hwid.clone(),
                    reason: "Config tampering detected - self-healed".to_string()
                })
            }
            Err(IdentityError::HwidMismatch) => {
                // 🛡️ CONFIG COPIED FROM ANOTHER MACHINE!
                log::error!("🚨 CONFIG TAMPERING DETECTED: HWID mismatch!");
                log::warn!("Identity file was copied from another machine");

                // Emit tamper incident
                Self::emit_tamper_incident("hwid_mismatch", "Identity file copied from another machine - HWID mismatch");

                // Self-heal
                if let Err(e) = self.storage.delete() {
                    log::error!("Failed to delete copied config: {}", e);
                }

                log::info!("Self-healing: Deleted copied config, will re-register");

                Ok(IdentityState::Invalid {
                    hwid: self.hwid.clone(),
                    reason: "Config copied from another machine - self-healed".to_string()
                })
            }
            Err(e) => {
                log::error!("Failed to load identity: {}", e);

                // Generic corruption - also self-heal
                if let Err(del_err) = self.storage.delete() {
                    log::error!("Failed to delete corrupted config: {}", del_err);
                }

                Ok(IdentityState::Invalid {
                    hwid: self.hwid.clone(),
                    reason: e.to_string()
                })
            }
        }
    }

    /// Emit tamper incident to cloud
    /// MITRE ATT&CK: T1562 - Impair Defenses
    ///
    /// Enterprise EDR: User sửa config = incident gửi lên cloud
    fn emit_tamper_incident(tamper_type: &str, description: &str) {
        let incident_id = uuid::Uuid::new_v4();

        log::error!("📢 CONFIG TAMPERING INCIDENT: {} - {}", incident_id, tamper_type);
        log::warn!("   MITRE: T1562 (Impair Defenses)");
        log::warn!("   Description: {}", description);
        log::info!("   Action: Agent self-healed, will re-register with cloud");

        // Queue for cloud sync - this is the important part
        // Cloud will see this incident even if user tries to hide it
        crate::logic::cloud_sync::sync::queue_incident(
            incident_id,
            "high".to_string(),
            format!("Config Tampering: {}", tamper_type),
            Some(description.to_string()),
            Some(vec!["T1562".to_string(), "T1562.001".to_string()]),
            Some("Defense Evasion".to_string()),
            Some(1.0), // 100% confidence - deterministic check
        );

        log::info!("✅ Tamper incident queued for cloud sync");
    }

    /// Save new identity after registration
    pub fn save_identity(
        &mut self,
        agent_id: Uuid,
        agent_token: String,
        org_id: Uuid,
        server_url: &str,
    ) -> Result<(), IdentityError> {
        let identity = AgentIdentity {
            agent_id,
            agent_token,
            hwid: self.hwid.clone(),
            org_id,
            issued_at: Utc::now(),
            version: 1,
            server_url: server_url.to_string(),
        };

        self.storage.save(&identity)?;
        self.current_identity = Some(identity);

        log::info!("New identity saved: agent={}", agent_id);

        Ok(())
    }

    /// Update identity version (after cloud verification)
    pub fn update_version(&mut self, new_version: u32) -> Result<(), IdentityError> {
        if let Some(ref mut identity) = self.current_identity {
            identity.version = new_version;
            self.storage.save(identity)?;
            log::debug!("Identity version updated to {}", new_version);
        }
        Ok(())
    }

    /// Clear identity (force re-registration)
    pub fn clear_identity(&mut self) -> Result<(), IdentityError> {
        self.storage.delete()?;
        self.current_identity = None;
        log::info!("Identity cleared, will re-register on next start");
        Ok(())
    }

    /// Get current identity
    pub fn current(&self) -> Option<&AgentIdentity> {
        self.current_identity.as_ref()
    }

    /// Get HWID
    pub fn hwid(&self) -> &str {
        &self.hwid
    }
}

impl Default for IdentityManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_manager_new() {
        let manager = IdentityManager::new();

        // HWID should be 64 characters (SHA256 hex)
        assert_eq!(manager.hwid.len(), 64);

        // No identity loaded initially
        assert!(manager.current_identity.is_none());
    }
}
