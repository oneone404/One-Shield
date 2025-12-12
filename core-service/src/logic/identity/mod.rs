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
                log::warn!("Identity file has invalid signature (tampered?)");
                Ok(IdentityState::Invalid {
                    hwid: self.hwid.clone(),
                    reason: "Invalid signature".to_string()
                })
            }
            Err(IdentityError::HwidMismatch) => {
                log::warn!("Identity file HWID mismatch (copied from another machine?)");
                Ok(IdentityState::Invalid {
                    hwid: self.hwid.clone(),
                    reason: "HWID mismatch".to_string()
                })
            }
            Err(e) => {
                log::error!("Failed to load identity: {}", e);
                Ok(IdentityState::Invalid {
                    hwid: self.hwid.clone(),
                    reason: e.to_string()
                })
            }
        }
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
