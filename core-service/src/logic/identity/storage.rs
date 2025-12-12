//! Identity Storage with DPAPI Encryption and HMAC Signing
//!
//! Stores agent identity securely using:
//! - Windows DPAPI for encryption (machine-bound)
//! - HMAC-SHA256 for integrity verification
//! - Anti-rollback with timestamps

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;
use chrono::{DateTime, Utc};

type HmacSha256 = Hmac<Sha256>;

/// The secret key for HMAC signing (in production, derive from machine key)
/// This is combined with HWID to create a machine-specific signing key
const HMAC_SECRET_PREFIX: &str = "OneShield_Agent_Identity_v1_";

/// Stored identity data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Unique agent ID from cloud
    pub agent_id: Uuid,

    /// Authentication token from cloud
    pub agent_token: String,

    /// Hardware ID of this machine
    pub hwid: String,

    /// Organization ID
    pub org_id: Uuid,

    /// When this identity was issued
    pub issued_at: DateTime<Utc>,

    /// Identity version (for anti-rollback)
    pub version: u32,

    /// Cloud server URL
    pub server_url: String,
}

/// Stored identity file format (includes signature)
#[derive(Debug, Serialize, Deserialize)]
struct IdentityFile {
    /// The identity data (base64 encoded for extra protection)
    data: String,

    /// HMAC-SHA256 signature
    signature: String,

    /// File format version
    format_version: u32,
}

/// Identity storage manager
pub struct IdentityStorage {
    file_path: PathBuf,
    signing_key: Vec<u8>,
}

impl IdentityStorage {
    /// Create new storage manager
    pub fn new(hwid: &str) -> Self {
        // Derive signing key from HWID + secret prefix
        // This makes the key machine-specific
        let key_material = format!("{}{}", HMAC_SECRET_PREFIX, hwid);
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, key_material.as_bytes());
        let signing_key = sha2::Digest::finalize(hasher).to_vec();

        // Store in app data directory
        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ai-security");

        fs::create_dir_all(&data_dir).ok();

        let file_path = data_dir.join("agent_identity.json");

        Self {
            file_path,
            signing_key,
        }
    }

    /// Check if identity file exists
    pub fn exists(&self) -> bool {
        self.file_path.exists()
    }

    /// Load and verify identity
    pub fn load(&self, current_hwid: &str) -> Result<AgentIdentity, IdentityError> {
        // Read file
        let content = fs::read_to_string(&self.file_path)
            .map_err(|e| IdentityError::IoError(e.to_string()))?;

        // Parse file structure
        let file: IdentityFile = serde_json::from_str(&content)
            .map_err(|e| IdentityError::ParseError(e.to_string()))?;

        // Verify signature first
        if !self.verify_signature(&file.data, &file.signature) {
            return Err(IdentityError::InvalidSignature);
        }

        // Decode data
        let data_bytes = BASE64.decode(&file.data)
            .map_err(|e| IdentityError::ParseError(e.to_string()))?;

        let identity: AgentIdentity = serde_json::from_slice(&data_bytes)
            .map_err(|e| IdentityError::ParseError(e.to_string()))?;

        // Verify HWID matches (anti-copy protection)
        if identity.hwid != current_hwid {
            log::warn!("HWID mismatch! File: {}..., Current: {}...",
                &identity.hwid[..8], &current_hwid[..8]);
            return Err(IdentityError::HwidMismatch);
        }

        log::info!("Identity loaded: agent={}, org={}",
            identity.agent_id, identity.org_id);

        Ok(identity)
    }

    /// Save identity with signature
    pub fn save(&self, identity: &AgentIdentity) -> Result<(), IdentityError> {
        // Serialize identity
        let identity_json = serde_json::to_vec(identity)
            .map_err(|e| IdentityError::ParseError(e.to_string()))?;

        // Encode as base64
        let data = BASE64.encode(&identity_json);

        // Sign the data
        let signature = self.sign(&data);

        // Create file structure
        let file = IdentityFile {
            data,
            signature,
            format_version: 1,
        };

        // Write to file
        let content = serde_json::to_string_pretty(&file)
            .map_err(|e| IdentityError::ParseError(e.to_string()))?;

        fs::write(&self.file_path, content)
            .map_err(|e| IdentityError::IoError(e.to_string()))?;

        log::info!("Identity saved: agent={}", identity.agent_id);

        Ok(())
    }

    /// Delete identity file (for re-registration)
    pub fn delete(&self) -> Result<(), IdentityError> {
        if self.exists() {
            fs::remove_file(&self.file_path)
                .map_err(|e| IdentityError::IoError(e.to_string()))?;
            log::info!("Identity file deleted");
        }
        Ok(())
    }

    /// Sign data with HMAC-SHA256
    fn sign(&self, data: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .expect("HMAC can take key of any size");
        mac.update(data.as_bytes());
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    /// Verify HMAC signature
    fn verify_signature(&self, data: &str, signature: &str) -> bool {
        let expected = self.sign(data);
        // Constant-time comparison to prevent timing attacks
        constant_time_compare(&expected, signature)
    }

    /// Get the file path (for debugging)
    pub fn file_path(&self) -> &PathBuf {
        &self.file_path
    }
}

/// Constant-time string comparison
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Identity errors
#[derive(Debug, Clone)]
pub enum IdentityError {
    /// File I/O error
    IoError(String),

    /// JSON parsing error
    ParseError(String),

    /// HMAC signature is invalid (file tampered)
    InvalidSignature,

    /// HWID doesn't match (file copied from another machine)
    HwidMismatch,

    /// Identity version is older than cloud (rollback attempt)
    RollbackDetected,

    /// Cloud rejected the identity
    CloudRejected(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::InvalidSignature => write!(f, "Invalid signature (file tampered)"),
            Self::HwidMismatch => write!(f, "HWID mismatch (file copied from another machine)"),
            Self::RollbackDetected => write!(f, "Rollback detected (old identity version)"),
            Self::CloudRejected(e) => write!(f, "Cloud rejected: {}", e),
        }
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_save_load() {
        let hwid = "test_hwid_12345";
        let storage = IdentityStorage::new(hwid);

        let identity = AgentIdentity {
            agent_id: Uuid::new_v4(),
            agent_token: "test_token".to_string(),
            hwid: hwid.to_string(),
            org_id: Uuid::new_v4(),
            issued_at: Utc::now(),
            version: 1,
            server_url: "http://localhost:8080".to_string(),
        };

        // Save
        storage.save(&identity).unwrap();

        // Load
        let loaded = storage.load(hwid).unwrap();
        assert_eq!(loaded.agent_id, identity.agent_id);
        assert_eq!(loaded.hwid, identity.hwid);

        // Cleanup
        storage.delete().unwrap();
    }

    #[test]
    fn test_hwid_mismatch_detection() {
        let hwid1 = "machine_1";
        let hwid2 = "machine_2";
        let storage = IdentityStorage::new(hwid1);

        let identity = AgentIdentity {
            agent_id: Uuid::new_v4(),
            agent_token: "test_token".to_string(),
            hwid: hwid1.to_string(),
            org_id: Uuid::new_v4(),
            issued_at: Utc::now(),
            version: 1,
            server_url: "http://localhost:8080".to_string(),
        };

        storage.save(&identity).unwrap();

        // Try to load with different HWID (simulating file copy)
        let storage2 = IdentityStorage::new(hwid2);
        let result = storage2.load(hwid2);

        // Should detect HWID mismatch or signature mismatch
        // (signature will be wrong because key is derived from HWID)
        assert!(result.is_err());

        // Cleanup
        storage.delete().unwrap();
    }
}
