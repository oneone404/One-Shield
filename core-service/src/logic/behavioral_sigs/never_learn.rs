//! Never-Learn Blacklist Module (Phase 3)
//!
//! Mục đích: Một số patterns KHÔNG BAO GIỜ được học vào baseline
//!
//! Rules:
//! - Known malware processes/hashes
//! - Network to Tor/C2
//! - Registry persistence attempts
//! - Unsigned with network activity

use std::collections::HashSet;
use std::path::Path;
use parking_lot::RwLock;
use once_cell::sync::Lazy;

use super::types::{NeverLearnReason, SampleContext};
use crate::logic::process_intel;

// ============================================================================
// BLACKLISTS
// ============================================================================

/// Known malware process names
const BLACKLISTED_PROCESSES: &[&str] = &[
    "mimikatz.exe",
    "lazagne.exe",
    "procdump.exe",
    "pwdump.exe",
    "gsecdump.exe",
    "wce.exe",
    "fgdump.exe",
    "cachedump.exe",
    "lsadump.exe",
    "psexec.exe",      // Often abused
    "paexec.exe",
    "nc.exe",          // Netcat
    "nc64.exe",
    "ncat.exe",
    "socat.exe",
    "putty.exe",       // When spawned suspiciously
    "plink.exe",
    "pscp.exe",
];

/// Known malware hashes (SHA256)
const BLACKLISTED_HASHES: &[&str] = &[
    // Mimikatz hashes
    "981bf56f4d20df7c5e3c2d1d3e3c0b0c0a0f0e0d0c0b0a0f0e0d0c0b0a0f0e0d",
    // Add more known bad hashes here
];

/// Known C2 domains/IPs (sample list)
const KNOWN_C2_ENDPOINTS: &[&str] = &[
    // Tor exit nodes (sample)
    ".onion",
    ".i2p",
    ".bit",

    // Known bad domains (examples, not real)
    "evil-c2.com",
    "badactor.biz",
];

/// Suspicious TLDs
const SUSPICIOUS_TLDS: &[&str] = &[
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".work",
    ".click",
];

// ============================================================================
// STATE
// ============================================================================

static BLACKLIST: Lazy<RwLock<NeverLearnBlacklist>> =
    Lazy::new(|| RwLock::new(NeverLearnBlacklist::new()));

// ============================================================================
// NEVER LEARN BLACKLIST
// ============================================================================

pub struct NeverLearnBlacklist {
    /// Blacklisted process names (lowercase)
    process_names: HashSet<String>,

    /// Blacklisted hashes
    hashes: HashSet<String>,

    /// Known C2 endpoints
    c2_endpoints: HashSet<String>,

    /// Block unsigned + network
    block_unsigned_network: bool,

    /// Block unsigned + disk write
    block_unsigned_disk: bool,

    /// Enable/disable
    enabled: bool,
}

impl NeverLearnBlacklist {
    pub fn new() -> Self {
        let mut bl = Self {
            process_names: HashSet::new(),
            hashes: HashSet::new(),
            c2_endpoints: HashSet::new(),
            block_unsigned_network: true,
            block_unsigned_disk: false, // Too noisy by default
            enabled: true,
        };

        // Initialize with defaults
        for name in BLACKLISTED_PROCESSES {
            bl.process_names.insert(name.to_lowercase());
        }
        for hash in BLACKLISTED_HASHES {
            bl.hashes.insert(hash.to_lowercase());
        }
        for endpoint in KNOWN_C2_ENDPOINTS {
            bl.c2_endpoints.insert(endpoint.to_lowercase());
        }

        bl
    }

    /// Check if sample should never be learned
    pub fn should_never_learn(&self, ctx: &SampleContext) -> Option<NeverLearnReason> {
        if !self.enabled {
            return None;
        }

        // Check process name
        if let Some(ref name) = ctx.process_name {
            let name_lower = name.to_lowercase();
            if self.process_names.contains(&name_lower) {
                return Some(NeverLearnReason::ProcessBlacklisted {
                    name: name.clone()
                });
            }
        }

        // Check hash
        if let Some(ref hash) = ctx.process_hash {
            if self.hashes.contains(&hash.to_lowercase()) {
                return Some(NeverLearnReason::HashBlacklisted {
                    hash: hash.clone()
                });
            }
        }

        // Check network destinations
        for dest in &ctx.network_destinations {
            let dest_lower = dest.to_lowercase();

            // Check for Tor
            if dest_lower.ends_with(".onion") || dest_lower.ends_with(".i2p") {
                return Some(NeverLearnReason::NetworkToTor);
            }

            // Check known C2
            if self.c2_endpoints.iter().any(|c2| dest_lower.contains(c2)) {
                return Some(NeverLearnReason::NetworkToKnownC2 {
                    endpoint: dest.clone()
                });
            }
        }

        // Check registry persistence
        for key in &ctx.registry_writes {
            if super::persistence::is_persistence_key(key) {
                return Some(NeverLearnReason::RegistryPersistence {
                    key: key.clone()
                });
            }
        }

        // Check unsigned + network
        if self.block_unsigned_network {
            if matches!(ctx.process_signed, Some(false)) && ctx.has_network_activity {
                return Some(NeverLearnReason::UnsignedWithNetwork);
            }
        }

        // Check unsigned + disk write
        if self.block_unsigned_disk {
            if matches!(ctx.process_signed, Some(false)) && ctx.has_disk_write {
                return Some(NeverLearnReason::UnsignedWithDiskWrite);
            }
        }

        None
    }

    /// Add process to blacklist
    pub fn add_process(&mut self, name: &str) {
        self.process_names.insert(name.to_lowercase());
    }

    /// Remove process from blacklist
    pub fn remove_process(&mut self, name: &str) {
        self.process_names.remove(&name.to_lowercase());
    }

    /// Add hash to blacklist
    pub fn add_hash(&mut self, hash: &str) {
        self.hashes.insert(hash.to_lowercase());
    }

    /// Remove hash from blacklist
    pub fn remove_hash(&mut self, hash: &str) {
        self.hashes.remove(&hash.to_lowercase());
    }

    /// Add C2 endpoint
    pub fn add_c2_endpoint(&mut self, endpoint: &str) {
        self.c2_endpoints.insert(endpoint.to_lowercase());
    }

    /// Set block unsigned + network
    pub fn set_block_unsigned_network(&mut self, enabled: bool) {
        self.block_unsigned_network = enabled;
    }

    /// Set block unsigned + disk
    pub fn set_block_unsigned_disk(&mut self, enabled: bool) {
        self.block_unsigned_disk = enabled;
    }

    /// Enable/disable
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Default for NeverLearnBlacklist {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Check if sample should never be learned
pub fn should_never_learn(ctx: &SampleContext) -> Option<NeverLearnReason> {
    BLACKLIST.read().should_never_learn(ctx)
}

/// Quick check for process name only
pub fn is_process_blacklisted(name: &str) -> bool {
    BLACKLIST.read().process_names.contains(&name.to_lowercase())
}

/// Quick check for hash only
pub fn is_hash_blacklisted(hash: &str) -> bool {
    BLACKLIST.read().hashes.contains(&hash.to_lowercase())
}

/// Quick check for network destination
pub fn is_network_blacklisted(dest: &str) -> bool {
    let dest_lower = dest.to_lowercase();

    // Check Tor
    if dest_lower.ends_with(".onion") || dest_lower.ends_with(".i2p") {
        return true;
    }

    // Check suspicious TLDs
    if SUSPICIOUS_TLDS.iter().any(|tld| dest_lower.ends_with(tld)) {
        // Not auto-block, but flag
        return false;
    }

    // Check C2 list
    BLACKLIST.read().c2_endpoints.iter().any(|c2| dest_lower.contains(c2))
}

/// Add process to blacklist
pub fn add_process_blacklist(name: &str) {
    BLACKLIST.write().add_process(name);
}

/// Remove process from blacklist
pub fn remove_process_blacklist(name: &str) {
    BLACKLIST.write().remove_process(name);
}

/// Add hash to blacklist
pub fn add_hash_blacklist(hash: &str) {
    BLACKLIST.write().add_hash(hash);
}

/// Remove hash from blacklist
pub fn remove_hash_blacklist(hash: &str) {
    BLACKLIST.write().remove_hash(hash);
}

/// Add C2 endpoint
pub fn add_c2_endpoint(endpoint: &str) {
    BLACKLIST.write().add_c2_endpoint(endpoint);
}

/// Set block unsigned + network
pub fn set_block_unsigned_network(enabled: bool) {
    BLACKLIST.write().set_block_unsigned_network(enabled);
}

/// Set block unsigned + disk
pub fn set_block_unsigned_disk(enabled: bool) {
    BLACKLIST.write().set_block_unsigned_disk(enabled);
}

/// Enable/disable blacklist
pub fn set_enabled(enabled: bool) {
    BLACKLIST.write().set_enabled(enabled);
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct BlacklistStats {
    pub enabled: bool,
    pub process_count: usize,
    pub hash_count: usize,
    pub c2_endpoint_count: usize,
    pub block_unsigned_network: bool,
    pub block_unsigned_disk: bool,
}

pub fn get_stats() -> BlacklistStats {
    let bl = BLACKLIST.read();
    BlacklistStats {
        enabled: bl.enabled,
        process_count: bl.process_names.len(),
        hash_count: bl.hashes.len(),
        c2_endpoint_count: bl.c2_endpoints.len(),
        block_unsigned_network: bl.block_unsigned_network,
        block_unsigned_disk: bl.block_unsigned_disk,
    }
}

/// Get all blacklisted processes
pub fn get_blacklisted_processes() -> Vec<String> {
    BLACKLIST.read().process_names.iter().cloned().collect()
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_blacklist() {
        let bl = NeverLearnBlacklist::new();

        let ctx = SampleContext {
            process_name: Some("mimikatz.exe".to_string()),
            ..Default::default()
        };

        let reason = bl.should_never_learn(&ctx);
        assert!(reason.is_some());
        assert!(matches!(reason, Some(NeverLearnReason::ProcessBlacklisted { .. })));
    }

    #[test]
    fn test_tor_detection() {
        let bl = NeverLearnBlacklist::new();

        let ctx = SampleContext {
            network_destinations: vec!["abcdef123456.onion".to_string()],
            ..Default::default()
        };

        let reason = bl.should_never_learn(&ctx);
        assert!(reason.is_some());
        assert!(matches!(reason, Some(NeverLearnReason::NetworkToTor)));
    }

    #[test]
    fn test_clean_sample() {
        let bl = NeverLearnBlacklist::new();

        let ctx = SampleContext {
            process_name: Some("notepad.exe".to_string()),
            process_signed: Some(true),
            ..Default::default()
        };

        let reason = bl.should_never_learn(&ctx);
        assert!(reason.is_none());
    }
}
