//! Threat Feed Module (Phase 4)
//!
//! Mục đích: Sync known-bad indicators từ các threat intelligence feeds
//!
//! Feeds supported:
//! - URLhaus (abuse.ch)
//! - Emerging Threats
//! - Custom feeds

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use chrono::Utc;

use super::types::{ThreatIndicator, IndicatorType, ThreatLevel};

// ============================================================================
// THREAT FEED SOURCES
// ============================================================================

/// Available threat feed sources
pub const FEED_SOURCES: &[FeedSource] = &[
    FeedSource {
        name: "URLhaus",
        url: "https://urlhaus.abuse.ch/downloads/text/",
        indicator_type: IndicatorType::Url,
        enabled: true,
    },
    FeedSource {
        name: "Emerging Threats - Compromised IPs",
        url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        indicator_type: IndicatorType::IPv4,
        enabled: true,
    },
    FeedSource {
        name: "Feodo Tracker - Botnet C2",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        indicator_type: IndicatorType::IPv4,
        enabled: true,
    },
];

#[derive(Debug, Clone)]
pub struct FeedSource {
    pub name: &'static str,
    pub url: &'static str,
    pub indicator_type: IndicatorType,
    pub enabled: bool,
}

// ============================================================================
// STATE
// ============================================================================

static THREAT_FEED: Lazy<RwLock<ThreatFeed>> =
    Lazy::new(|| RwLock::new(ThreatFeed::new()));

// ============================================================================
// THREAT FEED
// ============================================================================

pub struct ThreatFeed {
    /// Malicious IPs
    malicious_ips: HashSet<IpAddr>,

    /// Malicious domains
    malicious_domains: HashSet<String>,

    /// Malicious URLs
    malicious_urls: HashSet<String>,

    /// Malicious hashes
    malicious_hashes: HashSet<String>,

    /// Custom indicators with full metadata
    custom_indicators: Vec<ThreatIndicator>,

    /// Last sync time
    last_sync: Option<i64>,

    /// Sync in progress
    syncing: bool,

    /// Enabled
    enabled: bool,
}

impl ThreatFeed {
    pub fn new() -> Self {
        Self {
            malicious_ips: HashSet::new(),
            malicious_domains: HashSet::new(),
            malicious_urls: HashSet::new(),
            malicious_hashes: HashSet::new(),
            custom_indicators: Vec::new(),
            last_sync: None,
            syncing: false,
            enabled: true,
        }
    }

    /// Sync all enabled feeds (blocking)
    pub fn sync_all(&mut self) -> Result<SyncResult, String> {
        if self.syncing {
            return Err("Sync already in progress".to_string());
        }

        self.syncing = true;
        let mut result = SyncResult {
            success: true,
            feeds_synced: 0,
            total_indicators: 0,
            errors: Vec::new(),
        };

        for source in FEED_SOURCES {
            if !source.enabled {
                continue;
            }

            match self.sync_feed(source) {
                Ok(count) => {
                    result.feeds_synced += 1;
                    result.total_indicators += count;
                    log::info!("Synced {} indicators from {}", count, source.name);
                }
                Err(e) => {
                    result.errors.push(format!("{}: {}", source.name, e));
                    log::warn!("Failed to sync {}: {}", source.name, e);
                }
            }
        }

        self.last_sync = Some(Utc::now().timestamp());
        self.syncing = false;

        if !result.errors.is_empty() {
            result.success = result.feeds_synced > 0;
        }

        Ok(result)
    }

    /// Sync a single feed
    fn sync_feed(&mut self, source: &FeedSource) -> Result<usize, String> {
        // Fetch content (blocking)
        let response = ureq::get(source.url)
            .timeout(std::time::Duration::from_secs(30))
            .call()
            .map_err(|e| e.to_string())?;

        let content = response.into_string()
            .map_err(|e| e.to_string())?;

        let count = self.parse_feed(&content, source);
        Ok(count)
    }

    /// Parse feed content
    fn parse_feed(&mut self, content: &str, source: &FeedSource) -> usize {
        let mut count = 0;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            match source.indicator_type {
                IndicatorType::IPv4 | IndicatorType::IPv6 => {
                    // Try to parse as IP
                    if let Ok(ip) = IpAddr::from_str(line) {
                        self.malicious_ips.insert(ip);
                        count += 1;
                    }
                }
                IndicatorType::Domain => {
                    // Just add as domain
                    let domain = line.to_lowercase();
                    if !domain.is_empty() && domain.contains('.') {
                        self.malicious_domains.insert(domain);
                        count += 1;
                    }
                }
                IndicatorType::Url => {
                    // Add as URL
                    let url = line.to_lowercase();
                    if url.starts_with("http://") || url.starts_with("https://") {
                        self.malicious_urls.insert(url.clone());

                        // Also extract domain
                        if let Some(domain) = extract_domain(&url) {
                            self.malicious_domains.insert(domain);
                        }
                        count += 1;
                    }
                }
                IndicatorType::Sha256 | IndicatorType::Sha1 | IndicatorType::Md5 => {
                    // Add as hash
                    let hash = line.to_lowercase();
                    if is_valid_hash(&hash) {
                        self.malicious_hashes.insert(hash);
                        count += 1;
                    }
                }
                _ => {}
            }
        }

        count
    }

    /// Check if IP is malicious
    pub fn is_malicious_ip(&self, ip: &IpAddr) -> bool {
        self.malicious_ips.contains(ip)
    }

    /// Check if domain is malicious
    pub fn is_malicious_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Check exact match
        if self.malicious_domains.contains(&domain_lower) {
            return true;
        }

        // Check parent domains
        let parts: Vec<&str> = domain_lower.split('.').collect();
        for i in 0..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if self.malicious_domains.contains(&parent) {
                return true;
            }
        }

        false
    }

    /// Check if hash is malicious
    pub fn is_malicious_hash(&self, hash: &str) -> bool {
        self.malicious_hashes.contains(&hash.to_lowercase())
    }

    /// Check if URL is malicious
    pub fn is_malicious_url(&self, url: &str) -> bool {
        self.malicious_urls.contains(&url.to_lowercase())
    }

    /// Add custom indicator
    pub fn add_indicator(&mut self, indicator: ThreatIndicator) {
        // Add to quick lookup sets
        match indicator.indicator_type {
            IndicatorType::IPv4 | IndicatorType::IPv6 => {
                if let Ok(ip) = IpAddr::from_str(&indicator.value) {
                    self.malicious_ips.insert(ip);
                }
            }
            IndicatorType::Domain => {
                self.malicious_domains.insert(indicator.value.to_lowercase());
            }
            IndicatorType::Url => {
                self.malicious_urls.insert(indicator.value.to_lowercase());
            }
            IndicatorType::Sha256 | IndicatorType::Sha1 | IndicatorType::Md5 => {
                self.malicious_hashes.insert(indicator.value.to_lowercase());
            }
            _ => {}
        }

        self.custom_indicators.push(indicator);
    }

    /// Get stats
    pub fn stats(&self) -> FeedStats {
        FeedStats {
            total_ips: self.malicious_ips.len(),
            total_domains: self.malicious_domains.len(),
            total_urls: self.malicious_urls.len(),
            total_hashes: self.malicious_hashes.len(),
            custom_indicators: self.custom_indicators.len(),
            last_sync: self.last_sync,
            enabled: self.enabled,
        }
    }

    /// Clear all data
    pub fn clear(&mut self) {
        self.malicious_ips.clear();
        self.malicious_domains.clear();
        self.malicious_urls.clear();
        self.malicious_hashes.clear();
        self.custom_indicators.clear();
        self.last_sync = None;
    }
}

impl Default for ThreatFeed {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SYNC RESULT
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncResult {
    pub success: bool,
    pub feeds_synced: usize,
    pub total_indicators: usize,
    pub errors: Vec<String>,
}

// ============================================================================
// FEED STATS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct FeedStats {
    pub total_ips: usize,
    pub total_domains: usize,
    pub total_urls: usize,
    pub total_hashes: usize,
    pub custom_indicators: usize,
    pub last_sync: Option<i64>,
    pub enabled: bool,
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Sync all threat feeds
pub fn sync_feeds() -> Result<SyncResult, String> {
    THREAT_FEED.write().sync_all()
}

/// Check if IP is malicious
pub fn is_malicious_ip(ip: &str) -> bool {
    if let Ok(ip_addr) = IpAddr::from_str(ip) {
        THREAT_FEED.read().is_malicious_ip(&ip_addr)
    } else {
        false
    }
}

/// Check if domain is malicious
pub fn is_malicious_domain(domain: &str) -> bool {
    THREAT_FEED.read().is_malicious_domain(domain)
}

/// Check if hash is malicious
pub fn is_malicious_hash(hash: &str) -> bool {
    THREAT_FEED.read().is_malicious_hash(hash)
}

/// Check if URL is malicious
pub fn is_malicious_url(url: &str) -> bool {
    THREAT_FEED.read().is_malicious_url(url)
}

/// Add custom indicator
pub fn add_indicator(indicator: ThreatIndicator) {
    THREAT_FEED.write().add_indicator(indicator);
}

/// Get stats
pub fn get_stats() -> FeedStats {
    THREAT_FEED.read().stats()
}

/// Clear all data
pub fn clear() {
    THREAT_FEED.write().clear();
}

/// Enable/disable feeds
pub fn set_enabled(enabled: bool) {
    THREAT_FEED.write().enabled = enabled;
}

// ============================================================================
// UTILITIES
// ============================================================================

/// Extract domain from URL
fn extract_domain(url: &str) -> Option<String> {
    let url = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;

    let domain = url.split('/').next()?;
    let domain = domain.split(':').next()?; // Remove port

    Some(domain.to_lowercase())
}

/// Check if string is a valid hash
fn is_valid_hash(s: &str) -> bool {
    let len = s.len();

    // MD5 = 32, SHA1 = 40, SHA256 = 64
    if len != 32 && len != 40 && len != 64 {
        return false;
    }

    s.chars().all(|c| c.is_ascii_hexdigit())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("https://evil.com/malware"), Some("evil.com".to_string()));
        assert_eq!(extract_domain("http://bad.site:8080/path"), Some("bad.site".to_string()));
    }

    #[test]
    fn test_is_valid_hash() {
        assert!(is_valid_hash("d41d8cd98f00b204e9800998ecf8427e")); // MD5
        assert!(is_valid_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")); // SHA1
        assert!(is_valid_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")); // SHA256
        assert!(!is_valid_hash("invalid"));
    }

    #[test]
    fn test_domain_matching() {
        let mut feed = ThreatFeed::new();
        feed.malicious_domains.insert("evil.com".to_string());

        assert!(feed.is_malicious_domain("evil.com"));
        assert!(feed.is_malicious_domain("sub.evil.com"));
        assert!(!feed.is_malicious_domain("notevil.com"));
    }
}
