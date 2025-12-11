//! VirusTotal Integration Module (Phase 4)
//!
//! Mục đích: Query VirusTotal API để kiểm tra file hash
//!
//! Features:
//! - Check file hash (SHA256, SHA1, MD5)
//! - Rate limiting (free tier: 4 req/min)
//! - Local caching to reduce API calls

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use sha2::{Sha256, Digest};

use super::types::{VTResult, VTError, VTApiResponse, ThreatLevel};

// ============================================================================
// CONSTANTS
// ============================================================================

const VT_API_BASE: &str = "https://www.virustotal.com/api/v3";
const FREE_TIER_RATE_LIMIT: u32 = 4; // requests per minute
const CACHE_MAX_SIZE: usize = 1000;
const CACHE_TTL_HOURS: i64 = 24;

// ============================================================================
// STATE
// ============================================================================

static VT_CLIENT: Lazy<RwLock<VTClient>> =
    Lazy::new(|| RwLock::new(VTClient::new()));

// ============================================================================
// VT CLIENT
// ============================================================================

pub struct VTClient {
    api_key: Option<String>,
    cache: HashMap<String, CachedResult>,
    last_request: Option<Instant>,
    requests_this_minute: u32,
    minute_start: Instant,
    enabled: bool,
}

struct CachedResult {
    result: VTResult,
    cached_at: i64,
}

impl VTClient {
    pub fn new() -> Self {
        Self {
            api_key: None,
            cache: HashMap::new(),
            last_request: None,
            requests_this_minute: 0,
            minute_start: Instant::now(),
            enabled: false,
        }
    }

    /// Set API key
    pub fn set_api_key(&mut self, key: &str) {
        if key.is_empty() {
            self.api_key = None;
            self.enabled = false;
        } else {
            self.api_key = Some(key.to_string());
            self.enabled = true;
        }
    }

    /// Check if client is configured
    pub fn is_configured(&self) -> bool {
        self.api_key.is_some() && self.enabled
    }

    /// Check rate limit
    fn check_rate_limit(&mut self) -> Result<(), VTError> {
        let now = Instant::now();

        // Reset counter if minute passed
        if now.duration_since(self.minute_start) >= Duration::from_secs(60) {
            self.minute_start = now;
            self.requests_this_minute = 0;
        }

        if self.requests_this_minute >= FREE_TIER_RATE_LIMIT {
            let wait_time = 60 - now.duration_since(self.minute_start).as_secs();
            return Err(VTError::RateLimited { retry_after: wait_time });
        }

        Ok(())
    }

    /// Get from cache
    fn get_cached(&self, hash: &str) -> Option<VTResult> {
        let hash_lower = hash.to_lowercase();

        if let Some(cached) = self.cache.get(&hash_lower) {
            let now = chrono::Utc::now().timestamp();
            let age_hours = (now - cached.cached_at) / 3600;

            if age_hours < CACHE_TTL_HOURS {
                return Some(cached.result.clone());
            }
        }

        None
    }

    /// Add to cache
    fn cache_result(&mut self, hash: &str, result: VTResult) {
        let hash_lower = hash.to_lowercase();

        // Evict if full
        if self.cache.len() >= CACHE_MAX_SIZE {
            // Remove oldest entries
            let mut entries: Vec<_> = self.cache.iter()
                .map(|(k, v)| (k.clone(), v.cached_at))
                .collect();
            entries.sort_by(|a, b| a.1.cmp(&b.1));

            for (key, _) in entries.into_iter().take(CACHE_MAX_SIZE / 10) {
                self.cache.remove(&key);
            }
        }

        self.cache.insert(hash_lower, CachedResult {
            result,
            cached_at: chrono::Utc::now().timestamp(),
        });
    }

    /// Query VT API for hash (blocking)
    pub fn check_hash_sync(&mut self, hash: &str) -> Result<VTResult, VTError> {
        // Check if configured
        if !self.is_configured() {
            return Err(VTError::Other {
                message: "VirusTotal API key not configured".to_string()
            });
        }

        // Check cache first
        if let Some(cached) = self.get_cached(hash) {
            return Ok(VTResult { is_cached: true, ..cached });
        }

        // Check rate limit
        self.check_rate_limit()?;

        let api_key = self.api_key.clone().unwrap();
        let url = format!("{}/files/{}", VT_API_BASE, hash);

        // Make request (blocking)
        let response = ureq::get(&url)
            .set("x-apikey", &api_key)
            .call();

        self.requests_this_minute += 1;
        self.last_request = Some(Instant::now());

        match response {
            Ok(resp) => {
                if resp.status() == 404 {
                    return Err(VTError::NotFound);
                }

                let body = resp.into_string()
                    .map_err(|e| VTError::ParseError { message: e.to_string() })?;

                let api_response: VTApiResponse = serde_json::from_str(&body)
                    .map_err(|e| VTError::ParseError { message: e.to_string() })?;

                let result = parse_api_response(api_response);

                // Cache result
                self.cache_result(hash, result.clone());

                Ok(result)
            }
            Err(ureq::Error::Status(401, _)) => {
                Err(VTError::InvalidApiKey)
            }
            Err(ureq::Error::Status(429, _)) => {
                Err(VTError::RateLimited { retry_after: 60 })
            }
            Err(ureq::Error::Status(404, _)) => {
                Err(VTError::NotFound)
            }
            Err(e) => {
                Err(VTError::NetworkError { message: e.to_string() })
            }
        }
    }

    /// Get cache stats
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.cache.len(), CACHE_MAX_SIZE)
    }

    /// Clear cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

impl Default for VTClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PARSE RESPONSE
// ============================================================================

fn parse_api_response(resp: VTApiResponse) -> VTResult {
    let attrs = resp.data.attributes;
    let stats = attrs.last_analysis_stats.unwrap_or_else(|| super::types::VTApiStats {
        malicious: 0,
        suspicious: 0,
        undetected: 0,
        harmless: 0,
        timeout: 0,
        type_unsupported: Some(0),
    });

    // Extract detection names
    let mut detection_names = Vec::new();
    if let Some(results) = attrs.last_analysis_results {
        for (_, engine_result) in results {
            if engine_result.category == "malicious" || engine_result.category == "suspicious" {
                if let Some(name) = engine_result.result {
                    detection_names.push(name);
                }
            }
        }
    }

    VTResult {
        sha256: attrs.sha256.unwrap_or_else(|| resp.data.id),
        sha1: attrs.sha1,
        md5: attrs.md5,
        file_name: attrs.meaningful_name,
        file_size: attrs.size,
        file_type: attrs.type_description,
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        total_engines: stats.malicious + stats.suspicious + stats.undetected + stats.harmless,
        first_seen: attrs.first_submission_date,
        last_scan: attrs.last_analysis_date,
        detection_names,
        is_cached: false,
        cached_at: None,
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Configure VT API key
pub fn set_api_key(key: &str) {
    VT_CLIENT.write().set_api_key(key);
}

/// Check if VT is configured
pub fn is_configured() -> bool {
    VT_CLIENT.read().is_configured()
}

/// Check hash against VirusTotal
pub fn check_hash(hash: &str) -> Result<VTResult, VTError> {
    VT_CLIENT.write().check_hash_sync(hash)
}

/// Check file against VirusTotal (calculates SHA256 first)
pub fn check_file(path: &Path) -> Result<VTResult, VTError> {
    // Calculate SHA256
    let hash = calculate_sha256(path)?;
    check_hash(&hash)
}

/// Get cached result without API call
pub fn get_cached_result(hash: &str) -> Option<VTResult> {
    VT_CLIENT.read().get_cached(hash)
}

/// Clear cache
pub fn clear_cache() {
    VT_CLIENT.write().clear_cache();
}

/// Get cache stats
pub fn get_cache_stats() -> (usize, usize) {
    VT_CLIENT.read().cache_stats()
}

// ============================================================================
// UTILITIES
// ============================================================================

/// Calculate SHA256 of a file
fn calculate_sha256(path: &Path) -> Result<String, VTError> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)
        .map_err(|e| VTError::Other { message: format!("Cannot open file: {}", e) })?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)
            .map_err(|e| VTError::Other { message: format!("Cannot read file: {}", e) })?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct VTClientStats {
    pub configured: bool,
    pub cache_size: usize,
    pub cache_max: usize,
    pub requests_this_minute: u32,
}

pub fn get_stats() -> VTClientStats {
    let client = VT_CLIENT.read();
    let (cache_size, cache_max) = client.cache_stats();

    VTClientStats {
        configured: client.is_configured(),
        cache_size,
        cache_max,
        requests_this_minute: client.requests_this_minute,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_ratio() {
        let result = VTResult {
            sha256: "test".to_string(),
            sha1: None,
            md5: None,
            file_name: None,
            file_size: None,
            file_type: None,
            malicious: 10,
            suspicious: 5,
            total_engines: 60,
            first_seen: None,
            last_scan: None,
            detection_names: vec![],
            is_cached: false,
            cached_at: None,
        };

        assert!((result.detection_ratio() - 0.25).abs() < 0.01);
        assert_eq!(result.threat_level(), ThreatLevel::High);
    }

    #[test]
    fn test_is_malware() {
        let result = VTResult {
            sha256: "test".to_string(),
            sha1: None,
            md5: None,
            file_name: None,
            file_size: None,
            file_type: None,
            malicious: 30,
            suspicious: 0,
            total_engines: 60,
            first_seen: None,
            last_scan: None,
            detection_names: vec![],
            is_cached: false,
            cached_at: None,
        };

        assert!(result.is_malware());
    }
}
