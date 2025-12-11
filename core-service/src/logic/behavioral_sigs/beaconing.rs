//! Network Beaconing Detection Module (Phase 3)
//!
//! Mục đích: Phát hiện kết nối định kỳ đến cùng một endpoint (C2 communication)
//!
//! Beaconing là dấu hiệu của malware C2:
//! - Kết nối đến cùng endpoint nhiều lần
//! - Intervals đều đặn (low jitter)
//! - Thường xảy ra vào ban đêm

use std::collections::HashMap;
use std::net::IpAddr;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use chrono::Utc;

use super::types::{BeaconAlert, BeaconSeverity};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Minimum samples needed to detect beaconing
const MIN_SAMPLES: usize = 5;

/// Maximum jitter percentage to be considered beaconing
const DEFAULT_JITTER_THRESHOLD: f32 = 0.15; // 15%

/// Known C2 ports
const SUSPICIOUS_PORTS: &[u16] = &[
    4444,   // Metasploit default
    5555,   // Common C2
    8080,   // HTTP alt
    8443,   // HTTPS alt
    9999,   // Common backdoor
    1234,   // Simple backdoor
    31337,  // Elite/leet
    12345,  // NetBus
];

/// Known C2 intervals (seconds)
const KNOWN_C2_INTERVALS: &[(f32, f32)] = &[
    (60.0, 5.0),    // 1 minute
    (300.0, 15.0),  // 5 minutes
    (600.0, 30.0),  // 10 minutes
    (900.0, 45.0),  // 15 minutes
    (3600.0, 180.0), // 1 hour
];

// ============================================================================
// STATE
// ============================================================================

static DETECTOR: Lazy<RwLock<BeaconingDetector>> =
    Lazy::new(|| RwLock::new(BeaconingDetector::new()));

// ============================================================================
// BEACONING DETECTOR
// ============================================================================

pub struct BeaconingDetector {
    /// endpoint -> (timestamps, process_info)
    connections: HashMap<String, ConnectionHistory>,
    jitter_threshold: f32,
    min_samples: usize,
}

struct ConnectionHistory {
    timestamps: Vec<i64>,
    process_name: Option<String>,
    process_pid: Option<u32>,
    ip: Option<IpAddr>,
    port: Option<u16>,
}

impl BeaconingDetector {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            jitter_threshold: DEFAULT_JITTER_THRESHOLD,
            min_samples: MIN_SAMPLES,
        }
    }

    /// Record a new connection
    pub fn record_connection(&mut self, endpoint: &str, ip: Option<IpAddr>, port: Option<u16>,
                             process_name: Option<&str>, process_pid: Option<u32>) {
        let now = Utc::now().timestamp();

        let history = self.connections.entry(endpoint.to_string()).or_insert_with(|| {
            ConnectionHistory {
                timestamps: Vec::new(),
                process_name: process_name.map(|s| s.to_string()),
                process_pid,
                ip,
                port,
            }
        });

        history.timestamps.push(now);

        // Update process info if provided
        if let Some(name) = process_name {
            history.process_name = Some(name.to_string());
        }
        if let Some(pid) = process_pid {
            history.process_pid = Some(pid);
        }
        if ip.is_some() {
            history.ip = ip;
        }
        if port.is_some() {
            history.port = port;
        }

        // Keep only last 100 timestamps
        if history.timestamps.len() > 100 {
            history.timestamps.drain(0..history.timestamps.len() - 100);
        }
    }

    /// Check if endpoint shows beaconing behavior
    pub fn check_endpoint(&self, endpoint: &str) -> Option<BeaconAlert> {
        let history = self.connections.get(endpoint)?;

        if history.timestamps.len() < self.min_samples {
            return None;
        }

        // Calculate intervals
        let intervals: Vec<f32> = history.timestamps
            .windows(2)
            .map(|w| (w[1] - w[0]) as f32)
            .collect();

        if intervals.is_empty() {
            return None;
        }

        let mean_interval = intervals.iter().sum::<f32>() / intervals.len() as f32;

        // Calculate variance and jitter
        let variance = intervals.iter()
            .map(|i| (i - mean_interval).powi(2))
            .sum::<f32>() / intervals.len() as f32;

        let std_dev = variance.sqrt();
        let jitter = if mean_interval > 0.0 {
            std_dev / mean_interval
        } else {
            1.0
        };

        // Check if it's beaconing
        if jitter < self.jitter_threshold {
            let severity = self.calculate_severity(endpoint, mean_interval, jitter, history.port);

            Some(BeaconAlert {
                endpoint: endpoint.to_string(),
                ip: history.ip,
                port: history.port,
                interval_seconds: mean_interval,
                jitter_percent: jitter * 100.0,
                sample_count: history.timestamps.len(),
                process_name: history.process_name.clone(),
                process_pid: history.process_pid,
                first_seen: *history.timestamps.first().unwrap_or(&0),
                last_seen: *history.timestamps.last().unwrap_or(&0),
                severity,
            })
        } else {
            None
        }
    }

    /// Calculate severity based on various factors
    fn calculate_severity(&self, endpoint: &str, interval: f32, jitter: f32, port: Option<u16>) -> BeaconSeverity {
        let mut score = 0;

        // Very low jitter = more suspicious
        if jitter < 0.05 {
            score += 3;
        } else if jitter < 0.10 {
            score += 2;
        } else {
            score += 1;
        }

        // Suspicious port
        if let Some(port) = port {
            if SUSPICIOUS_PORTS.contains(&port) {
                score += 2;
            }
        }

        // Known C2 interval
        for (known_interval, tolerance) in KNOWN_C2_INTERVALS {
            if (interval - known_interval).abs() < *tolerance {
                score += 2;
                break;
            }
        }

        // Non-standard TLD or IP
        if endpoint.contains(".onion") || endpoint.contains(".bit") {
            score += 4; // Tor/I2P
        } else if endpoint.parse::<IpAddr>().is_ok() {
            score += 1; // Direct IP connection
        }

        // Night time connections (TODO: implement)

        match score {
            0..=2 => BeaconSeverity::Low,
            3..=4 => BeaconSeverity::Medium,
            5..=6 => BeaconSeverity::High,
            _ => BeaconSeverity::Critical,
        }
    }

    /// Get all detected beacons
    pub fn get_all_beacons(&self) -> Vec<BeaconAlert> {
        self.connections.keys()
            .filter_map(|endpoint| self.check_endpoint(endpoint))
            .collect()
    }

    /// Clear history for an endpoint
    pub fn clear_endpoint(&mut self, endpoint: &str) {
        self.connections.remove(endpoint);
    }

    /// Clear all history
    pub fn clear_all(&mut self) {
        self.connections.clear();
    }
}

impl Default for BeaconingDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Record a network connection
pub fn record_connection(endpoint: &str, ip: Option<IpAddr>, port: Option<u16>,
                        process_name: Option<&str>, process_pid: Option<u32>) {
    DETECTOR.write().record_connection(endpoint, ip, port, process_name, process_pid);
}

/// Check if an endpoint shows beaconing behavior
pub fn check_beaconing(endpoint: &str) -> Option<BeaconAlert> {
    DETECTOR.read().check_endpoint(endpoint)
}

/// Get all detected beacons
pub fn get_all_beacons() -> Vec<BeaconAlert> {
    DETECTOR.read().get_all_beacons()
}

/// Get beacons above a severity threshold
pub fn get_beacons_by_severity(min_severity: BeaconSeverity) -> Vec<BeaconAlert> {
    let all = get_all_beacons();
    all.into_iter()
        .filter(|b| b.severity as u8 >= min_severity as u8)
        .collect()
}

/// Clear history
pub fn clear_all() {
    DETECTOR.write().clear_all();
}

/// Set jitter threshold
pub fn set_jitter_threshold(threshold: f32) {
    DETECTOR.write().jitter_threshold = threshold.clamp(0.01, 1.0);
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct BeaconingStats {
    pub total_endpoints_tracked: usize,
    pub possible_beacons: usize,
    pub high_severity_beacons: usize,
    pub endpoints_with_most_connections: Vec<(String, usize)>,
}

pub fn get_stats() -> BeaconingStats {
    let detector = DETECTOR.read();
    let beacons = detector.get_all_beacons();

    let mut endpoints: Vec<_> = detector.connections.iter()
        .map(|(e, h)| (e.clone(), h.timestamps.len()))
        .collect();
    endpoints.sort_by(|a, b| b.1.cmp(&a.1));
    endpoints.truncate(10);

    BeaconingStats {
        total_endpoints_tracked: detector.connections.len(),
        possible_beacons: beacons.len(),
        high_severity_beacons: beacons.iter()
            .filter(|b| b.severity as u8 >= BeaconSeverity::High as u8)
            .count(),
        endpoints_with_most_connections: endpoints,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beaconing_detection() {
        let mut detector = BeaconingDetector::new();

        // Simulate regular connections every 60 seconds
        let base_time = 1000000i64;
        for i in 0..10 {
            detector.connections.entry("evil.com".to_string()).or_insert_with(|| {
                ConnectionHistory {
                    timestamps: Vec::new(),
                    process_name: Some("malware.exe".to_string()),
                    process_pid: Some(1234),
                    ip: None,
                    port: Some(4444),
                }
            }).timestamps.push(base_time + i * 60);
        }

        let alert = detector.check_endpoint("evil.com");
        assert!(alert.is_some());

        let alert = alert.unwrap();
        assert!((alert.interval_seconds - 60.0).abs() < 1.0);
        assert!(alert.jitter_percent < 5.0);
    }

    #[test]
    fn test_no_beaconing_for_random_intervals() {
        let mut detector = BeaconingDetector::new();

        // Random intervals
        let timestamps = vec![1000, 1050, 1200, 1230, 1500, 1510, 2000, 2500, 3000, 3100];

        detector.connections.insert("random.com".to_string(), ConnectionHistory {
            timestamps,
            process_name: None,
            process_pid: None,
            ip: None,
            port: None,
        });

        let alert = detector.check_endpoint("random.com");
        // Should not detect beaconing due to high jitter
        assert!(alert.is_none() || alert.unwrap().jitter_percent > 15.0);
    }
}
