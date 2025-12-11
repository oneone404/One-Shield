//! Memory Scanning - Detect Shellcode Patterns in Memory/Files
//!
//! Scans binary data for known shellcode signatures including:
//! - API resolution patterns (GetProcAddress, LoadLibrary)
//! - Metasploit/Cobalt Strike signatures
//! - Socket operations (WSAStartup, connect, bind)
//! - NOP sleds and egg hunters
//!
//! # Usage
//! ```ignore
//! use crate::logic::advanced_detection::memory;
//!
//! memory::init();
//!
//! // Scan binary data
//! let results = memory::scan_buffer(&data, "test.exe");
//! for result in results {
//!     if result.is_critical() {
//!         println!("Shellcode detected: {}", result.shellcode_type.as_str());
//!     }
//! }
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use parking_lot::Mutex;
use once_cell::sync::Lazy;

use super::memory_types::{ShellcodeType, MemoryScanResult, MemoryScanStats, MemoryScanError};

// ============================================================================
// GLOBAL STATE
// ============================================================================

static STATS: Lazy<Mutex<MemoryScanStats>> = Lazy::new(|| Mutex::new(MemoryScanStats::default()));
static INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// SHELLCODE PATTERNS DATABASE
// ============================================================================

/// Shellcode pattern definition
struct ShellcodePattern {
    name: &'static str,
    pattern: &'static [u8],
    mask: Option<&'static [u8]>,  // None = exact match, Some = mask (0xFF = must match, 0x00 = wildcard)
    shellcode_type: ShellcodeType,
    confidence: u8,
}

/// Known shellcode byte patterns
const PATTERNS: &[ShellcodePattern] = &[
    // ========== API Resolution ==========
    // GetProcAddress pattern (common in shellcode)
    ShellcodePattern {
        name: "GetProcAddress_hash",
        pattern: &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],  // mov eax, fs:[0x30] (PEB access)
        mask: None,
        shellcode_type: ShellcodeType::ApiResolution,
        confidence: 85,
    },
    // mov eax, fs:[0x30] - 64-bit variant
    ShellcodePattern {
        name: "PEB_access_x64",
        pattern: &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
        mask: None,
        shellcode_type: ShellcodeType::ApiResolution,
        confidence: 85,
    },
    // GetProcAddress string hash resolution
    ShellcodePattern {
        name: "API_hash_loop",
        pattern: &[0xC1, 0xCF, 0x0D, 0x01, 0xC7],  // ror edi, 0x0d; add edi, eax
        mask: None,
        shellcode_type: ShellcodeType::ApiResolution,
        confidence: 90,
    },

    // ========== Metasploit ==========
    // MSF reverse TCP
    ShellcodePattern {
        name: "MSF_reverse_tcp",
        pattern: &[0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00],  // cld; call $+0x87
        mask: None,
        shellcode_type: ShellcodeType::Metasploit,
        confidence: 95,
    },
    // MSF bind TCP
    ShellcodePattern {
        name: "MSF_bind_tcp",
        pattern: &[0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00],
        mask: None,
        shellcode_type: ShellcodeType::Metasploit,
        confidence: 95,
    },
    // Meterpreter stage
    ShellcodePattern {
        name: "Meterpreter_stage",
        pattern: &[0x4D, 0x5A, 0x52, 0x45],  // "MZRE" - Meterpreter reflective loader
        mask: None,
        shellcode_type: ShellcodeType::Metasploit,
        confidence: 90,
    },

    // ========== Cobalt Strike ==========
    // CS beacon
    ShellcodePattern {
        name: "CS_beacon_start",
        pattern: &[0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8],  // cld; and rsp, -0x10; call
        mask: None,
        shellcode_type: ShellcodeType::CobaltStrike,
        confidence: 90,
    },
    // CS sleep mask
    ShellcodePattern {
        name: "CS_sleep_mask",
        pattern: &[0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D],
        mask: None,
        shellcode_type: ShellcodeType::CobaltStrike,
        confidence: 85,
    },

    // ========== Reverse Shell ==========
    // WSAStartup pattern
    ShellcodePattern {
        name: "WSAStartup",
        pattern: &[0x66, 0xB8, 0x02, 0x02],  // mov ax, 0x202 (Winsock 2.2)
        mask: None,
        shellcode_type: ShellcodeType::SocketCode,
        confidence: 70,
    },
    // socket() call setup
    ShellcodePattern {
        name: "socket_call",
        pattern: &[0x6A, 0x01, 0x6A, 0x02],  // push 1; push 2 (SOCK_STREAM, AF_INET)
        mask: None,
        shellcode_type: ShellcodeType::SocketCode,
        confidence: 75,
    },

    // ========== NOP Sleds ==========
    ShellcodePattern {
        name: "NOP_sled_8",
        pattern: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        mask: None,
        shellcode_type: ShellcodeType::NopSled,
        confidence: 60,
    },
    ShellcodePattern {
        name: "NOP_sled_16",
        pattern: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                   0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        mask: None,
        shellcode_type: ShellcodeType::NopSled,
        confidence: 80,
    },

    // ========== Egg Hunters ==========
    // NtAccessCheckAndAuditAlarm egg hunter
    ShellcodePattern {
        name: "Egg_hunter_ntaccess",
        pattern: &[0x66, 0x81, 0xCA, 0xFF, 0x0F],  // or dx, 0x0fff
        mask: None,
        shellcode_type: ShellcodeType::EggHunter,
        confidence: 85,
    },
    // SEH egg hunter
    ShellcodePattern {
        name: "Egg_hunter_seh",
        pattern: &[0xEB, 0x21, 0x5A, 0x6A],  // jmp; pop edx; push
        mask: None,
        shellcode_type: ShellcodeType::EggHunter,
        confidence: 80,
    },

    // ========== Encoded Shellcode ==========
    // XOR decoder stub
    ShellcodePattern {
        name: "XOR_decoder",
        pattern: &[0xEB, 0x0E, 0x5B, 0x4B, 0x33, 0xC9],  // jmp; pop ebx; dec ebx; xor ecx,ecx
        mask: None,
        shellcode_type: ShellcodeType::Encoded,
        confidence: 75,
    },
    // Alpha-numeric stub
    ShellcodePattern {
        name: "Alphanumeric_stub",
        pattern: &[0x56, 0x57, 0x58, 0x59],  // push regs (common alpha pattern)
        mask: None,
        shellcode_type: ShellcodeType::Encoded,
        confidence: 50,
    },

    // ========== Generic Shellcode ==========
    // Call/pop (shellcode locator)
    ShellcodePattern {
        name: "Call_pop",
        pattern: &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58],  // call $+5; pop eax
        mask: None,
        shellcode_type: ShellcodeType::Generic,
        confidence: 80,
    },
    ShellcodePattern {
        name: "Call_pop_ebx",
        pattern: &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B],  // call $+5; pop ebx
        mask: None,
        shellcode_type: ShellcodeType::Generic,
        confidence: 80,
    },
];

// ============================================================================
// SCANNER
// ============================================================================

/// Memory Scanner for shellcode detection
pub struct MemoryScanner {
    results: Vec<MemoryScanResult>,
    max_results: usize,
}

impl MemoryScanner {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            max_results: 1000,
        }
    }

    /// Scan a buffer for shellcode patterns
    pub fn scan_buffer(&mut self, data: &[u8], source_name: &str) -> Vec<MemoryScanResult> {
        let start = Instant::now();
        let mut results = Vec::new();

        for pattern in PATTERNS {
            for (offset, _) in data.windows(pattern.pattern.len())
                .enumerate()
                .filter(|(_, window)| {
                    if let Some(mask) = pattern.mask {
                        window.iter().zip(pattern.pattern.iter()).zip(mask.iter())
                            .all(|((w, p), m)| *m == 0 || *w == *p)
                    } else {
                        *window == pattern.pattern
                    }
                })
            {
                let result = MemoryScanResult::new(
                    0,  // PID 0 for buffer scan
                    source_name,
                    pattern.shellcode_type,
                    pattern.confidence,
                    offset,
                    pattern.name,
                    pattern.pattern.len(),
                );

                results.push(result.clone());
                self.results.push(result);

                // Trim stored results
                if self.results.len() > self.max_results {
                    self.results.remove(0);
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        // Update stats
        update_stats(|s| {
            s.total_scans += 1;
            s.bytes_scanned += data.len() as u64;
            s.detections += results.len() as u64;
            s.critical_detections += results.iter().filter(|r| r.is_critical()).count() as u64;
            s.avg_scan_time_ms = (s.avg_scan_time_ms * (s.total_scans - 1) as f64
                + duration_ms as f64) / s.total_scans as f64;
        });

        if !results.is_empty() {
            log::warn!(
                "Shellcode detected in {}: {} patterns found",
                source_name, results.len()
            );
        }

        results
    }

    /// Scan a file for shellcode patterns
    pub fn scan_file(&mut self, path: &std::path::Path) -> Result<Vec<MemoryScanResult>, MemoryScanError> {
        let data = std::fs::read(path).map_err(|e| MemoryScanError::ScanFailed {
            reason: format!("Failed to read file: {}", e),
        })?;

        let name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        Ok(self.scan_buffer(&data, name))
    }

    /// Get recent scan results
    pub fn get_recent_results(&self, limit: usize) -> Vec<MemoryScanResult> {
        let start = if self.results.len() > limit {
            self.results.len() - limit
        } else {
            0
        };
        self.results[start..].to_vec()
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GLOBAL INSTANCE
// ============================================================================

static SCANNER: Lazy<Mutex<MemoryScanner>> = Lazy::new(|| Mutex::new(MemoryScanner::new()));

// ============================================================================
// PUBLIC API
// ============================================================================

/// Initialize memory scanner
pub fn init() {
    if INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    INITIALIZED.store(true, Ordering::SeqCst);
    log::info!("Memory scanner initialized ({} patterns)", PATTERNS.len());
}

/// Check if initialized
pub fn is_available() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

/// Scan a buffer for shellcode
pub fn scan_buffer(data: &[u8], source_name: &str) -> Vec<MemoryScanResult> {
    SCANNER.lock().scan_buffer(data, source_name)
}

/// Scan a file for shellcode
pub fn scan_file(path: &std::path::Path) -> Result<Vec<MemoryScanResult>, MemoryScanError> {
    SCANNER.lock().scan_file(path)
}

/// Quick check if buffer contains shellcode
pub fn contains_shellcode(data: &[u8]) -> bool {
    !scan_buffer(data, "quick_scan").is_empty()
}

/// Check if buffer contains critical shellcode (high confidence, high severity)
pub fn contains_critical_shellcode(data: &[u8]) -> bool {
    scan_buffer(data, "critical_scan")
        .iter()
        .any(|r| r.is_critical())
}

/// Get recent scan results
pub fn get_recent_results(limit: usize) -> Vec<MemoryScanResult> {
    SCANNER.lock().get_recent_results(limit)
}

/// Get scan statistics
pub fn get_stats() -> MemoryScanStats {
    STATS.lock().clone()
}

/// Reset statistics
pub fn reset_stats() {
    *STATS.lock() = MemoryScanStats::default();
}

fn update_stats<F: FnOnce(&mut MemoryScanStats)>(f: F) {
    f(&mut STATS.lock());
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_buffer() {
        init();
        let clean_data = b"Hello, World! This is clean data.";
        let results = scan_buffer(clean_data, "test");
        assert!(results.is_empty());
    }

    #[test]
    fn test_nop_sled_detection() {
        init();
        // 16 NOPs
        let shellcode = [0x90u8; 16];
        let results = scan_buffer(&shellcode, "nop_test");
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| matches!(r.shellcode_type, ShellcodeType::NopSled)));
    }

    #[test]
    fn test_msf_detection() {
        init();
        // MSF reverse TCP stub
        let shellcode = [0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00];
        let results = scan_buffer(&shellcode, "msf_test");
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| matches!(r.shellcode_type, ShellcodeType::Metasploit)));
    }

    #[test]
    fn test_call_pop_detection() {
        init();
        // call $+5; pop eax pattern
        let shellcode = [0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00];
        let results = scan_buffer(&shellcode, "callpop_test");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_peb_access_detection() {
        init();
        // mov eax, fs:[0x30]
        let shellcode = [0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00];
        let results = scan_buffer(&shellcode, "peb_test");
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| matches!(r.shellcode_type, ShellcodeType::ApiResolution)));
    }

    #[test]
    fn test_multiple_patterns() {
        init();
        // Buffer with multiple shellcode patterns
        let mut shellcode = vec![0u8; 100];
        // Add NOP sled
        shellcode[0..16].copy_from_slice(&[0x90; 16]);
        // Add call/pop
        shellcode[20..26].copy_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58]);

        let results = scan_buffer(&shellcode, "multi_test");
        assert!(results.len() >= 2);
    }
}
