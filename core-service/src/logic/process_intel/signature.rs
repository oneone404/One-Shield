//! Signature Verification Module - Kiểm tra chữ ký số (Phase 2)
//!
//! Mục đích: Xác định app có được ký bởi publisher tin cậy không
//!
//! Windows sử dụng Authenticode để ký file. Module này verify:
//! 1. File có được ký không
//! 2. Chữ ký có hợp lệ không (không bị tamper)
//! 3. Publisher có trong whitelist không

use std::path::Path;
use std::collections::HashMap;
use std::process::Command;
use parking_lot::RwLock;
use once_cell::sync::Lazy;

use super::types::{SignatureStatus, is_publisher_trusted};

// ============================================================================
// CACHE
// ============================================================================

/// Cache kết quả signature verification (tránh verify lại nhiều lần)
static SIGNATURE_CACHE: Lazy<RwLock<HashMap<String, SignatureStatus>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

const CACHE_MAX_SIZE: usize = 1000;

// ============================================================================
// PUBLIC API
// ============================================================================

/// Kết quả kiểm tra signature chi tiết
#[derive(Debug, Clone)]
pub struct SignatureResult {
    pub status: SignatureStatus,
    pub is_cached: bool,
    pub check_time_ms: u64,
}

/// Verify chữ ký của một file
pub fn verify_signature(file_path: &Path) -> SignatureResult {
    let start = std::time::Instant::now();

    // Check cache first
    let path_str = file_path.to_string_lossy().to_string();
    if let Some(cached) = SIGNATURE_CACHE.read().get(&path_str) {
        return SignatureResult {
            status: cached.clone(),
            is_cached: true,
            check_time_ms: start.elapsed().as_millis() as u64,
        };
    }

    // Verify signature
    let status = verify_signature_internal(file_path);

    // Cache result
    {
        let mut cache = SIGNATURE_CACHE.write();

        // Evict oldest if cache full
        if cache.len() >= CACHE_MAX_SIZE {
            // Simple eviction: clear half
            let keys: Vec<_> = cache.keys().take(CACHE_MAX_SIZE / 2).cloned().collect();
            for key in keys {
                cache.remove(&key);
            }
        }

        cache.insert(path_str, status.clone());
    }

    SignatureResult {
        status,
        is_cached: false,
        check_time_ms: start.elapsed().as_millis() as u64,
    }
}

/// Kiểm tra nhanh có phải trusted publisher không
pub fn is_trusted_publisher(file_path: &Path) -> bool {
    let result = verify_signature(file_path);
    result.status.is_trusted()
}

/// Kiểm tra file có được ký không (bất kể publisher)
pub fn is_signed(file_path: &Path) -> bool {
    let result = verify_signature(file_path);
    result.status.is_signed()
}

/// Clear signature cache
pub fn clear_cache() {
    SIGNATURE_CACHE.write().clear();
}

/// Lấy số entries trong cache
pub fn cache_size() -> usize {
    SIGNATURE_CACHE.read().len()
}

// ============================================================================
// INTERNAL IMPLEMENTATION
// ============================================================================

/// Verify signature using PowerShell (Windows)
fn verify_signature_internal(file_path: &Path) -> SignatureStatus {
    // Check file exists
    if !file_path.exists() {
        return SignatureStatus::Error {
            message: "File not found".to_string(),
        };
    }

    // Use PowerShell to check signature
    // Get-AuthenticodeSignature returns detailed info about the signature
    let ps_script = format!(
        r#"
        $sig = Get-AuthenticodeSignature -FilePath '{}'
        @{{
            'Status' = $sig.Status.ToString()
            'StatusMessage' = $sig.StatusMessage
            'SignerCertificate' = if ($sig.SignerCertificate) {{
                @{{
                    'Subject' = $sig.SignerCertificate.Subject
                    'Issuer' = $sig.SignerCertificate.Issuer
                }}
            }} else {{ $null }}
        }} | ConvertTo-Json -Compress
        "#,
        file_path.display()
    );

    let output = match Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_script])
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            return SignatureStatus::Error {
                message: format!("PowerShell execution failed: {}", e),
            };
        }
    };

    if !output.status.success() {
        return SignatureStatus::Error {
            message: String::from_utf8_lossy(&output.stderr).to_string(),
        };
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_signature_result(&stdout)
}

/// Parse kết quả từ PowerShell
fn parse_signature_result(json_str: &str) -> SignatureStatus {
    // Parse JSON response
    let parsed: serde_json::Value = match serde_json::from_str(json_str.trim()) {
        Ok(v) => v,
        Err(_) => {
            // Fallback: try to extract info from raw output
            return parse_signature_fallback(json_str);
        }
    };

    let status = parsed["Status"].as_str().unwrap_or("");

    match status {
        "Valid" => {
            // Extract publisher info
            if let Some(cert) = parsed.get("SignerCertificate") {
                let subject = cert["Subject"].as_str().unwrap_or("");
                let issuer = cert["Issuer"].as_str().unwrap_or("");

                // Extract CN (Common Name) from Subject
                let publisher = extract_cn(subject);

                if is_publisher_trusted(&publisher) {
                    SignatureStatus::Trusted {
                        publisher,
                        issuer: extract_cn(issuer),
                    }
                } else {
                    SignatureStatus::SignedUntrusted { publisher }
                }
            } else {
                SignatureStatus::SignedUntrusted {
                    publisher: "Unknown".to_string(),
                }
            }
        }
        "NotSigned" => SignatureStatus::Unsigned,
        "HashMismatch" | "NotTrusted" | "UnknownError" => {
            let message = parsed["StatusMessage"].as_str().unwrap_or("Unknown error");
            SignatureStatus::Invalid {
                reason: message.to_string(),
            }
        }
        _ => SignatureStatus::Error {
            message: format!("Unknown status: {}", status),
        },
    }
}

/// Fallback parsing khi JSON parse fail
fn parse_signature_fallback(output: &str) -> SignatureStatus {
    let output_lower = output.to_lowercase();

    if output_lower.contains("valid") && output_lower.contains("microsoft") {
        SignatureStatus::Trusted {
            publisher: "Microsoft Corporation".to_string(),
            issuer: "Microsoft".to_string(),
        }
    } else if output_lower.contains("valid") {
        SignatureStatus::SignedUntrusted {
            publisher: "Unknown".to_string(),
        }
    } else if output_lower.contains("notsigned") {
        SignatureStatus::Unsigned
    } else if output_lower.contains("hashmismatch") || output_lower.contains("invalid") {
        SignatureStatus::Invalid {
            reason: "Signature verification failed".to_string(),
        }
    } else {
        SignatureStatus::Error {
            message: "Could not parse signature result".to_string(),
        }
    }
}

/// Extract Common Name (CN) from certificate subject
fn extract_cn(subject: &str) -> String {
    // Subject format: CN=Microsoft Corporation, O=Microsoft, ...
    for part in subject.split(',') {
        let part = part.trim();
        if part.starts_with("CN=") || part.starts_with("cn=") {
            return part[3..].to_string();
        }
    }

    // Fallback: return first part or whole subject
    subject.split(',').next().unwrap_or(subject).trim().to_string()
}

// ============================================================================
// BATCH VERIFICATION
// ============================================================================

/// Verify nhiều files cùng lúc (parallel)
pub fn verify_batch(file_paths: &[&Path]) -> Vec<(String, SignatureResult)> {
    file_paths
        .iter()
        .map(|path| {
            (
                path.to_string_lossy().to_string(),
                verify_signature(path),
            )
        })
        .collect()
}

/// Lọc chỉ lấy files trusted
pub fn filter_trusted<'a>(file_paths: &[&'a Path]) -> Vec<&'a Path> {
    file_paths
        .iter()
        .filter(|path| is_trusted_publisher(path))
        .copied()
        .collect()
}

// ============================================================================
// STATS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct SignatureStats {
    pub cache_size: usize,
    pub trusted_count: usize,
    pub untrusted_count: usize,
    pub unsigned_count: usize,
    pub invalid_count: usize,
}

pub fn get_stats() -> SignatureStats {
    let cache = SIGNATURE_CACHE.read();

    let mut stats = SignatureStats {
        cache_size: cache.len(),
        trusted_count: 0,
        untrusted_count: 0,
        unsigned_count: 0,
        invalid_count: 0,
    };

    for status in cache.values() {
        match status {
            SignatureStatus::Trusted { .. } => stats.trusted_count += 1,
            SignatureStatus::SignedUntrusted { .. } => stats.untrusted_count += 1,
            SignatureStatus::Unsigned => stats.unsigned_count += 1,
            SignatureStatus::Invalid { .. } | SignatureStatus::Error { .. } => stats.invalid_count += 1,
        }
    }

    stats
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_extract_cn() {
        let subject = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
        assert_eq!(extract_cn(subject), "Microsoft Corporation");
    }

    #[test]
    fn test_is_trusted_publisher_check() {
        assert!(is_publisher_trusted("Microsoft Corporation"));
        assert!(is_publisher_trusted("Google LLC"));
        assert!(!is_publisher_trusted("Random Malware Inc"));
    }

    #[test]
    fn test_verify_system_file() {
        // Test with a known Windows system file
        let notepad = PathBuf::from(r"C:\Windows\System32\notepad.exe");
        if notepad.exists() {
            let result = verify_signature(&notepad);
            // Should be signed by Microsoft
            assert!(result.status.is_signed());
        }
    }
}
