use std::thread;
use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::logic::{collector, baseline, incident, events};
use crate::logic::features::vector::FeatureVector;
use crate::logic::dataset::DatasetRecord;
use crate::logic::threat::ThreatClass;
use crate::logic::advanced_detection::{injection, keylogger};

// Track last check times
static LAST_INJECTION_CHECK: AtomicU64 = AtomicU64::new(0);
static LAST_KEYLOGGER_CHECK: AtomicU64 = AtomicU64::new(0);

const INJECTION_CHECK_INTERVAL_MS: u64 = 10_000; // Check every 10 seconds
const KEYLOGGER_CHECK_INTERVAL_MS: u64 = 30_000; // Check every 30 seconds

pub fn start() {
    // Initialize detection modules
    injection::init();
    keylogger::init();

    thread::spawn(move || {
        log::info!("Analysis Engine loop started (v2.3 - Advanced Detection)");
        loop {
            // === ADVANCED DETECTION ===
            check_injection_patterns();
            check_keylogger_patterns();

            let pending = collector::get_pending_summaries();
            if pending.is_empty() {
                // Sleep short interval to be responsive
                thread::sleep(Duration::from_millis(500));
                continue;
            }

            for summary in pending {
                // 1. Create FeatureVector wrapper
                let fv = FeatureVector::from_values(summary.features);

                // 2. Mock AI Score / Retrieve from Cache
                // For v1.0, we rely on baseline tags primarily if ML not loaded
                let ml_score = 0.5;

                // 3. Analyze Baseline (returns AnalysisResult)
                let analysis = baseline::analyze_summary(&summary.id, &fv, ml_score);

                use crate::logic::features::layout::{FEATURE_VERSION, layout_hash};

                // 4. Map to ThreatClass
                let threat = if analysis.final_score >= 0.8 {
                    ThreatClass::Malicious
                } else if analysis.final_score >= 0.5 {
                    ThreatClass::Suspicious
                } else {
                    ThreatClass::Benign
                };

                // 5. Create Dataset Record (Correct definition)
                let record = DatasetRecord {
                    timestamp: summary.created_at.timestamp_millis() as u64,
                    feature_version: FEATURE_VERSION,
                    layout_hash: layout_hash(),
                    features: summary.features.to_vec(),
                    baseline_diff: analysis.baseline_diff,
                    score: analysis.final_score,
                    confidence: analysis.confidence,
                    threat,
                    user_label: None,
                };

                // 6. Send to Incident Manager & Dataset Logger
                incident::process_event(&record, &analysis.tags);

                // LOGGING TO DISK (Crucial for Training)
                crate::logic::dataset::log(record.clone());

                // 7. Mark summary as processed in Collector
                collector::mark_summary_processed(
                    &summary.id, ml_score, analysis.tag_score, analysis.final_score, analysis.tags
                );
            }
        }
    });
}

/// Check running processes for injection patterns
fn check_injection_patterns() {
    let now = get_current_time_ms();
    let last_check = LAST_INJECTION_CHECK.load(Ordering::Relaxed);

    // Only check every INJECTION_CHECK_INTERVAL_MS
    if now - last_check < INJECTION_CHECK_INTERVAL_MS {
        return;
    }

    LAST_INJECTION_CHECK.store(now, Ordering::Relaxed);

    // Get running processes
    let processes = collector::get_running_processes(100);

    let mut total_alerts = 0;

    for proc in processes {
        // Skip common safe processes
        if is_safe_process(&proc.name) {
            continue;
        }

        // Analyze for injection patterns
        let alerts = injection::analyze_process(
            proc.pid,
            &proc.name,
            "", // No cmdline available from ProcessInfo
            None,
            None,
        );

        if !alerts.is_empty() {
            total_alerts += alerts.len();

            // Emit event for each critical alert
            for alert in &alerts {
                if alert.is_critical() {
                    log::warn!(
                        "[INJECTION DETECTED] {} -> {} ({})",
                        alert.source_name,
                        alert.target_name,
                        alert.mitre_id
                    );

                    // Emit event to frontend
                    events::emit_injection_detected(alert);
                }
            }
        }
    }

    if total_alerts > 0 {
        log::info!("[Advanced Detection] Found {} injection alerts", total_alerts);
    }
}

/// Check running processes for keylogger behavior patterns
fn check_keylogger_patterns() {
    let now = get_current_time_ms();
    let last_check = LAST_KEYLOGGER_CHECK.load(Ordering::Relaxed);

    // Only check every KEYLOGGER_CHECK_INTERVAL_MS
    if now - last_check < KEYLOGGER_CHECK_INTERVAL_MS {
        return;
    }

    LAST_KEYLOGGER_CHECK.store(now, Ordering::Relaxed);

    // Get running processes
    let processes = collector::get_running_processes(100);

    let mut total_alerts = 0;

    for proc in &processes {
        // Skip common safe processes
        if is_safe_process(&proc.name) {
            continue;
        }

        // Check for keylogger patterns (static analysis - suspicious names + common APIs)
        let suspicious_apis = get_common_keylogger_apis();

        if let Some(alert) = keylogger::analyze_process(
            proc.pid,
            &proc.name,
            &suspicious_apis,
        ) {
            total_alerts += 1;

            log::warn!(
                "[KEYLOGGER DETECTED] {} (PID: {}) - confidence: {}% ({})",
                alert.process_name,
                alert.pid,
                alert.confidence,
                alert.mitre_id
            );

            // Emit event to frontend
            events::emit_threat_alert(&serde_json::json!({
                "type": "KEYLOGGER",
                "pid": alert.pid,
                "process_name": alert.process_name,
                "confidence": alert.confidence,
                "severity": alert.severity,
                "indicators": alert.indicators,
                "mitre_id": alert.mitre_id,
                "mitre_name": alert.mitre_name,
                "timestamp": alert.timestamp
            }));
        }
    }

    // Also check tracked processes (runtime behavior)
    let runtime_alerts = keylogger::check_all_processes();
    for alert in runtime_alerts {
        if alert.is_critical() {
            log::warn!(
                "[KEYLOGGER BEHAVIOR] {} (PID: {}) - {} indicators",
                alert.process_name,
                alert.pid,
                alert.indicators.len()
            );

            events::emit_threat_alert(&serde_json::json!({
                "type": "KEYLOGGER_BEHAVIOR",
                "pid": alert.pid,
                "process_name": alert.process_name,
                "confidence": alert.confidence,
                "severity": alert.severity,
                "indicators": alert.indicators,
                "mitre_id": alert.mitre_id,
                "timestamp": alert.timestamp
            }));
        }
    }

    if total_alerts > 0 {
        log::info!("[Advanced Detection] Found {} keylogger alerts", total_alerts);
    }

    // Cleanup old tracking data (older than 5 minutes)
    keylogger::cleanup_old_stats(300);
}

/// Get current time in milliseconds
fn get_current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Get common keylogger APIs for static analysis
fn get_common_keylogger_apis() -> Vec<String> {
    // These are commonly found in keyloggers
    // In real implementation, we'd scan the process's IAT
    vec![]
}

/// Check if process is commonly safe (skip scanning)
fn is_safe_process(name: &str) -> bool {
    let safe_list = [
        "svchost.exe", "csrss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "smss.exe", "System", "Registry", "Idle",
        "explorer.exe", "dwm.exe", "sihost.exe", "taskhostw.exe",
        "conhost.exe", "fontdrvhost.exe", "WmiPrvSE.exe",
        // Development tools
        "Code.exe", "node.exe", "cargo.exe", "rustc.exe",
        // Browser processes
        "chrome.exe", "firefox.exe", "msedge.exe",
        // One-Shield itself
        "ai-security-core.exe",
    ];

    safe_list.iter().any(|&s| name.eq_ignore_ascii_case(s))
}
