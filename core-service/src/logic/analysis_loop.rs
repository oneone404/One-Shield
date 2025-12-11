use std::thread;
use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::logic::{collector, baseline, incident, events};
use crate::logic::features::vector::FeatureVector;
use crate::logic::dataset::DatasetRecord;
use crate::logic::threat::ThreatClass;
use crate::logic::advanced_detection::injection;

// Track last injection check time
static LAST_INJECTION_CHECK: AtomicU64 = AtomicU64::new(0);
const INJECTION_CHECK_INTERVAL_MS: u64 = 10_000; // Check every 10 seconds

pub fn start() {
    // Initialize injection detection
    injection::init();

    thread::spawn(move || {
        log::info!("Analysis Engine loop started");
        loop {
            // === ADVANCED DETECTION: Injection Check ===
            check_injection_patterns();

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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

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

/// Check if process is commonly safe (skip scanning)
fn is_safe_process(name: &str) -> bool {
    let safe_list = [
        "svchost.exe", "csrss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "smss.exe", "System", "Registry", "Idle",
        "explorer.exe", "dwm.exe", "sihost.exe", "taskhostw.exe",
        "conhost.exe", "fontdrvhost.exe", "WmiPrvSE.exe",
        // Development tools
        "Code.exe", "node.exe", "cargo.exe", "rustc.exe",
    ];

    safe_list.iter().any(|&s| name.eq_ignore_ascii_case(s))
}
