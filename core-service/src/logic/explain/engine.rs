use super::types::{FeatureContribution, ExplainResult};
use crate::logic::dataset::DatasetRecord;
use crate::logic::threat::ThreatClass;

// Heuristic Weights focused on Security Impact
// 1.0 = standard, 1.5 = network/high risk, 1.2 = strange behavior
// This maps to the standard 15 features in vector.rs
static FEATURE_WEIGHTS: [f32; 15] = [
    1.0, // cpu_percent
    1.0, // cpu_spike_rate
    1.0, // memory_percent
    1.2, // memory_spike_rate
    1.5, // network_sent_rate (Exfiltration risk)
    1.5, // network_recv_rate (C2 download risk)
    1.2, // network_ratio
    1.2, // disk_read_rate
    1.5, // disk_write_rate (Ransomware risk)
    1.1, // combined_io
    1.0, // unique_processes
    1.3, // new_process_rate (Dropper risk)
    1.3, // process_churn_rate (Evasion risk)
    1.1, // cpu_memory_product
    1.2, // spike_correlation
];

use crate::logic::config::SafetyConfig;

pub fn explain(record: &DatasetRecord) -> Option<ExplainResult> {
    // Safety guard: Check Config first
    if !SafetyConfig::is_explain_enabled() {
        return None;
    }

    // Safety guard: only explain suspicious/malicious
    if record.threat == ThreatClass::Benign || record.confidence < 0.4 {
        return None;
    }

    let mut contributions = Vec::new();

    // Iterate features
    for (i, &diff) in record.baseline_diff.iter().enumerate() {
        if i >= FEATURE_WEIGHTS.len() { break; }

        let weight = FEATURE_WEIGHTS[i];
        let delta = diff.abs(); // Magnitude of deviation from baseline
        let importance = delta * weight;

        // Only include meaningful deviations
        if importance > 0.05 {
            let name = crate::logic::features::feature_name(i).unwrap_or("unknown").to_string();
            contributions.push(FeatureContribution {
                name: name.clone(),
                delta: diff, // Keep sign to show increase/decrease
                weight,
                importance,
                description: get_description(&name),
            });
        }
    }

    // Sort by importance DESC
    contributions.sort_by(|a, b| b.importance.partial_cmp(&a.importance).unwrap_or(std::cmp::Ordering::Equal));

    // Take top 5
    if contributions.len() > 5 {
        contributions.truncate(5);
    }

    if contributions.is_empty() {
        return None;
    }

    Some(ExplainResult { contributions })
}

fn get_description(name: &str) -> Option<String> {
    match name {
        "network_sent_rate" => Some("Potential Data Exfiltration (High Outbound Traffic)".to_string()),
        "network_recv_rate" => Some("Suspicious Inbound Volume (Possible C2 Communication)".to_string()),
        "disk_write_rate" => Some("High Intensity Disk Write (Ransomware-like behavior)".to_string()),
        "disk_read_rate" => Some("Abnormal Data Collection Activity".to_string()),
        "process_churn_rate" => Some("Rapid Process Forking/Termination (Evasion Technique)".to_string()),
        "new_process_rate" => Some("Sudden Spike in New Process Creation".to_string()),
        "cpu_spike_rate" => Some("Anomalous CPU Usage Patterns (Possible Crypto-mining)".to_string()),
        "memory_spike_rate" => Some("Memory Usage Deviation (Potential Injection)".to_string()),
        "combined_io" => Some("Aggregate System I/O Stress".to_string()),
        "unique_processes" => Some("Deviation in Active Process Count".to_string()),
        _ => Some("Statistical Deviation from Baseline".to_string())
    }
}
