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

pub fn explain(record: &DatasetRecord) -> Option<ExplainResult> {
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
        "network_sent_rate" => Some("High outbound traffic variance".to_string()),
        "network_recv_rate" => Some("Unusual download activity".to_string()),
        "disk_write_rate" => Some("Abnormal disk write pattern".to_string()),
        "process_churn_rate" => Some("Rapid process creation/termination".to_string()),
        "new_process_rate" => Some("Sudden appearance of new processes".to_string()),
        "cpu_spike_rate" => Some("Erratical CPU usage spikes".to_string()),
        "memory_spike_rate" => Some("Sudden memory consumption change".to_string()),
        _ => None
    }
}
