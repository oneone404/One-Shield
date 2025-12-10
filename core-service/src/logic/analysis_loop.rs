use std::thread;
use std::time::Duration;
use crate::logic::{collector, baseline, incident};
use crate::logic::features::vector::FeatureVector;
use crate::logic::dataset::DatasetRecord;
use crate::logic::threat::ThreatClass;

pub fn start() {
    thread::spawn(move || {
        log::info!("Analysis Engine loop started");
        loop {
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
