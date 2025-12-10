use std::collections::HashMap;
use parking_lot::Mutex;
use uuid::Uuid;
use chrono::Utc;

use super::types::{Incident, DatasetRecordSummary};
use crate::logic::threat::ThreatClass;
use crate::logic::dataset::DatasetRecord;

// Global Incident Manager (In-Memory for P3.1)
static MANAGER: Mutex<Option<IncidentManager>> = Mutex::new(None);

pub struct IncidentManager {
    active: HashMap<Uuid, Incident>,
}

impl IncidentManager {
    fn new() -> Self {
        Self {
            active: HashMap::new(),
        }
    }

    fn process(&mut self, record: &DatasetRecord, tags: &[String]) {
        // P3.1: Only process non-benign events
        if record.threat == ThreatClass::Benign {
            return;
        }

        let summary = DatasetRecordSummary {
            ts: chrono::DateTime::from_timestamp_millis(record.timestamp as i64)
                .unwrap_or(Utc::now())
                .with_timezone(&Utc),
            score: record.score,
            confidence: record.confidence,
            threat: record.threat.clone(),
            tags: tags.to_vec(),
        };

        // Rule: Group by time window (60s)
        let mut target_id = None;
        let now = summary.ts;

        for (id, incident) in self.active.iter() {
            let gap = now.signed_duration_since(incident.last_seen).num_seconds();
            if gap.abs() < 60 {
                target_id = Some(*id);
                break;
            }
        }

        if let Some(id) = target_id {
            if let Some(inc) = self.active.get_mut(&id) {
                inc.update(summary);
            }
        } else {
            let inc = Incident::new(summary);
            self.active.insert(inc.incident_id, inc);
        }
    }
}

// Public API
pub fn process_event(record: &DatasetRecord, tags: &[String]) {
    let mut guard = MANAGER.lock();
    if guard.is_none() {
        *guard = Some(IncidentManager::new());
    }

    if let Some(mgr) = guard.as_mut() {
        mgr.process(record, tags);
    }
}

pub fn get_incidents() -> Vec<Incident> {
    let mut guard = MANAGER.lock();
    if guard.is_none() {
        *guard = Some(IncidentManager::new());
    }

    if let Some(mgr) = guard.as_ref() {
        let mut list: Vec<Incident> = mgr.active.values().cloned().collect();
        // Sort by started_at desc (newest first)
        list.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        return list;
    }
    vec![]
}

pub fn get_incident(id: Uuid) -> Option<Incident> {
    let mut guard = MANAGER.lock();
    if guard.is_none() {
        *guard = Some(IncidentManager::new());
    }

    guard.as_ref().and_then(|mgr| mgr.active.get(&id).cloned())
}
