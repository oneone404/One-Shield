use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::logic::threat::ThreatClass;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentStatus {
    Open,
    Mitigated,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Low,     // Suspicious low confidence
    Medium,  // Suspicious high confidence or single malicious
    High,    // Confirmed Malicious or Escalated
    Critical, // Multiple Malicious or Critical Tag
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRecordSummary {
    pub ts: DateTime<Utc>,
    pub score: f32,
    pub confidence: f32,
    pub threat: ThreatClass,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,

    pub severity: Severity,
    pub status: IncidentStatus,

    pub records: Vec<DatasetRecordSummary>,
}

impl Incident {
    pub fn new(first_record: DatasetRecordSummary) -> Self {
        let severity = Self::map_severity(&first_record);
        Self {
            incident_id: Uuid::new_v4(),
            started_at: first_record.ts,
            last_seen: first_record.ts,
            severity,
            status: IncidentStatus::Open,
            records: vec![first_record],
        }
    }

    pub fn update(&mut self, record: DatasetRecordSummary) {
        if record.ts > self.last_seen {
            self.last_seen = record.ts;
        }

        // Escalation Logic (Always escalate, never de-escalate automatically)
        let new_severity = Self::map_severity(&record);
        if self.severity_level(&new_severity) > self.severity_level(&self.severity) {
            self.severity = new_severity;
        }

        self.records.push(record);
    }

    fn map_severity(rec: &DatasetRecordSummary) -> Severity {
        match rec.threat {
            ThreatClass::Benign => Severity::Low,
            ThreatClass::Suspicious => {
                if rec.score > 0.7 { Severity::Medium } else { Severity::Low }
            },
            ThreatClass::Malicious => {
                if rec.score > 0.9 { Severity::Critical } else { Severity::High }
            }
        }
    }

    fn severity_level(&self, s: &Severity) -> u8 {
        match s {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}
