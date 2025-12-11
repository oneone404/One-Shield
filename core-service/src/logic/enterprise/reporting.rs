//! Reporting & Analytics Module (Phase 6)
//!
//! Mục đích: Generate reports và analytics
//!
//! Features:
//! - Incident summaries
//! - Endpoint statistics
//! - Threat overviews

use std::collections::HashMap;
use chrono::{Utc, Duration};

use super::types::{
    IncidentSummary, EndpointStats, ThreatOverview, TrendData, TrendDirection, MitreCoverage,
};

// ============================================================================
// INCIDENT SUMMARY
// ============================================================================

/// Generate incident summary for a time period
pub fn generate_summary(hours: i64) -> IncidentSummary {
    let now = Utc::now().timestamp();
    let period_start = now - (hours * 3600);

    // TODO: Get actual data from incident manager
    // For now, return mock data structure

    IncidentSummary {
        period_start,
        period_end: now,
        total_incidents: 0,
        by_severity: HashMap::from([
            ("critical".to_string(), 0),
            ("high".to_string(), 0),
            ("medium".to_string(), 0),
            ("low".to_string(), 0),
        ]),
        by_status: HashMap::from([
            ("open".to_string(), 0),
            ("acknowledged".to_string(), 0),
            ("resolved".to_string(), 0),
        ]),
        by_mitre: HashMap::new(),
        top_processes: Vec::new(),
        trend: TrendData {
            direction: TrendDirection::Stable,
            percentage_change: 0.0,
            previous_count: 0,
            current_count: 0,
        },
    }
}

/// Generate daily summary
pub fn generate_daily_summary() -> IncidentSummary {
    generate_summary(24)
}

/// Generate weekly summary
pub fn generate_weekly_summary() -> IncidentSummary {
    generate_summary(24 * 7)
}

/// Generate monthly summary
pub fn generate_monthly_summary() -> IncidentSummary {
    generate_summary(24 * 30)
}

// ============================================================================
// ENDPOINT STATISTICS
// ============================================================================

/// Get endpoint statistics
pub fn get_endpoint_stats() -> EndpointStats {
    // TODO: Get actual data from agent manager
    // For now, return local endpoint data

    EndpointStats {
        total_endpoints: 1,
        online_count: 1,
        offline_count: 0,
        degraded_count: 0,
        by_os: HashMap::from([
            ("Windows".to_string(), 1),
        ]),
        by_group: HashMap::from([
            ("default".to_string(), 1),
        ]),
        avg_cpu_usage: get_current_cpu_usage(),
        avg_memory_usage: get_current_memory_usage(),
    }
}

fn get_current_cpu_usage() -> f32 {
    // TODO: Get actual CPU usage
    0.0
}

fn get_current_memory_usage() -> f32 {
    // TODO: Get actual memory usage
    0.0
}

// ============================================================================
// THREAT OVERVIEW
// ============================================================================

/// Get threat overview
pub fn get_threat_overview() -> ThreatOverview {
    let now = Utc::now().timestamp();
    let today_start = now - (now % 86400);
    let week_start = now - (7 * 86400);

    // TODO: Get actual data from incident and detection modules

    ThreatOverview {
        active_threats: 0,
        threats_today: 0,
        threats_this_week: 0,
        top_threat_types: vec![
            ("Suspicious Spawn".to_string(), 0),
            ("Beaconing".to_string(), 0),
            ("Persistence".to_string(), 0),
        ],
        top_affected_endpoints: vec![],
        mitre_coverage: get_mitre_coverage(),
    }
}

fn get_mitre_coverage() -> Vec<MitreCoverage> {
    vec![
        MitreCoverage {
            tactic: "Execution".to_string(),
            technique_count: 5,
            incident_count: 0,
        },
        MitreCoverage {
            tactic: "Persistence".to_string(),
            technique_count: 4,
            incident_count: 0,
        },
        MitreCoverage {
            tactic: "Defense Evasion".to_string(),
            technique_count: 6,
            incident_count: 0,
        },
        MitreCoverage {
            tactic: "Credential Access".to_string(),
            technique_count: 3,
            incident_count: 0,
        },
        MitreCoverage {
            tactic: "Command and Control".to_string(),
            technique_count: 3,
            incident_count: 0,
        },
    ]
}

// ============================================================================
// EXECUTIVE REPORT
// ============================================================================

/// Generate executive summary
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecutiveSummary {
    pub generated_at: i64,
    pub period: String,
    pub security_score: f32,
    pub risk_level: String,
    pub headline: String,
    pub key_findings: Vec<KeyFinding>,
    pub recommendations: Vec<String>,
    pub incident_summary: IncidentSummary,
    pub endpoint_stats: EndpointStats,
    pub threat_overview: ThreatOverview,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyFinding {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

pub fn generate_executive_summary(period: &str) -> ExecutiveSummary {
    let hours = match period.to_lowercase().as_str() {
        "daily" | "day" => 24,
        "weekly" | "week" => 24 * 7,
        "monthly" | "month" => 24 * 30,
        _ => 24,
    };

    let incident_summary = generate_summary(hours);
    let endpoint_stats = get_endpoint_stats();
    let threat_overview = get_threat_overview();

    // Calculate security score (0-100)
    let security_score = calculate_security_score(
        &incident_summary,
        &endpoint_stats,
        &threat_overview,
    );

    let risk_level = match security_score as i32 {
        90..=100 => "Low",
        70..=89 => "Medium",
        50..=69 => "High",
        _ => "Critical",
    };

    let headline = format!(
        "Security Score: {:.0}% ({} risk) - {} incidents in the past {}",
        security_score,
        risk_level,
        incident_summary.total_incidents,
        period
    );

    ExecutiveSummary {
        generated_at: Utc::now().timestamp(),
        period: period.to_string(),
        security_score,
        risk_level: risk_level.to_string(),
        headline,
        key_findings: generate_key_findings(&incident_summary, &threat_overview),
        recommendations: generate_recommendations(&incident_summary, &threat_overview),
        incident_summary,
        endpoint_stats,
        threat_overview,
    }
}

fn calculate_security_score(
    incidents: &IncidentSummary,
    endpoints: &EndpointStats,
    threats: &ThreatOverview,
) -> f32 {
    let mut score = 100.0;

    // Deduct for critical incidents
    let critical = incidents.by_severity.get("critical").unwrap_or(&0);
    score -= (*critical as f32) * 10.0;

    // Deduct for high incidents
    let high = incidents.by_severity.get("high").unwrap_or(&0);
    score -= (*high as f32) * 5.0;

    // Deduct for active threats
    score -= (threats.active_threats as f32) * 3.0;

    // Deduct for offline endpoints
    if endpoints.total_endpoints > 0 {
        let offline_ratio = endpoints.offline_count as f32 / endpoints.total_endpoints as f32;
        score -= offline_ratio * 20.0;
    }

    score.max(0.0).min(100.0)
}

fn generate_key_findings(
    incidents: &IncidentSummary,
    threats: &ThreatOverview,
) -> Vec<KeyFinding> {
    let mut findings = Vec::new();

    let critical = *incidents.by_severity.get("critical").unwrap_or(&0);
    if critical > 0 {
        findings.push(KeyFinding {
            severity: "critical".to_string(),
            title: format!("{} Critical Incidents Detected", critical),
            description: "Critical severity incidents require immediate attention.".to_string(),
            recommendation: "Review and remediate all critical incidents immediately.".to_string(),
        });
    }

    if threats.active_threats > 0 {
        findings.push(KeyFinding {
            severity: "high".to_string(),
            title: format!("{} Active Threats", threats.active_threats),
            description: "Active threats are currently affecting the environment.".to_string(),
            recommendation: "Investigate and neutralize active threats.".to_string(),
        });
    }

    if findings.is_empty() {
        findings.push(KeyFinding {
            severity: "info".to_string(),
            title: "No Major Issues".to_string(),
            description: "No critical or high severity issues detected.".to_string(),
            recommendation: "Continue monitoring and maintain security posture.".to_string(),
        });
    }

    findings
}

fn generate_recommendations(
    incidents: &IncidentSummary,
    threats: &ThreatOverview,
) -> Vec<String> {
    let mut recommendations = Vec::new();

    let open = *incidents.by_status.get("open").unwrap_or(&0);
    if open > 5 {
        recommendations.push(format!(
            "Review {} open incidents to reduce backlog",
            open
        ));
    }

    if threats.threats_this_week > threats.threats_today * 7 {
        recommendations.push(
            "Threat activity is decreasing - maintain current security measures".to_string()
        );
    } else if threats.threats_today > 0 {
        recommendations.push(
            "Monitor for escalating threat activity".to_string()
        );
    }

    if recommendations.is_empty() {
        recommendations.push("Continue regular security monitoring".to_string());
        recommendations.push("Keep baseline updated with latest behaviors".to_string());
    }

    recommendations
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReportingStats {
    pub reports_generated: usize,
    pub last_report: Option<i64>,
    pub available_periods: Vec<String>,
}

pub fn get_stats() -> ReportingStats {
    ReportingStats {
        reports_generated: 0,
        last_report: None,
        available_periods: vec![
            "daily".to_string(),
            "weekly".to_string(),
            "monthly".to_string(),
        ],
    }
}

// ============================================================================
// ENTERPRISE API FUNCTIONS
// ============================================================================

/// Executive report for UI
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecutiveReport {
    pub security_score: f32,
    pub risk_level: String,
    pub total_incidents: u64,
    pub critical_incidents: u64,
    pub high_incidents: u64,
    pub medium_incidents: u64,
    pub low_incidents: u64,
    pub endpoints_protected: u64,
    pub threats_blocked: u64,
    pub key_findings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Generate executive report for dashboard
pub fn generate_executive_report() -> ExecutiveReport {
    let summary = generate_executive_summary("daily");

    ExecutiveReport {
        security_score: summary.security_score,
        risk_level: summary.risk_level.clone(),
        total_incidents: summary.incident_summary.total_incidents as u64,
        critical_incidents: *summary.incident_summary.by_severity.get("critical").unwrap_or(&0) as u64,
        high_incidents: *summary.incident_summary.by_severity.get("high").unwrap_or(&0) as u64,
        medium_incidents: *summary.incident_summary.by_severity.get("medium").unwrap_or(&0) as u64,
        low_incidents: *summary.incident_summary.by_severity.get("low").unwrap_or(&0) as u64,
        endpoints_protected: summary.endpoint_stats.total_endpoints as u64,
        threats_blocked: summary.threat_overview.threats_this_week as u64,
        key_findings: summary.key_findings.iter().map(|f| f.title.clone()).collect(),
        recommendations: summary.recommendations.clone(),
    }
}

/// Incident summary for UI
#[derive(Debug, Clone, serde::Serialize)]
pub struct IncidentSummaryUI {
    pub total: u64,
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub trend: TrendData,
    pub top_threats: Vec<String>,
}

/// Get incident summary for a period
pub fn get_incident_summary(period: super::types::ReportPeriod) -> IncidentSummaryUI {
    let hours = match period {
        super::types::ReportPeriod::Daily => 24,
        super::types::ReportPeriod::Weekly => 24 * 7,
        super::types::ReportPeriod::Monthly => 24 * 30,
        super::types::ReportPeriod::Quarterly => 24 * 90,
        super::types::ReportPeriod::Yearly => 24 * 365,
    };

    let summary = generate_summary(hours);

    IncidentSummaryUI {
        total: summary.total_incidents as u64,
        critical: *summary.by_severity.get("critical").unwrap_or(&0) as u64,
        high: *summary.by_severity.get("high").unwrap_or(&0) as u64,
        medium: *summary.by_severity.get("medium").unwrap_or(&0) as u64,
        low: *summary.by_severity.get("low").unwrap_or(&0) as u64,
        trend: summary.trend,
        top_threats: summary.top_processes.iter().map(|(name, _)| name.clone()).collect(),
    }
}

/// Endpoint stats for UI
#[derive(Debug, Clone, serde::Serialize)]
pub struct EndpointStatsUI {
    pub total: u64,
    pub online: u64,
    pub offline: u64,
    pub critical: u64,
    pub warning: u64,
    pub healthy: u64,
    pub compliance_rate: f32,
}

/// Get endpoint stats for UI
pub fn get_endpoint_stats_ui() -> EndpointStatsUI {
    let stats = get_endpoint_stats();

    EndpointStatsUI {
        total: stats.total_endpoints as u64,
        online: stats.online_count as u64,
        offline: stats.offline_count as u64,
        critical: 0, // TODO: Calculate from incidents
        warning: stats.degraded_count as u64,
        healthy: stats.online_count.saturating_sub(stats.degraded_count) as u64,
        compliance_rate: if stats.total_endpoints > 0 {
            (stats.online_count as f32 / stats.total_endpoints as f32) * 100.0
        } else {
            100.0
        },
    }
}
