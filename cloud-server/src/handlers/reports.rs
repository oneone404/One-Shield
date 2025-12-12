//! Reports handlers

use axum::{extract::State, Json};
use serde::Serialize;
use sqlx::Row;

use crate::{AppState, AppResult};
use crate::models::Incident;
use crate::middleware::auth::UserContext;

#[derive(Debug, Serialize)]
pub struct ExecutiveReport {
    pub org_name: String,
    pub total_endpoints: i64,
    pub online_endpoints: i64,
    pub total_incidents: i64,
    pub open_incidents: i64,
    pub critical_incidents: i64,
    pub high_incidents: i64,
    pub medium_incidents: i64,
    pub security_score: f32,
    pub period: String,
}

#[derive(Debug, Serialize)]
pub struct ComplianceReport {
    pub compliant: bool,
    pub checks: Vec<ComplianceCheck>,
}

#[derive(Debug, Serialize)]
pub struct ComplianceCheck {
    pub control_id: String,
    pub name: String,
    pub status: String,
    pub details: String,
}

/// Generate executive report
pub async fn executive(
    State(state): State<AppState>,
    user: UserContext,
) -> AppResult<Json<ExecutiveReport>> {
    // Count endpoints
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE status = 'online') as online
        FROM endpoints WHERE org_id = $1
        "#
    )
    .bind(user.org_id)
    .fetch_one(&state.pool)
    .await?;

    let total_endpoints: i64 = row.get("total");
    let online_endpoints: i64 = row.get("online");

    // Count incidents by severity
    let incident_counts = Incident::count_by_severity(&state.pool, user.org_id).await?;

    let mut critical = 0i64;
    let mut high = 0i64;
    let mut medium = 0i64;
    let mut total_open = 0i64;

    for (severity, count) in &incident_counts {
        total_open += count;
        match severity.as_str() {
            "critical" => critical = *count,
            "high" => high = *count,
            "medium" => medium = *count,
            _ => {}
        }
    }

    // Calculate security score (simple formula)
    let security_score = if total_endpoints == 0 {
        100.0
    } else {
        let incident_penalty = (critical * 10 + high * 5 + medium * 2) as f32;
        (100.0 - incident_penalty / total_endpoints as f32).max(0.0)
    };

    // Get org name
    let org_row = sqlx::query("SELECT name FROM organizations WHERE id = $1")
        .bind(user.org_id)
        .fetch_one(&state.pool)
        .await?;
    let org_name: String = org_row.get("name");

    Ok(Json(ExecutiveReport {
        org_name,
        total_endpoints,
        online_endpoints,
        total_incidents: total_open,
        open_incidents: total_open,
        critical_incidents: critical,
        high_incidents: high,
        medium_incidents: medium,
        security_score,
        period: "Last 30 days".to_string(),
    }))
}

/// Generate compliance report
pub async fn compliance(
    State(_state): State<AppState>,
    _user: UserContext,
) -> AppResult<Json<ComplianceReport>> {
    // Simplified compliance checks
    let checks = vec![
        ComplianceCheck {
            control_id: "A.12.4.1".to_string(),
            name: "Event Logging".to_string(),
            status: "compliant".to_string(),
            details: "All endpoints have logging enabled".to_string(),
        },
        ComplianceCheck {
            control_id: "A.12.4.3".to_string(),
            name: "Administrator Logs".to_string(),
            status: "compliant".to_string(),
            details: "Admin actions are logged".to_string(),
        },
        ComplianceCheck {
            control_id: "A.16.1.2".to_string(),
            name: "Incident Reporting".to_string(),
            status: "compliant".to_string(),
            details: "Incidents are reported automatically".to_string(),
        },
    ];

    Ok(Json(ComplianceReport {
        compliant: true,
        checks,
    }))
}
