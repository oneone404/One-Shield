/**
 * Executive Dashboard Page
 *
 * Security overview for management with key metrics and risk assessment
 */

import React, { useState, useEffect } from 'react';
import { getExecutiveReport, getIncidentSummary, getEndpointStats } from '../services/tauriApi';
import '../styles/pages/executive.css';

// Icons
const SecurityIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
);

const AlertIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
);

const CheckIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="20 6 9 17 4 12" />
    </svg>
);

const TrendUpIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="23 6 13.5 15.5 8.5 10.5 1 18" />
        <polyline points="17 6 23 6 23 12" />
    </svg>
);

const TrendDownIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="23 18 13.5 8.5 8.5 13.5 1 6" />
        <polyline points="17 18 23 18 23 12" />
    </svg>
);

const ServerIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
        <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
        <line x1="6" y1="6" x2="6.01" y2="6" />
        <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
);

export default function ExecutiveDashboard() {
    const [report, setReport] = useState(null);
    const [incidentSummary, setIncidentSummary] = useState(null);
    const [endpointStats, setEndpointStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [period, setPeriod] = useState('daily');

    useEffect(() => {
        loadData();
    }, [period]);

    const loadData = async () => {
        try {
            setLoading(true);
            const [reportData, summaryData, statsData] = await Promise.all([
                getExecutiveReport(),
                getIncidentSummary(period),
                getEndpointStats()
            ]);
            setReport(reportData);
            setIncidentSummary(summaryData);
            setEndpointStats(statsData);
        } catch (error) {
            console.error('Failed to load executive data:', error);
        } finally {
            setLoading(false);
        }
    };

    const getScoreColor = (score) => {
        if (score >= 90) return 'var(--color-success)';
        if (score >= 70) return 'var(--color-warning)';
        if (score >= 50) return 'var(--color-orange)';
        return 'var(--color-critical)';
    };

    const getRiskBadgeClass = (level) => {
        switch (level?.toLowerCase()) {
            case 'low': return 'risk-low';
            case 'medium': return 'risk-medium';
            case 'high': return 'risk-high';
            case 'critical': return 'risk-critical';
            default: return 'risk-low';
        }
    };

    if (loading) {
        return (
            <div className="executive-loading">
                <div className="loading-spinner"></div>
                <p>Loading Executive Report...</p>
            </div>
        );
    }

    return (
        <div className="executive-dashboard">
            {/* Header */}
            <div className="executive-header">
                <div className="executive-title">
                    <SecurityIcon />
                    <h1>Security Executive Dashboard</h1>
                </div>
                <div className="period-selector">
                    <button
                        className={period === 'daily' ? 'active' : ''}
                        onClick={() => setPeriod('daily')}
                    >
                        Daily
                    </button>
                    <button
                        className={period === 'weekly' ? 'active' : ''}
                        onClick={() => setPeriod('weekly')}
                    >
                        Weekly
                    </button>
                    <button
                        className={period === 'monthly' ? 'active' : ''}
                        onClick={() => setPeriod('monthly')}
                    >
                        Monthly
                    </button>
                </div>
            </div>

            {/* Security Score Card */}
            <div className="security-score-section">
                <div className="score-card">
                    <div className="score-circle" style={{ '--score-color': getScoreColor(report?.security_score || 100) }}>
                        <svg viewBox="0 0 100 100">
                            <circle className="score-bg" cx="50" cy="50" r="45" />
                            <circle
                                className="score-fill"
                                cx="50" cy="50" r="45"
                                style={{ strokeDashoffset: 283 - (283 * (report?.security_score || 100) / 100) }}
                            />
                        </svg>
                        <div className="score-value">
                            <span className="score-number">{Math.round(report?.security_score || 100)}</span>
                            <span className="score-label">Security Score</span>
                        </div>
                    </div>
                    <div className={`risk-badge ${getRiskBadgeClass(report?.risk_level)}`}>
                        {report?.risk_level || 'Low'} Risk
                    </div>
                </div>

                <div className="score-details">
                    <h3>Security Posture Overview</h3>
                    <div className="metrics-grid">
                        <div className="metric-item">
                            <span className="metric-value">{report?.total_incidents || 0}</span>
                            <span className="metric-label">Total Incidents</span>
                        </div>
                        <div className="metric-item critical">
                            <span className="metric-value">{report?.critical_incidents || 0}</span>
                            <span className="metric-label">Critical</span>
                        </div>
                        <div className="metric-item high">
                            <span className="metric-value">{report?.high_incidents || 0}</span>
                            <span className="metric-label">High</span>
                        </div>
                        <div className="metric-item medium">
                            <span className="metric-value">{report?.medium_incidents || 0}</span>
                            <span className="metric-label">Medium</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Stats Cards */}
            <div className="stats-row">
                <div className="stat-card endpoints">
                    <div className="stat-icon">
                        <ServerIcon />
                    </div>
                    <div className="stat-content">
                        <span className="stat-value">{endpointStats?.total_endpoints || 1}</span>
                        <span className="stat-label">Endpoints Protected</span>
                        <div className="stat-breakdown">
                            <span className="online">{endpointStats?.online || 1} Online</span>
                            <span className="offline">{endpointStats?.offline || 0} Offline</span>
                        </div>
                    </div>
                </div>

                <div className="stat-card threats">
                    <div className="stat-icon">
                        <AlertIcon />
                    </div>
                    <div className="stat-content">
                        <span className="stat-value">{report?.threats_blocked || 0}</span>
                        <span className="stat-label">Threats Blocked</span>
                        <div className="stat-trend">
                            {incidentSummary?.trend === 'Down' ? (
                                <><TrendDownIcon /> <span className="trend-down">-{incidentSummary?.trend_percent || 0}%</span></>
                            ) : incidentSummary?.trend === 'Up' ? (
                                <><TrendUpIcon /> <span className="trend-up">+{incidentSummary?.trend_percent || 0}%</span></>
                            ) : (
                                <span className="trend-stable">Stable</span>
                            )}
                        </div>
                    </div>
                </div>

                <div className="stat-card compliance">
                    <div className="stat-icon">
                        <CheckIcon />
                    </div>
                    <div className="stat-content">
                        <span className="stat-value">{Math.round(endpointStats?.compliance_rate || 100)}%</span>
                        <span className="stat-label">Compliance Rate</span>
                        <div className="compliance-bar">
                            <div
                                className="compliance-fill"
                                style={{ width: `${endpointStats?.compliance_rate || 100}%` }}
                            />
                        </div>
                    </div>
                </div>
            </div>

            {/* Key Findings & Recommendations */}
            <div className="insights-row">
                <div className="insight-card findings">
                    <h3>🔍 Key Findings</h3>
                    <ul>
                        {(report?.key_findings || ['No major issues detected']).map((finding, index) => (
                            <li key={index}>{finding}</li>
                        ))}
                    </ul>
                </div>

                <div className="insight-card recommendations">
                    <h3>💡 Recommendations</h3>
                    <ul>
                        {(report?.recommendations || ['Continue regular monitoring']).map((rec, index) => (
                            <li key={index}>{rec}</li>
                        ))}
                    </ul>
                </div>
            </div>

            {/* Top Threats */}
            {incidentSummary?.top_threats?.length > 0 && (
                <div className="top-threats-section">
                    <h3>🎯 Top Threats This Period</h3>
                    <div className="threats-list">
                        {incidentSummary.top_threats.map((threat, index) => (
                            <div key={index} className="threat-item">
                                <span className="threat-rank">#{index + 1}</span>
                                <span className="threat-name">{threat}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Footer */}
            <div className="report-footer">
                <p>Report generated: {report?.generated_at ? new Date(report.generated_at).toLocaleString() : new Date().toLocaleString()}</p>
                <button className="export-button" onClick={() => window.print()}>
                    📄 Export PDF
                </button>
            </div>
        </div>
    );
}
