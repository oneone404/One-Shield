import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
    Shield, Activity, CheckCircle, XCircle, AlertTriangle,
    FileText, TrendingUp, Clock, Eye, RefreshCw
} from 'lucide-react';

/**
 * SecurityLogs Component
 * Displays security analytics, recent events, and log files
 */
export default function SecurityLogs() {
    const [analytics, setAnalytics] = useState(null);
    const [telemetryStats, setTelemetryStats] = useState(null);
    const [recentEvents, setRecentEvents] = useState([]);
    const [logFiles, setLogFiles] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('overview');

    // Fetch all data
    const fetchData = async () => {
        setLoading(true);
        try {
            const [analyticsData, statsData, eventsData, filesData] = await Promise.all([
                invoke('get_security_analytics').catch(() => null),
                invoke('get_telemetry_stats').catch(() => null),
                invoke('get_recent_security_events', { limit: 50 }).catch(() => ({ events: [] })),
                invoke('get_security_log_files').catch(() => []),
            ]);

            setAnalytics(analyticsData);
            setTelemetryStats(statsData);
            setRecentEvents(eventsData?.events || []);
            setLogFiles(filesData || []);
        } catch (error) {
            console.error('Failed to fetch security data:', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
        // Refresh every 30 seconds
        const interval = setInterval(fetchData, 30000);
        return () => clearInterval(interval);
    }, []);

    // Event type icon and color
    const getEventIcon = (eventType) => {
        switch (eventType) {
            case 'ThreatDetected':
                return <AlertTriangle size={14} className="event-icon threat" />;
            case 'UserApproved':
                return <CheckCircle size={14} className="event-icon approved" />;
            case 'UserDenied':
                return <XCircle size={14} className="event-icon denied" />;
            case 'ActionCreated':
                return <Shield size={14} className="event-icon action" />;
            case 'SystemStart':
            case 'SystemStop':
                return <Activity size={14} className="event-icon system" />;
            default:
                return <FileText size={14} className="event-icon default" />;
        }
    };

    // Format timestamp
    const formatTime = (timestamp) => {
        if (!timestamp) return '';
        const date = new Date(timestamp);
        return date.toLocaleTimeString('vi-VN', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    };

    const formatDate = (timestamp) => {
        if (!timestamp) return '';
        const date = new Date(timestamp);
        return date.toLocaleDateString('vi-VN');
    };

    if (loading && !analytics) {
        return (
            <div className="security-logs loading">
                <div className="loading-spinner">
                    <RefreshCw size={24} className="spin" />
                    <span>Đang tải dữ liệu bảo mật...</span>
                </div>
            </div>
        );
    }

    return (
        <div className="security-logs">
            {/* Header */}
            <div className="security-header">
                <div className="header-title">
                    <Shield size={24} />
                    <h2>Security Logs</h2>
                </div>
                <button className="refresh-btn" onClick={fetchData} disabled={loading}>
                    <RefreshCw size={16} className={loading ? 'spin' : ''} />
                </button>
            </div>

            {/* Session Info */}
            {telemetryStats && (
                <div className="session-info">
                    <span className="session-label">Session:</span>
                    <span className="session-id">{telemetryStats.session_id?.slice(0, 8)}...</span>
                    <span className="events-count">{telemetryStats.events_recorded} events</span>
                </div>
            )}

            {/* Tabs */}
            <div className="tabs">
                <button
                    className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
                    onClick={() => setActiveTab('overview')}
                >
                    <TrendingUp size={14} />
                    Overview
                </button>
                <button
                    className={`tab ${activeTab === 'events' ? 'active' : ''}`}
                    onClick={() => setActiveTab('events')}
                >
                    <Clock size={14} />
                    Recent Events
                </button>
                <button
                    className={`tab ${activeTab === 'files' ? 'active' : ''}`}
                    onClick={() => setActiveTab('files')}
                >
                    <FileText size={14} />
                    Log Files
                </button>
            </div>

            {/* Tab Content */}
            <div className="tab-content">
                {/* Overview Tab */}
                {activeTab === 'overview' && analytics && (
                    <div className="overview-grid">
                        <div className="stat-card total">
                            <div className="stat-icon"><Activity size={20} /></div>
                            <div className="stat-value">{analytics.total_events}</div>
                            <div className="stat-label">Total Events</div>
                        </div>

                        <div className="stat-card threats">
                            <div className="stat-icon"><AlertTriangle size={20} /></div>
                            <div className="stat-value">{analytics.threats_detected}</div>
                            <div className="stat-label">Threats Detected</div>
                        </div>

                        <div className="stat-card approvals">
                            <div className="stat-icon"><CheckCircle size={20} /></div>
                            <div className="stat-value">{analytics.user_approvals}</div>
                            <div className="stat-label">Approvals</div>
                        </div>

                        <div className="stat-card denials">
                            <div className="stat-icon"><XCircle size={20} /></div>
                            <div className="stat-value">{analytics.user_denials}</div>
                            <div className="stat-label">Denials</div>
                        </div>

                        {/* Rates */}
                        <div className="rate-card">
                            <div className="rate-header">
                                <span>Approval Rate</span>
                                <span className="rate-value">
                                    {(analytics.approval_rate * 100).toFixed(1)}%
                                </span>
                            </div>
                            <div className="rate-bar">
                                <div
                                    className="rate-fill approval"
                                    style={{ width: `${analytics.approval_rate * 100}%` }}
                                />
                            </div>
                        </div>

                        <div className="rate-card">
                            <div className="rate-header">
                                <span>Override Rate</span>
                                <span className="rate-value">
                                    {(analytics.override_rate * 100).toFixed(1)}%
                                </span>
                            </div>
                            <div className="rate-bar">
                                <div
                                    className="rate-fill override"
                                    style={{ width: `${analytics.override_rate * 100}%` }}
                                />
                            </div>
                        </div>
                    </div>
                )}

                {/* Events Tab */}
                {activeTab === 'events' && (
                    <div className="events-list">
                        {recentEvents.length === 0 ? (
                            <div className="no-events">
                                <Eye size={32} />
                                <p>No events recorded yet</p>
                            </div>
                        ) : (
                            recentEvents.slice().reverse().map((event, index) => (
                                <div key={event.id || index} className="event-item">
                                    <div className="event-icon-wrapper">
                                        {getEventIcon(event.event_type)}
                                    </div>
                                    <div className="event-content">
                                        <div className="event-type">{event.event_type}</div>
                                        <div className="event-desc">{event.description}</div>
                                        {event.process && (
                                            <div className="event-process">
                                                {event.process.name} (PID: {event.process.pid})
                                            </div>
                                        )}
                                    </div>
                                    <div className="event-time">
                                        <div className="time">{formatTime(event.timestamp)}</div>
                                        <div className="date">{formatDate(event.timestamp)}</div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                )}

                {/* Files Tab */}
                {activeTab === 'files' && (
                    <div className="files-list">
                        {logFiles.length === 0 ? (
                            <div className="no-files">
                                <FileText size={32} />
                                <p>No log files available</p>
                            </div>
                        ) : (
                            logFiles.map((file, index) => {
                                const fileName = file.split(/[/\\]/).pop();
                                return (
                                    <div key={index} className="file-item">
                                        <FileText size={16} />
                                        <span className="file-name">{fileName}</span>
                                    </div>
                                );
                            })
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
