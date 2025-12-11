import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { ShieldAlert } from 'lucide-react';
import '../styles/components/incident-panel.css';

const SeverityBadge = ({ level }) => {
    let color = '#9ca3af';
    if (level === 'Low') color = '#fbbf24'; // Suspicious
    if (level === 'Medium') color = '#f97316';
    if (level === 'High') color = '#ef4444'; // Malicious
    if (level === 'Critical') color = '#b91c1c';

    return (
        <span className="severity-badge" style={{ backgroundColor: `${color}15`, color: color, borderColor: `${color}30` }}>
            {level}
        </span>
    );
};

export function IncidentPanel() {
    const [incidents, setIncidents] = useState([]);
    const [selectedId, setSelectedId] = useState(null);
    const [detail, setDetail] = useState(null);

    const refresh = async () => {
        try {
            const list = await invoke('get_incidents');
            setIncidents(list);

            // Auto refresh detail if selected
            if (selectedId) {
                const d = await invoke('get_incident_detail', { id: selectedId });
                setDetail(d);
            }
        } catch (e) { console.error(e); }
    };

    useEffect(() => {
        refresh();
        const interval = setInterval(refresh, 5000); // 5s poll
        return () => clearInterval(interval);
    }, [selectedId]);

    const selectIncident = async (id) => {
        setSelectedId(id);
        setDetail(null); // Clear loading
        try {
            const d = await invoke('get_incident_detail', { id });
            setDetail(d);
        } catch (e) { console.error(e); }
    };

    return (
        <div className="incident-panel glass-panel">
            <div className="ip-header">
                <div className="title"><ShieldAlert size={18} /> SECURITY INCIDENTS</div>
                <div className="badge-count">{incidents.length}</div>
            </div>

            <div className="ip-content">
                {/* List */}
                <div className="ip-list">
                    {incidents.length === 0 && <div className="placeholder" style={{ fontSize: '0.8rem' }}>No active incidents</div>}
                    {incidents.map(inc => (
                        <div key={inc.incident_id}
                            className={`ip-item ${selectedId === inc.incident_id ? 'active' : ''}`}
                            onClick={() => selectIncident(inc.incident_id)}>
                            <div className="ip-row top">
                                <SeverityBadge level={inc.severity} />
                                <span className="time">{new Date(inc.last_seen).toLocaleTimeString()}</span>
                            </div>
                            <div className="ip-row id">ID: {inc.incident_id.substring(0, 8)}...</div>
                            <div className="ip-row status">
                                <span>{inc.records.length} events</span>
                                <span style={{ color: inc.status === 'Open' ? '#4ade80' : '#9ca3af' }}>{inc.status}</span>
                            </div>
                        </div>
                    ))}
                </div>

                {/* Detail Timeline */}
                <div className="ip-detail">
                    {detail ? (
                        <div className="timeline-view">
                            <div className="detail-header">
                                <h3>Incident Details</h3>
                                <span className="uuid">{detail.incident_id}</span>
                            </div>

                            {/* P3.2 Explainability Section */}
                            {detail.explanation && (
                                <div className="explanation-section">
                                    <h4>Why was this detected?</h4>
                                    <div className="features-list">
                                        {detail.explanation.contributions.map((feat, idx) => (
                                            <div key={idx} className="feat-item">
                                                <div className="feat-row">
                                                    <span className="feat-name">{feat.name}</span>
                                                    <span className="feat-val">{feat.delta > 0 ? '+' : ''}{feat.delta.toFixed(2)}</span>
                                                </div>
                                                <div className="feat-desc">{feat.description || "Anomaly detected"}</div>
                                                <div className="feat-bar-bg">
                                                    <div className="feat-bar" style={{ width: `${Math.min(feat.importance * 30, 100)}%` }}></div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            <div className="timeline">
                                {detail.records.map((rec, idx) => (
                                    <div key={idx} className="tl-event" style={{ animationDelay: `${idx * 0.05}s` }}>
                                        <div className="tl-line"></div>
                                        <div className="tl-dot" style={{ borderColor: rec.threat === 'Malicious' ? '#ef4444' : '#fbbf24' }}></div>
                                        <div className="tl-content">
                                            <div className="tl-time">{new Date(rec.ts).toLocaleTimeString()}</div>
                                            <div className="tl-main">
                                                <span className={`threat ${rec.threat.toLowerCase()}`}>{rec.threat}</span>
                                                <span className="score-box">{rec.score.toFixed(2)}</span>
                                            </div>
                                            <div className="tl-tags">
                                                {rec.tags.map((t, i) => <span key={i} className="tag">{t}</span>)}
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <div className="placeholder">
                            {incidents.length > 0 ? "Select an incident to view details" : "System Secure - No Incidents"}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default IncidentPanel;
