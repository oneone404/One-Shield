import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import '../styles/components/ai-dashboard.css';

const AiDashboard = () => {
    const [engineStatus, setEngineStatus] = useState(null);
    const [baselineStatus, setBaselineStatus] = useState(null);
    const [datasetStatus, setDatasetStatus] = useState(null);
    const [policyStatus, setPolicyStatus] = useState(null);
    const [threats, setThreats] = useState([]);

    useEffect(() => {
        const fetchData = async () => {
            try {
                // Fetch all status in parallel
                const [eng, base, data, pol, th] = await Promise.all([
                    invoke('get_engine_status'),
                    invoke('get_baseline_status'),
                    invoke('get_dataset_status'),
                    invoke('get_policy_status'),
                    invoke('get_threat_snapshot', { limit: 10 })
                ]);
                setEngineStatus(eng);
                setBaselineStatus(base);
                setDatasetStatus(data);
                setPolicyStatus(pol);
                setThreats(th);
            } catch (e) {
                console.error("Dashboard fetch error:", e);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 2000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="ai-dashboard-container fade-in">
            <div className="dashboard-header">
                <h1 className="glow-text">AI Security Engine v0.6.0</h1>
                <span className="status-pill">System Online</span>
            </div>

            <div className="status-grid">
                {/* Engine Card */}
                <StatusCard title="AI Engine" icon="🧠" status={engineStatus?.model_loaded ? "active" : "inactive"}>
                    <div className="stat-row"><span>Model</span> <span className="val">{engineStatus?.model_name || "None"}</span></div>
                    <div className="stat-row"><span>Inference</span> <span className="val">{engineStatus?.inference_device}</span></div>
                    <div className="stat-row"><span>Latency (avg)</span> <span className="val highlight">{engineStatus?.avg_latency_ms.toFixed(2)} ms</span></div>
                    <div className="stat-row"><span>Buffer Size</span> <span className="val">Dynamic</span></div>
                    <div className="stat-row"><span>Total Inferences</span> <span className="val">{engineStatus?.inference_count.toLocaleString()}</span></div>
                </StatusCard>

                {/* Baseline Card */}
                <StatusCard title="Baseline Engine" icon="📈" status={baselineStatus?.status === "Stable" ? "active" : "warning"}>
                    <div className="stat-row"><span>Status</span> <span className={`badge ${baselineStatus?.status === "Stable" ? "green" : "yellow"}`}>{baselineStatus?.status}</span></div>
                    <div className="stat-row"><span>Feature Ver</span> <span className="val">v{baselineStatus?.feature_version}</span></div>
                    <div className="stat-row"><span>Layout Hash</span> <span className="val mono">{baselineStatus?.layout_hash?.toString(16).toUpperCase()}</span></div>
                    <div className="stat-row"><span>Samples</span> <span className="val">{baselineStatus?.samples_learned.toLocaleString()}</span></div>
                    <div className="stat-row"><span>Last Reset</span> <span className="val tiny">{baselineStatus?.last_reset}</span></div>
                </StatusCard>

                {/* Dataset Card */}
                <StatusCard title="AI Dataset" icon="🗂️" status="active">
                    <div className="stat-row"><span>Files</span> <span className="val">{datasetStatus?.file_count}</span></div>
                    <div className="stat-row"><span>Total Records</span> <span className="val highlight">{datasetStatus?.record_count.toLocaleString()}</span></div>
                    <div className="stat-row"><span>Total Size</span> <span className="val">{(datasetStatus?.total_size_bytes / 1024 / 1024).toFixed(2)} MB</span></div>
                    <div className="stat-row"><span>Location</span> <span className="val tiny-text" title={datasetStatus?.location}>{datasetStatus?.location}</span></div>
                </StatusCard>

                {/* Policy Card */}
                <StatusCard title="Policy Engine" icon="🛡️" status="active">
                    <div className="stat-row"><span>Mode</span> <span className="val">{policyStatus?.enable_auto_block ? "Aggressive" : "Balanced"}</span></div>
                    <div className="stat-row"><span>Auto Block</span> <span className="val">{policyStatus?.enable_auto_block ? "ENABLED" : "Disabled"}</span></div>
                    <div className="stat-row"><span>Require Review</span> <span className="val">Yes</span></div>
                    <div className="stat-row"><span>Last Action</span> <span className="val">None</span></div>
                </StatusCard>
            </div>

            <div className="threat-section">
                <h3>Recent Threat Snapshot</h3>
                <div className="threat-list glass-panel">
                    <div className="threat-header">
                        <span>Time</span>
                        <span>Severity</span>
                        <span>Score</span>
                        <span>Tags</span>
                    </div>
                    {threats.map((t, i) => (
                        <div key={i} className="threat-item">
                            <span className="time">{new Date(t.analyzed_at).toLocaleTimeString()}</span>
                            <span className={`severity-badge ${t.severity_level.toLowerCase()}`}>{t.severity_level}</span>
                            <span className="score">{t.final_score.toFixed(2)}</span>
                            <span className="tags">{t.tags.join(", ")}</span>
                        </div>
                    ))}
                    {threats.length === 0 && <div className="empty-state">No recent activity detected. System is clean.</div>}
                </div>
            </div>
        </div>
    );
};

const StatusCard = ({ title, icon, children, status }) => (
    <div className={`status-card glass-panel ${status}`}>
        <div className="card-header">
            <div className="header-left">
                <span className="card-icon">{icon}</span>
                <span className="card-title">{title}</span>
            </div>
            <span className={`status-dot ${status}`}></span>
        </div>
        <div className="card-divider"></div>
        <div className="card-content">
            {children}
        </div>
    </div>
);

export default AiDashboard;
