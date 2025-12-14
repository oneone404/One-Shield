import { useEffect, useState } from 'react';
import { getEngineStatus } from '../api/engine';
import '../styles/components/ai-engine-status.css';
import { Shield, Database, Cpu, Activity } from 'lucide-react';

export default function AiEngineStatus() {
    const [status, setStatus] = useState(null);
    const [loading, setLoading] = useState(true);

    const fetchStatus = async () => {
        try {
            const data = await getEngineStatus();
            setStatus(data);
        } catch (e) {
            console.error("Fetch engine status failed", e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStatus();
        const interval = setInterval(fetchStatus, 3000); // 3s refresh
        return () => clearInterval(interval);
    }, []);

    if (loading && !status) return <div className="engine-status loading">Loading AI Engine...</div>;
    if (!status) return (
        <div className="engine-status-card glass-panel" style={{ borderColor: '#ef4444' }}>
            <div className="es-header">
                <div className="es-title" style={{ color: '#ef4444' }}>
                    <Shield size={20} /> ENGINE DISCONNECTED
                </div>
            </div>
        </div>
    );

    const getModeColor = (mode) => {
        if (mode === 'Stable' || mode === 'Safe') return 'status-green';
        if (mode === 'Learning') return 'status-yellow';
        return 'status-red';
    };

    return (
        <div className="engine-status-card glass-panel">
            <div className="es-header">
                <div className="es-title">
                    <Shield size={20} className="es-icon-main" />
                    AI ENGINE STATUS
                </div>
                <div className="es-feature-info">
                    <span className="badge">Feature v{status.feature_version}</span>
                    <span className="badge hash">#{status.layout_hash.toString(16).toUpperCase().substring(0, 8)}</span>
                </div>
            </div>

            <div className="es-grid">
                {/* AI Model */}
                <div className={`es-section ${status.model.loaded ? 'status-green' : 'status-yellow'}`}>
                    <div className="es-label"><Cpu size={14} /> AI MODEL</div>
                    <div className="es-row">
                        <span>Engine:</span> <span className="value bold">{status.model.engine}</span>
                    </div>
                    <div className="es-row">
                        <span>Version:</span> <span className="value bold">{status.model.model_version || "Native"}</span>
                    </div>
                    <div className="es-row">
                        <span>Trained on:</span> <span className="value">{status.model.trained_on_records ? status.model.trained_on_records.toLocaleString() : "Pre-trained"}</span>
                    </div>
                    <div className="es-row">
                        <span>Status:</span> <span className="value">{status.model.loaded ? "Active" : "Fallback"}</span>
                    </div>
                </div>
                {/* Baseline */}
                <div className={`es-section ${getModeColor(status.baseline.mode)}`}>
                    <div className="es-label"><Activity size={14} /> BASELINE</div>
                    <div className="es-row">
                        <span>Mode:</span> <span className="value bold">{status.baseline.mode}</span>
                    </div>
                    <div className="es-row">
                        <span>Samples:</span> <span className="value">{status.baseline.samples}</span>
                    </div>
                    {status.baseline.last_reset_reason && (
                        <div className="es-row reset-reason" style={{ color: '#f87171' }}>
                            Since Reset
                        </div>
                    )}
                </div>

                {/* Dataset Inspector (P2.2.2) */}
                <div className="dataset-inspector es-section">
                    <div className="es-label"><Database size={14} /> DATASET INSPECTOR</div>
                    <div className="ds-stats">
                        <div className="stat-big">
                            <span className="label">Total Records</span>
                            <span className="value">{status.dataset.total_records.toLocaleString()}</span>
                        </div>
                        <div className="ds-distribution">
                            <div className="dist-row benign">
                                <span style={{ width: '70px' }}>Benign</span>
                                <div className="bar"><div style={{ width: `${((status.dataset.benign_count / (status.dataset.total_records || 1)) * 100).toFixed(0)}%` }}></div></div>
                                <span className="pct">{((status.dataset.benign_count / (status.dataset.total_records || 1)) * 100).toFixed(0)}%</span>
                            </div>
                            <div className="dist-row suspicious">
                                <span style={{ width: '70px' }}>Suspicious</span>
                                <div className="bar"><div style={{ width: `${((status.dataset.suspicious_count / (status.dataset.total_records || 1)) * 100).toFixed(0)}%` }}></div></div>
                                <span className="pct">{((status.dataset.suspicious_count / (status.dataset.total_records || 1)) * 100).toFixed(0)}%</span>
                            </div>
                            <div className="dist-row malicious">
                                <span style={{ width: '70px' }}>Malicious</span>
                                <div className="bar"><div style={{ width: `${((status.dataset.malicious_count / (status.dataset.total_records || 1)) * 100).toFixed(0)}%` }}></div></div>
                                <span className="pct">{((status.dataset.malicious_count / (status.dataset.total_records || 1)) * 100).toFixed(0)}%</span>
                            </div>
                        </div>
                        <button className="btn-export" onClick={async () => {
                            try {
                                const api = await import('../services/tauriApi');
                                const msg = await api.invoke('export_dataset', { path: "" });
                                alert(msg);
                            } catch (e) {
                                alert("Export failed: " + e);
                            }
                        }}>
                            Export Dataset
                        </button>
                    </div>
                </div>
            </div>

            {/* Model */}
            <div className="es-footer">
                <div className="es-footer-section">
                    <div className="es-label" style={{ marginBottom: 0 }}><Cpu size={14} /> MODEL</div>
                </div>
                <div className="es-footer-section">
                    <span className={`value bold ${status.model.engine === 'ONNX' ? 'text-green' : 'text-yellow'}`}>
                        {status.model.engine}
                    </span>
                    <span className="badge">v{status.model.model_version || "N/A"}</span>
                </div>
            </div>
        </div>
    );
}
