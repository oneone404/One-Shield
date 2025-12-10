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

                {/* Dataset */}
                <div className="es-section status-blue">
                    <div className="es-label"><Database size={14} /> DATASET</div>
                    <div className="es-row">
                        <span>Records:</span> <span className="value">{status.dataset.total_records.toLocaleString()}</span>
                    </div>
                    <div className="es-row">
                        <span>Current File:</span> <span className="value" style={{ fontSize: '0.7rem' }}>{status.dataset.current_file}</span>
                    </div>
                    <div className="es-row">
                        <span>Size:</span> <span className="value">{status.dataset.total_size_mb.toFixed(2)} MB</span>
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
