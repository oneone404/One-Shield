import { BrainCircuit, Database } from 'lucide-react'

export default function AiStatusCard({ aiStatus }) {
    const model = aiStatus?.model || {}
    const buffer = aiStatus?.buffer || {}

    return (
        <div className="detail-card ai-card">
            <div className="detail-card-header">
                <div className="detail-card-icon ai">
                    <BrainCircuit size={22} />
                </div>
                <div className="detail-card-title">
                    <span className="title">AI ENGINE</span>
                    <span className="subtitle">{model.loaded ? 'ONNX Runtime' : 'Fallback Mode'}</span>
                </div>
                <span className={`badge-${model.loaded ? 'success' : 'warning'}`}>
                    {model.loaded ? 'Active' : 'Fallback'}
                </span>
            </div>

            <div className="ai-info-grid">
                <div className="ai-info-item">
                    <span className="info-label">Model</span>
                    <span className="info-value">{model.type?.toUpperCase() || 'LSTM'}</span>
                </div>
                <div className="ai-info-item">
                    <span className="info-label">Features</span>
                    <span className="info-value">{model.features || 15}</span>
                </div>
                <div className="ai-info-item">
                    <span className="info-label">Threshold</span>
                    <span className="info-value">{(model.threshold || 0.7).toFixed(2)}</span>
                </div>
            </div>

            <div className="ai-buffer">
                <div className="ai-buffer-label">
                    <Database size={14} />
                    <span>Buffer</span>
                    <span className={`buffer-badge ${buffer.is_ready ? 'ready' : 'filling'}`}>
                        {buffer.is_ready ? 'Ready' : 'Filling'}
                    </span>
                </div>
                <div className="ai-buffer-track">
                    <div
                        className="ai-buffer-fill"
                        style={{ width: `${Math.min(buffer.fill_percent || 0, 100)}%` }}
                    />
                </div>
                <div className="ai-buffer-info">
                    <span>{buffer.current_size || 0}/{buffer.required_size || 5}</span>
                    <span>{(buffer.fill_percent || 0).toFixed(0)}%</span>
                </div>
            </div>
        </div>
    )
}
