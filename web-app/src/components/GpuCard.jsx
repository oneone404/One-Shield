import { Zap, Thermometer, Fan } from 'lucide-react'

export default function GpuCard({ gpu }) {
    if (!gpu?.available) {
        return (
            <div className="detail-card gpu-card">
                <div className="detail-card-header">
                    <div className="detail-card-icon gpu inactive">
                        <Zap size={22} />
                    </div>
                    <div className="detail-card-title">
                        <span className="title">GPU</span>
                        <span className="subtitle">Not Detected</span>
                    </div>
                </div>
            </div>
        )
    }

    return (
        <div className="detail-card gpu-card">
            <div className="detail-card-header">
                <div className="detail-card-icon gpu">
                    <Zap size={22} />
                </div>
                <div className="detail-card-title">
                    <span className="title">GPU</span>
                    <span className="subtitle">{gpu.name || 'NVIDIA GPU'}</span>
                </div>
                {gpu.driver_version && (
                    <span className="badge-subtle">v{gpu.driver_version}</span>
                )}
            </div>

            <div className="gpu-bars">
                <div className="gpu-bar-row">
                    <span className="bar-label">Core</span>
                    <div className="bar-track">
                        <div
                            className="bar-fill usage"
                            style={{ width: `${Math.min(gpu.gpu_usage || 0, 100)}%` }}
                        />
                    </div>
                    <span className="bar-value">{(gpu.gpu_usage || 0).toFixed(0)}%</span>
                </div>
                <div className="gpu-bar-row">
                    <span className="bar-label">VRAM</span>
                    <div className="bar-track">
                        <div
                            className="bar-fill memory"
                            style={{ width: `${Math.min(gpu.memory_usage || 0, 100)}%` }}
                        />
                    </div>
                    <span className="bar-value">
                        {((gpu.memory_used_mb || 0) / 1024).toFixed(1)}/{((gpu.memory_total_mb || 0) / 1024).toFixed(0)}G
                    </span>
                </div>
            </div>

            <div className="detail-card-stats">
                <div className="stat-item">
                    <Thermometer size={14} />
                    <span className="stat-value">{(gpu.temperature || 0).toFixed(0)}°C</span>
                </div>
                <div className="stat-item">
                    <Zap size={14} />
                    <span className="stat-value">{(gpu.power_draw || 0).toFixed(0)}W</span>
                </div>
                <div className="stat-item">
                    <Fan size={14} />
                    <span className="stat-value">{(gpu.fan_speed || 0).toFixed(0)}%</span>
                </div>
            </div>
        </div>
    )
}
