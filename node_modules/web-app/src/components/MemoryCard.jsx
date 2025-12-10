import { MemoryStick } from 'lucide-react'

export default function MemoryCard({ usage, usedMb, totalMb }) {
    const usedGb = (usedMb || 0) / 1024
    const totalGb = (totalMb || 0) / 1024

    const getUsageColor = (val) => {
        if (val > 85) return 'danger'
        if (val > 60) return 'warning'
        return 'success'
    }

    return (
        <div className="detail-card">
            <div className="detail-card-header">
                <div className="detail-card-icon memory">
                    <MemoryStick size={22} />
                </div>
                <div className="detail-card-title">
                    <span className="title">MEMORY</span>
                    <span className="subtitle">RAM Usage</span>
                </div>
                <div className={`detail-card-value ${getUsageColor(usage)}`}>
                    {usage.toFixed(1)}%
                </div>
            </div>
            <div className="detail-card-bar">
                <div
                    className={`detail-card-fill ${getUsageColor(usage)}`}
                    style={{ width: `${Math.min(usage, 100)}%` }}
                />
            </div>
            <div className="detail-card-stats">
                <div className="stat-item">
                    <span className="stat-label">Used</span>
                    <span className="stat-value">{usedGb.toFixed(1)} GB</span>
                </div>
                <div className="stat-item">
                    <span className="stat-label">Total</span>
                    <span className="stat-value">{totalGb.toFixed(0)} GB</span>
                </div>
            </div>
        </div>
    )
}
