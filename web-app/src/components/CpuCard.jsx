import { Cpu } from 'lucide-react'

export default function CpuCard({ usage, cpuName }) {
    const getUsageColor = (val) => {
        if (val > 80) return 'danger'
        if (val > 50) return 'warning'
        return 'success'
    }

    const shortName = cpuName
        ? cpuName.replace(/\(R\)|\(TM\)|CPU|@.*$/gi, '').trim()
        : 'Unknown CPU'

    return (
        <div className="detail-card">
            <div className="detail-card-header">
                <div className="detail-card-icon cpu">
                    <Cpu size={22} />
                </div>
                <div className="detail-card-title">
                    <span className="title">CPU</span>
                    <span className="subtitle">{shortName}</span>
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
                    <span className="stat-label">Status</span>
                    <span className={`stat-value ${getUsageColor(usage)}`}>
                        {usage > 80 ? 'High' : usage > 50 ? 'Moderate' : 'Normal'}
                    </span>
                </div>
            </div>
        </div>
    )
}
