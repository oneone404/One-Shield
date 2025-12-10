import { Activity } from 'lucide-react'

export default function ProcessesCard({ count, summaries }) {
    return (
        <div className="detail-card">
            <div className="detail-card-header">
                <div className="detail-card-icon processes">
                    <Activity size={22} />
                </div>
                <div className="detail-card-title">
                    <span className="title">PROCESSES</span>
                    <span className="subtitle">Active Tasks</span>
                </div>
                <div className="detail-card-value neutral">
                    {count}
                </div>
            </div>
            <div className="detail-card-stats">
                <div className="stat-item">
                    <span className="stat-label">Summaries</span>
                    <span className="stat-value">{summaries}</span>
                </div>
                <div className="stat-item">
                    <span className="stat-label">Status</span>
                    <span className="stat-value success">Monitoring</span>
                </div>
            </div>
        </div>
    )
}
