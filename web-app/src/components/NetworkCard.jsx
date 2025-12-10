import { Wifi } from 'lucide-react'

export default function NetworkCard({ upload, download }) {
    const formatRate = (bytes) => {
        if (bytes > 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB/s`
        if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB/s`
        return `${bytes} B/s`
    }

    return (
        <div className="detail-card">
            <div className="detail-card-header">
                <div className="detail-card-icon network">
                    <Wifi size={22} />
                </div>
                <div className="detail-card-title">
                    <span className="title">NETWORK</span>
                    <span className="subtitle">I/O Activity</span>
                </div>
            </div>
            <div className="detail-card-stats network-stats">
                <div className="stat-item">
                    <span className="stat-label">↑ Upload</span>
                    <span className="stat-value success">{formatRate(upload)}</span>
                </div>
                <div className="stat-item">
                    <span className="stat-label">↓ Download</span>
                    <span className="stat-value primary">{formatRate(download)}</span>
                </div>
            </div>
        </div>
    )
}
