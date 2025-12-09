import { useState, useEffect } from 'react'
import {
    Cpu, HardDrive, Activity, TrendingUp, Wifi, CheckCircle, AlertTriangle
} from 'lucide-react'
import * as api from '../services/tauriApi'

/* Helper Sub-components */
function StatCard({ icon: Icon, label, value, unit, color = 'purple' }) {
    return (
        <div className="stat-card">
            <div className={`stat-card-icon ${color}`}>
                <Icon size={28} strokeWidth={2} />
            </div>
            <div className="stat-card-info">
                <span className="stat-card-label">{label}</span>
                <div className="value-group">
                    <span className="stat-card-value">
                        {typeof value === 'number' ? value.toFixed(1) : value}
                    </span>
                    {unit && <span className="stat-card-unit">{unit}</span>}
                </div>
            </div>
        </div>
    )
}

function NetworkCard({ upload, download }) {
    return (
        <div className="network-card">
            <div className="network-card-header">
                <Wifi size={20} className="text-secondary" />
                <span>Network Activity</span>
            </div>
            <div className="network-card-stats">
                <div className="network-stat">
                    <span className="network-stat-label">Upload</span>
                    <span className="network-stat-value success">
                        {(upload / 1024).toFixed(2)} <span className="unit">KB/s</span>
                    </span>
                </div>
                <div className="network-stat">
                    <span className="network-stat-label">Download</span>
                    <span className="network-stat-value primary">
                        {(download / 1024).toFixed(2)} <span className="unit">KB/s</span>
                    </span>
                </div>
            </div>
        </div>
    )
}

export default function Dashboard({ isMonitoring }) {
    const [stats, setStats] = useState({
        cpu: 0,
        memory: 0,
        processCount: 0,
        summaryCount: 0,
        networkSent: 0,
        networkRecv: 0
    })

    // Poll system status
    useEffect(() => {
        const fetchStats = async () => {
            try {
                const status = await api.getSystemStatus()
                setStats({
                    cpu: status.cpu_usage || 0,
                    memory: status.memory_percent || 0,
                    processCount: status.process_count || 0,
                    summaryCount: status.summaries_created || 0,
                    networkSent: status.network_sent_rate || 0,
                    networkRecv: status.network_recv_rate || 0
                })
            } catch (error) {
                // Silently fail or log debug
            }
        }
        fetchStats()
        const interval = setInterval(fetchStats, 2000)
        return () => clearInterval(interval)
    }, [])

    return (
        <div className="dashboard-container">
            {/* Intro / Status Area */}
            <div className="dashboard-intro">
                <div className="welcome-text">
                    <h1>System Overview</h1>
                    <p>Real-time anomaly detection metrics</p>
                </div>
            </div>

            {/* Responsive Grid for Stats */}
            <div className="responsive-grid">
                <StatCard
                    icon={Cpu}
                    label="CPU Usage"
                    value={stats.cpu}
                    unit="%"
                    color="purple"
                />
                <StatCard
                    icon={HardDrive}
                    label="Memory"
                    value={stats.memory}
                    unit="%"
                    color="violet"
                />
                <StatCard
                    icon={Activity}
                    label="Processes"
                    value={stats.processCount}
                    unit=""
                    color="green"
                />
                <StatCard
                    icon={TrendingUp}
                    label="Summaries"
                    value={stats.summaryCount}
                    unit=""
                    color="orange"
                />
            </div>

            {/* Network & Info Section */}
            <div className="details-grid">
                <NetworkCard upload={stats.networkSent} download={stats.networkRecv} />

                {/* Model Info Card */}
                <div className="info-card-glass">
                    <div className="info-header">
                        <h4>AI Engine Status</h4>
                        <span className="badge-phase">Phase IV</span>
                    </div>
                    <p>Running ONNX Runtime (quantized). Monitoring {stats.processCount} active threads.</p>
                </div>
            </div>
        </div>
    )
}
