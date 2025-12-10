import { useState, useEffect } from 'react'
import * as api from '../services/tauriApi'

// Components
import {
    CpuCard,
    MemoryCard,
    ProcessesCard,
    NetworkCard,
    GpuCard,
    AiStatusCard,
    AiEngineStatus,
    UsageChart,
    IncidentPanel
} from '../components'

/* ============================================================================
   MAIN DASHBOARD
   ============================================================================ */

export default function Dashboard({ isMonitoring }) {
    const [stats, setStats] = useState({
        cpu: 0,
        cpuName: '',
        memory: 0,
        memoryUsedMb: 0,
        memoryTotalMb: 0,
        processCount: 0,
        summaryCount: 0,
        networkSent: 0,
        networkRecv: 0
    })
    const [gpu, setGpu] = useState(null)
    const [aiStatus, setAiStatus] = useState(null)
    const [isVisible, setIsVisible] = useState(true)

    // Visibility check - pause polling when tab is hidden
    useEffect(() => {
        const handleVisibilityChange = () => {
            setIsVisible(!document.hidden)
        }
        document.addEventListener('visibilitychange', handleVisibilityChange)
        return () => document.removeEventListener('visibilitychange', handleVisibilityChange)
    }, [])

    // Poll system status - only when visible
    useEffect(() => {
        if (!isVisible) return

        const fetchStats = async () => {
            try {
                const status = await api.getSystemStatus()
                setStats({
                    cpu: status.cpu_usage || 0,
                    cpuName: status.cpu_name || '',
                    memory: status.memory_usage || 0,
                    memoryUsedMb: status.memory_used_mb || 0,
                    memoryTotalMb: status.memory_total_mb || 0,
                    processCount: status.process_count || 0,
                    summaryCount: status.summaries_created || 0,
                    networkSent: status.network_sent_rate || 0,
                    networkRecv: status.network_recv_rate || 0
                })
            } catch (error) {
                // Silently fail
            }
        }
        fetchStats()
        const interval = setInterval(fetchStats, 2000)
        return () => clearInterval(interval)
    }, [isVisible])

    // Poll GPU - only when visible, 5s interval
    useEffect(() => {
        if (!isVisible) return

        const fetchGpu = async () => {
            try {
                const [gpuInfo, gpuMetrics] = await Promise.all([
                    api.getGpuInfo(),
                    api.getGpuMetrics()
                ])
                setGpu({
                    ...gpuInfo,
                    ...gpuMetrics,
                    available: gpuInfo?.available || gpuMetrics?.available || false
                })
            } catch (error) {
                setGpu({ available: false })
            }
        }
        fetchGpu()
        const interval = setInterval(fetchGpu, 5000)
        return () => clearInterval(interval)
    }, [isVisible])

    // Poll AI status - only when visible, 5s interval
    useEffect(() => {
        if (!isVisible) return

        const fetchAi = async () => {
            try {
                const aiData = await api.getAiStatus()
                setAiStatus(aiData)
            } catch (error) {
                // Silently fail
            }
        }
        fetchAi()
        const interval = setInterval(fetchAi, 5000)
        return () => clearInterval(interval)
    }, [isVisible])

    return (
        <div className="dashboard-container">
            {/* AI Engine Observability (P2.1) */}
            <AiEngineStatus />

            {/* Incident Monitor (P3.1) */}
            <IncidentPanel />

            {/* Main Stats Grid */}
            <div className="dashboard-grid">
                <CpuCard usage={stats.cpu} cpuName={stats.cpuName} />
                <MemoryCard
                    usage={stats.memory}
                    usedMb={stats.memoryUsedMb}
                    totalMb={stats.memoryTotalMb}
                />
                <ProcessesCard
                    count={stats.processCount}
                    summaries={stats.summaryCount}
                />
                <NetworkCard
                    upload={stats.networkSent}
                    download={stats.networkRecv}
                />
            </div>

            {/* Hardware & AI Section */}
            <div className="dashboard-grid-2">
                <GpuCard gpu={gpu} />
                <AiStatusCard aiStatus={aiStatus} />
            </div>

            {/* Usage Chart */}
            <UsageChart
                cpuUsage={stats.cpu}
                memoryUsage={stats.memory}
                gpuUsage={gpu?.gpu_usage || 0}
            />
        </div>
    )
}
