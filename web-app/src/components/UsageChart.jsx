import { useState, useEffect, useRef } from 'react'
import { Cpu, MemoryStick, Zap } from 'lucide-react'

const TIME_OPTIONS = [
    { label: '60S', value: 60, interval: 1000 },  // 60 giây, mỗi giây
]

// Màu mới: Đỏ, Xanh biển, Tím
const METRICS = [
    { key: 'cpu', label: 'CPU', color: '#ef4444', icon: Cpu },        // Đỏ
    { key: 'memory', label: 'RAM', color: '#3b82f6', icon: MemoryStick }, // Xanh biển
    { key: 'gpu', label: 'GPU', color: '#8b5cf6', icon: Zap },        // Tím
]

export default function UsageChart({ cpuUsage = 0, memoryUsage = 0, gpuUsage = 0 }) {
    const [timeRange, setTimeRange] = useState(0)
    const [history, setHistory] = useState({
        cpu: [],
        memory: [],
        gpu: [],
    })
    const [activeMetrics, setActiveMetrics] = useState(['cpu', 'memory', 'gpu'])
    const [isVisible, setIsVisible] = useState(true)
    const canvasRef = useRef(null)
    const maxPoints = TIME_OPTIONS[timeRange].value / (TIME_OPTIONS[timeRange].interval / 1000)

    // Visibility check - pause when tab hidden
    useEffect(() => {
        const handleVisibilityChange = () => {
            setIsVisible(!document.hidden)
        }
        document.addEventListener('visibilitychange', handleVisibilityChange)
        return () => document.removeEventListener('visibilitychange', handleVisibilityChange)
    }, [])

    // Collect data - only when visible
    useEffect(() => {
        if (!isVisible) return

        const interval = setInterval(() => {
            const now = Date.now()
            setHistory(prev => ({
                cpu: [...prev.cpu.slice(-maxPoints + 1), { time: now, value: cpuUsage }],
                memory: [...prev.memory.slice(-maxPoints + 1), { time: now, value: memoryUsage }],
                gpu: [...prev.gpu.slice(-maxPoints + 1), { time: now, value: gpuUsage }],
            }))
        }, TIME_OPTIONS[timeRange].interval)

        return () => clearInterval(interval)
    }, [cpuUsage, memoryUsage, gpuUsage, timeRange, maxPoints, isVisible])

    // Clear history when time range changes
    useEffect(() => {
        setHistory({ cpu: [], memory: [], gpu: [] })
    }, [timeRange])

    // Draw chart with requestAnimationFrame
    useEffect(() => {
        if (!isVisible) return

        const canvas = canvasRef.current
        if (!canvas) return

        const draw = () => {
            const ctx = canvas.getContext('2d')
            const dpr = window.devicePixelRatio || 1
            const rect = canvas.getBoundingClientRect()

            canvas.width = rect.width * dpr
            canvas.height = rect.height * dpr
            ctx.scale(dpr, dpr)

            const width = rect.width
            const height = rect.height
            const padding = { top: 10, right: 10, bottom: 10, left: 35 }
            const chartWidth = width - padding.left - padding.right
            const chartHeight = height - padding.top - padding.bottom

            // Clear
            ctx.clearRect(0, 0, width, height)

            // Grid lines
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)'
            ctx.lineWidth = 1
            for (let i = 0; i <= 4; i++) {
                const y = padding.top + (chartHeight / 4) * i
                ctx.beginPath()
                ctx.moveTo(padding.left, y)
                ctx.lineTo(width - padding.right, y)
                ctx.stroke()
            }

            // Y-axis labels
            ctx.fillStyle = 'rgba(255, 255, 255, 0.4)'
            ctx.font = '10px Inter, sans-serif'
            ctx.textAlign = 'right'
            for (let i = 0; i <= 4; i++) {
                const y = padding.top + (chartHeight / 4) * i
                ctx.fillText(`${100 - i * 25}%`, padding.left - 5, y + 3)
            }

            // Draw lines for each active metric
            METRICS.forEach(metric => {
                if (!activeMetrics.includes(metric.key)) return

                const data = history[metric.key]
                if (data.length < 2) return

                ctx.strokeStyle = metric.color
                ctx.lineWidth = 2
                ctx.lineCap = 'round'
                ctx.lineJoin = 'round'
                ctx.beginPath()

                data.forEach((point, i) => {
                    const x = padding.left + (i / (maxPoints - 1)) * chartWidth
                    const y = padding.top + ((100 - point.value) / 100) * chartHeight

                    if (i === 0) {
                        ctx.moveTo(x, y)
                    } else {
                        ctx.lineTo(x, y)
                    }
                })
                ctx.stroke()

                // Gradient fill
                const gradient = ctx.createLinearGradient(0, padding.top, 0, height - padding.bottom)
                gradient.addColorStop(0, metric.color + '25')
                gradient.addColorStop(1, metric.color + '00')

                ctx.fillStyle = gradient
                ctx.beginPath()
                data.forEach((point, i) => {
                    const x = padding.left + (i / (maxPoints - 1)) * chartWidth
                    const y = padding.top + ((100 - point.value) / 100) * chartHeight
                    if (i === 0) {
                        ctx.moveTo(x, y)
                    } else {
                        ctx.lineTo(x, y)
                    }
                })
                const lastX = padding.left + ((data.length - 1) / (maxPoints - 1)) * chartWidth
                ctx.lineTo(lastX, height - padding.bottom)
                ctx.lineTo(padding.left, height - padding.bottom)
                ctx.closePath()
                ctx.fill()
            })
        }

        requestAnimationFrame(draw)
    }, [history, activeMetrics, timeRange, maxPoints, isVisible])

    const toggleMetric = (key) => {
        setActiveMetrics(prev =>
            prev.includes(key)
                ? prev.filter(k => k !== key)
                : [...prev, key]
        )
    }

    return (
        <div className="usage-chart-card">
            <div className="chart-header">
                <h4>PERFORMANCE</h4>
                <span className="chart-time-label">60S</span>
            </div>

            <div className="chart-container">
                <canvas ref={canvasRef} className="usage-canvas" />
            </div>

            <div className="chart-legend">
                {METRICS.map(metric => {
                    const Icon = metric.icon
                    const isActive = activeMetrics.includes(metric.key)
                    return (
                        <button
                            key={metric.key}
                            className={`legend-item ${isActive ? 'active' : ''}`}
                            onClick={() => toggleMetric(metric.key)}
                            style={{ '--metric-color': metric.color }}
                        >
                            <span className="legend-dot" />
                            <Icon size={14} />
                            <span>{metric.label}</span>
                        </button>
                    )
                })}
            </div>
        </div>
    )
}
