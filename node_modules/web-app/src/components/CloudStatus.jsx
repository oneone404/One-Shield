import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { Cloud, CloudOff, RefreshCw, Server, Wifi, WifiOff } from 'lucide-react'

/**
 * CloudStatus - Hiển thị trạng thái kết nối Cloud
 *
 * Features:
 * - Real-time connection status
 * - Agent registration info
 * - Heartbeat count
 * - Last sync time
 */
export default function CloudStatus({ compact = false }) {
    const [status, setStatus] = useState(null)
    const [isLoading, setIsLoading] = useState(true)
    const [error, setError] = useState(null)

    // Fetch cloud status
    const fetchStatus = async () => {
        try {
            const result = await invoke('get_cloud_sync_status')
            setStatus(result)
            setError(null)
        } catch (err) {
            console.error('Failed to get cloud status:', err)
            setError(err.toString())
        } finally {
            setIsLoading(false)
        }
    }

    // Initial fetch and interval
    useEffect(() => {
        fetchStatus()

        // Update every 10 seconds
        const interval = setInterval(fetchStatus, 10000)
        return () => clearInterval(interval)
    }, [])

    // Compact mode - just an indicator in header
    if (compact) {
        // Need both connected AND registered to show green
        const isActive = status?.is_connected && status?.is_registered;
        const needsLogin = !status?.is_registered && status?.errors?.some(e => e.includes('authentication'));

        let title = 'Cloud: Checking...';
        if (isActive) {
            title = `Cloud: Connected (${status?.heartbeat_count || 0} heartbeats)`;
        } else if (needsLogin) {
            title = 'Cloud: Sign in required';
        } else if (!status?.is_registered) {
            title = 'Cloud: Not registered';
        } else {
            title = 'Cloud: Disconnected';
        }

        return (
            <div
                className={`cloud-status-compact ${isActive ? 'connected' : 'disconnected'}`}
                title={title}
            >
                {isActive ? (
                    <Cloud size={18} className="cloud-icon connected" />
                ) : (
                    <CloudOff size={18} className="cloud-icon disconnected" />
                )}
            </div>
        )
    }

    // Full panel mode
    return (
        <div className="cloud-status-panel">
            <div className="cloud-status-header">
                <div className="cloud-status-title">
                    <Cloud size={20} />
                    <span>Cloud Sync</span>
                </div>
                <button
                    className="cloud-refresh-btn"
                    onClick={fetchStatus}
                    disabled={isLoading}
                    title="Refresh"
                >
                    <RefreshCw size={14} className={isLoading ? 'spinning' : ''} />
                </button>
            </div>

            <div className="cloud-status-content">
                {/* Connection Status */}
                <div className={`cloud-connection-status ${status?.is_connected ? 'connected' : 'disconnected'}`}>
                    {status?.is_connected ? (
                        <>
                            <Wifi size={24} />
                            <span>Connected</span>
                        </>
                    ) : (
                        <>
                            <WifiOff size={24} />
                            <span>Disconnected</span>
                        </>
                    )}
                </div>

                {/* Stats Grid */}
                {status && (
                    <div className="cloud-stats-grid">
                        <div className="cloud-stat">
                            <div className="cloud-stat-value">
                                {status.is_registered ? '✅' : '❌'}
                            </div>
                            <div className="cloud-stat-label">Registered</div>
                        </div>

                        <div className="cloud-stat">
                            <div className="cloud-stat-value">
                                {status.heartbeat_count || 0}
                            </div>
                            <div className="cloud-stat-label">Heartbeats</div>
                        </div>

                        <div className="cloud-stat">
                            <div className="cloud-stat-value">
                                {status.incident_sync_count || 0}
                            </div>
                            <div className="cloud-stat-label">Synced</div>
                        </div>

                        <div className="cloud-stat">
                            <div className="cloud-stat-value">
                                {status.server_version || '-'}
                            </div>
                            <div className="cloud-stat-label">Server</div>
                        </div>
                    </div>
                )}

                {/* Agent Info */}
                {status?.agent_id && (
                    <div className="cloud-agent-info">
                        <Server size={14} />
                        <span className="agent-id" title={status.agent_id}>
                            {status.agent_id.slice(0, 8)}...
                        </span>
                    </div>
                )}

                {/* Last Sync */}
                {status?.last_heartbeat && (
                    <div className="cloud-last-sync">
                        Last heartbeat: {new Date(status.last_heartbeat).toLocaleTimeString()}
                    </div>
                )}

                {/* Errors */}
                {status?.errors?.length > 0 && (
                    <div className="cloud-errors">
                        {status.errors.slice(-2).map((err, i) => (
                            <div key={i} className="cloud-error">{err}</div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    )
}
