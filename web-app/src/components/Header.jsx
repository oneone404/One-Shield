import { Search, Bell, Play, Square, Sun, Moon } from 'lucide-react'

export default function Header({
    title = 'Dashboard',
    isMonitoring = false,
    onToggleMonitoring,
    pendingActionsCount = 0,
    onShowPendingActions,
    theme,
    onToggleTheme
}) {
    return (
        <header className="header">
            <div className="header-left">
                <h1 className="header-title">{title}</h1>
            </div>

            <div className="header-right">
                {/* Unified Search & Theme Bar */}
                <div className="header-search-group">
                    <Search className="search-icon" size={16} />
                    <input
                        type="text"
                        className="search-input"
                        placeholder="Search..."
                    />
                    <div className="search-divider"></div>
                    <button
                        className="theme-toggle-small"
                        onClick={onToggleTheme}
                        title="Toggle Theme"
                    >
                        {theme === 'dark' ? <Moon size={16} /> : <Sun size={16} />}
                    </button>
                </div>

                {/* Notification Bell */}
                <button
                    className="header-icon-btn"
                    onClick={onShowPendingActions}
                >
                    <Bell size={20} />
                    {pendingActionsCount > 0 && (
                        <span className="notification-badge">
                            {pendingActionsCount}
                        </span>
                    )}
                </button>

                {/* Status Actions */}
                <div className="status-actions">
                    <button
                        className={`control-btn ${isMonitoring ? 'stop' : 'start'}`}
                        onClick={onToggleMonitoring}
                    >
                        {isMonitoring ? (
                            <>
                                <Square size={16} fill="currentColor" />
                                <span>Stop Monitoring</span>
                            </>
                        ) : (
                            <>
                                <Play size={16} fill="currentColor" />
                                <span>Start Monitoring</span>
                            </>
                        )}
                    </button>
                </div>
            </div>
        </header>
    )
}
