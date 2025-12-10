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
            {/* Left - Title (Fixed) */}
            <div className="header-left">
                <h1 className="header-title">{title}</h1>
            </div>

            {/* Right - All Controls */}
            <div className="header-right">
                {/* Search */}
                <div className="header-search">
                    <Search size={16} className="search-icon" />
                    <input
                        type="text"
                        className="search-input"
                        placeholder="Search..."
                    />
                </div>

                {/* Theme Toggle */}
                <button
                    className="header-btn"
                    onClick={onToggleTheme}
                    title={theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
                >
                    {theme === 'dark' ? <Moon size={18} /> : <Sun size={18} />}
                </button>

                {/* Notification */}
                <button
                    className="header-btn"
                    onClick={onShowPendingActions}
                    title="Notifications"
                >
                    <Bell size={18} />
                    {pendingActionsCount > 0 && (
                        <span className="header-badge">{pendingActionsCount}</span>
                    )}
                </button>

                {/* Start/Stop Monitoring */}
                <button
                    className={`header-btn ${isMonitoring ? 'active' : ''}`}
                    onClick={onToggleMonitoring}
                    title={isMonitoring ? 'Stop Monitoring' : 'Start Monitoring'}
                >
                    {isMonitoring ? (
                        <Square size={16} fill="currentColor" />
                    ) : (
                        <Play size={16} fill="currentColor" />
                    )}
                </button>
            </div>
        </header>
    )
}
