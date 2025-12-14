import { Search, Bell, Play, Square, Sun, Moon, LogIn } from 'lucide-react'
import CloudStatus from './CloudStatus'
import TierBadge from './TierBadge'
import UserMenu from './UserMenu'

export default function Header({
    title = 'Dashboard',
    isMonitoring = false,
    onToggleMonitoring,
    pendingActionsCount = 0,
    onShowPendingActions,
    theme,
    onToggleTheme,
    isAuthenticated = false,
    onShowAuth,
    onLogout,
    onNavigate
}) {
    return (
        <header className="header">
            {/* Left - Title (Fixed) */}
            <div className="header-left">
                <h1 className="header-title">{title}</h1>
            </div>

            {/* Right - All Controls */}
            <div className="header-right">
                {/* Cloud Status Indicator */}
                <CloudStatus compact={true} />

                {/* Tier Badge */}
                {isAuthenticated && <TierBadge compact={true} />}

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

                {/* Auth Button or User Menu */}
                {isAuthenticated ? (
                    <UserMenu
                        isAuthenticated={isAuthenticated}
                        onLogout={onLogout}
                        onNavigate={onNavigate}
                    />
                ) : (
                    <button
                        className="header-btn not-authenticated"
                        onClick={onShowAuth}
                        title="Sign In"
                    >
                        <LogIn size={18} />
                        <span className="login-text">Sign In</span>
                    </button>
                )}

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
