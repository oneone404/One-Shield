import {
    Home, Activity, Bell, Cpu,
    FileText, Database, Settings, Shield,
    ChevronsLeft, Menu
} from 'lucide-react'

const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Home },
    { id: 'monitoring', label: 'Monitoring', icon: Activity },
    { id: 'alerts', label: 'Alerts', icon: Bell },
    { id: 'processes', label: 'Processes', icon: Cpu },
    { id: 'logs', label: 'Logs', icon: FileText },
    { id: 'data', label: 'Training Data', icon: Database },
    { id: 'settings', label: 'Settings', icon: Settings },
]

export default function Sidebar({ activePage, onPageChange, collapsed, onToggle }) {
    return (
        <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
            {/* Header */}
            <div className="sidebar-header">
                {/* Logo Section */}
                <div className="logo-container" onClick={() => onPageChange('dashboard')}>
                    <div className="logo-icon">
                        <Shield size={22} strokeWidth={2.5} />
                    </div>
                    <span className="logo-text">AI Security</span>
                </div>

                {/* Toggle Button - Glass Style */}
                <button
                    className="sidebar-toggle-btn"
                    onClick={onToggle}
                    title={collapsed ? "Expand" : "Collapse"}
                >
                    {collapsed ? <Menu size={18} /> : <ChevronsLeft size={18} />}
                </button>
            </div>

            {/* Navigation */}
            <nav className="sidebar-nav">
                {menuItems.map((item) => {
                    const Icon = item.icon
                    const isActive = activePage === item.id
                    return (
                        <button
                            key={item.id}
                            className={`nav-item ${isActive ? 'active' : ''}`}
                            onClick={() => onPageChange(item.id)}
                            title={collapsed ? item.label : ''}
                        >
                            <div className="nav-icon-container">
                                <Icon size={20} strokeWidth={isActive ? 2.5 : 2} />
                            </div>
                            <span className="nav-label">{item.label}</span>

                            {isActive && <div className="active-glow" />}
                        </button>
                    )
                })}
            </nav>

            {/* Footer */}
            <div className="sidebar-footer">
                <div className="version-pill">
                    <span className="v-text">v0.4.0</span>
                </div>
            </div>
        </aside>
    )
}
