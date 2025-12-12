import { NavLink, useLocation } from 'react-router-dom';
import {
    LayoutDashboard,
    Monitor,
    AlertTriangle,
    FileText,
    Settings,
    Shield,
    LogOut,
    ChevronRight,
} from 'lucide-react';
import './Sidebar.css';

const navItems = [
    { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/agents', icon: Monitor, label: 'Agents' },
    { path: '/incidents', icon: AlertTriangle, label: 'Incidents' },
    { path: '/policies', icon: FileText, label: 'Policies' },
    { path: '/reports', icon: FileText, label: 'Reports' },
    { path: '/settings', icon: Settings, label: 'Settings' },
];

export default function Sidebar() {
    const location = useLocation();

    return (
        <aside className="sidebar">
            {/* Logo Section */}
            <div className="sidebar-header">
                <div className="logo">
                    <Shield className="logo-icon" />
                    <div className="logo-text">
                        <span className="logo-title">One-Shield</span>
                        <span className="logo-subtitle">Cloud Console</span>
                    </div>
                </div>
            </div>

            {/* Navigation */}
            <nav className="sidebar-nav">
                <ul className="nav-list">
                    {navItems.map((item) => {
                        const Icon = item.icon;
                        const isActive = location.pathname === item.path;

                        return (
                            <li key={item.path}>
                                <NavLink
                                    to={item.path}
                                    className={`nav-item ${isActive ? 'active' : ''}`}
                                >
                                    <Icon className="nav-icon" size={20} />
                                    <span className="nav-label">{item.label}</span>
                                    {isActive && <ChevronRight className="nav-indicator" size={16} />}
                                </NavLink>
                            </li>
                        );
                    })}
                </ul>
            </nav>

            {/* Footer */}
            <div className="sidebar-footer">
                <div className="user-info">
                    <div className="user-avatar">
                        <span>A</span>
                    </div>
                    <div className="user-details">
                        <span className="user-name">Admin</span>
                        <span className="user-role">Administrator</span>
                    </div>
                </div>
                <button className="logout-btn" title="Logout">
                    <LogOut size={18} />
                </button>
            </div>
        </aside>
    );
}
