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
    Key,
    Users,
} from 'lucide-react';
import { useOrg } from '../../context/OrgContext';
import './Sidebar.css';

// Base nav items (always shown)
const baseNavItems = [
    { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/agents', icon: Monitor, label: 'Agents' },
    { path: '/incidents', icon: AlertTriangle, label: 'Incidents' },
];

// Organization-only nav items
const orgNavItems = [
    { path: '/tokens', icon: Key, label: 'Tokens', feature: 'can_create_tokens' },
    { path: '/users', icon: Users, label: 'Users', feature: 'can_manage_users' },
];

// Common nav items (always shown)
const commonNavItems = [
    { path: '/policies', icon: FileText, label: 'Policies' },
    { path: '/reports', icon: FileText, label: 'Reports' },
    { path: '/settings', icon: Settings, label: 'Settings' },
];

export default function Sidebar() {
    const location = useLocation();
    const { isOrganization, canCreateTokens, tier, loading } = useOrg();

    // Build nav items based on tier
    const navItems = [
        ...baseNavItems,
        // Only show org items for organization tier
        ...(isOrganization ? orgNavItems : []),
        ...commonNavItems,
    ];

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

            {/* Tier Badge */}
            {!loading && tier && (
                <div className="tier-badge-container">
                    <span className={`tier-badge tier-${tier.replace('_', '-')}`}>
                        {tier === 'organization' ? '🏢 Organization' :
                            tier === 'personal_pro' ? '⭐ Pro' :
                                tier === 'personal_free' ? '👤 Free' : tier}
                    </span>
                </div>
            )}

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

