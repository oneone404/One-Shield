import { useState, useEffect, useRef } from 'react';
import { User, LogOut, Settings, ExternalLink, Shield, Crown, Building2 } from 'lucide-react';
import api from '../services/tauriApi';
import './UserMenu.css';

/**
 * UserMenu - Dropdown menu for user account actions
 *
 * Shows:
 * - User info (email, tier)
 * - Open Dashboard link
 * - Settings link
 * - Logout
 */
export default function UserMenu({ isAuthenticated, onLogout, onNavigate }) {
    const [isOpen, setIsOpen] = useState(false);
    const [userInfo, setUserInfo] = useState(null);
    const menuRef = useRef(null);

    // Fetch user info when authenticated
    useEffect(() => {
        if (isAuthenticated) {
            fetchUserInfo();
        } else {
            setUserInfo(null);
        }
    }, [isAuthenticated]);

    // Close menu when clicking outside
    useEffect(() => {
        const handleClickOutside = (e) => {
            if (menuRef.current && !menuRef.current.contains(e.target)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const fetchUserInfo = async () => {
        try {
            const mode = await api.invoke('get_agent_mode');
            if (mode && mode.has_identity) {
                setUserInfo({
                    email: mode.org_name || 'User',
                    tier: mode.mode === 'organization' ? 'organization' : 'personal_free',
                    mode: mode.mode
                });
            }
        } catch (e) {
            console.error('Failed to fetch user info:', e);
        }
    };

    const getTierInfo = () => {
        if (!userInfo) return { label: 'Free', icon: Shield, color: 'tier-free' };

        switch (userInfo.tier) {
            case 'organization':
                return { label: 'Organization', icon: Building2, color: 'tier-org' };
            case 'personal_pro':
                return { label: 'Pro', icon: Crown, color: 'tier-pro' };
            default:
                return { label: 'Free', icon: Shield, color: 'tier-free' };
        }
    };

    const handleOpenDashboard = () => {
        window.open('https://dashboard.accone.vn', '_blank');
        setIsOpen(false);
    };

    const handleSettings = () => {
        if (onNavigate) onNavigate('settings');
        setIsOpen(false);
    };

    const handleLogout = () => {
        setIsOpen(false);
        if (onLogout) onLogout();
    };

    const tierInfo = getTierInfo();
    const TierIcon = tierInfo.icon;

    if (!isAuthenticated) {
        return null;
    }

    return (
        <div className="user-menu" ref={menuRef}>
            <button
                className="user-menu-trigger"
                onClick={() => setIsOpen(!isOpen)}
                title="Account menu"
            >
                <div className="user-avatar">
                    <User size={18} />
                </div>
            </button>

            {isOpen && (
                <div className="user-menu-dropdown">
                    {/* User Info Header */}
                    <div className="user-menu-header">
                        <div className="user-avatar-large">
                            <User size={24} />
                        </div>
                        <div className="user-info">
                            <span className="user-email">{userInfo?.email || 'User'}</span>
                            <span className={`user-tier ${tierInfo.color}`}>
                                <TierIcon size={12} />
                                {tierInfo.label}
                            </span>
                        </div>
                    </div>

                    <div className="user-menu-divider" />

                    {/* Menu Items */}
                    <div className="user-menu-items">
                        <button className="user-menu-item" onClick={handleOpenDashboard}>
                            <ExternalLink size={16} />
                            <span>Open Dashboard</span>
                        </button>

                        <button className="user-menu-item" onClick={handleSettings}>
                            <Settings size={16} />
                            <span>Account Settings</span>
                        </button>
                    </div>

                    <div className="user-menu-divider" />

                    {/* Logout */}
                    <div className="user-menu-items">
                        <button className="user-menu-item logout" onClick={handleLogout}>
                            <LogOut size={16} />
                            <span>Logout</span>
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}
