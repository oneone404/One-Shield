import { useState, useEffect } from 'react';
import { User, Shield, Mail, Clock, UserPlus, Crown, Eye } from 'lucide-react';
import { getOrganizationUsers } from '../services/api';
import { useOrg } from '../context/OrgContext';
import './Users.css';

export default function UsersPage() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const { isOrganization, canManageUsers } = useOrg();

    useEffect(() => {
        fetchUsers();
    }, []);

    const fetchUsers = async () => {
        try {
            setLoading(true);
            const data = await getOrganizationUsers();
            setUsers(Array.isArray(data) ? data : []);
            setError(null);
        } catch (err) {
            console.error('Failed to fetch users:', err);
            setError(err.message || 'Failed to load users');
        } finally {
            setLoading(false);
        }
    };

    const formatDate = (dateString) => {
        if (!dateString) return 'Never';
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);

        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins} min ago`;
        if (diffHours < 24) return `${diffHours} hours ago`;
        if (diffDays < 7) return `${diffDays} days ago`;

        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    };

    const getRoleBadge = (role) => {
        if (role === 'admin') {
            return (
                <span className="role-badge admin">
                    <Crown size={12} />
                    Admin
                </span>
            );
        }
        return (
            <span className="role-badge viewer">
                <Eye size={12} />
                Viewer
            </span>
        );
    };

    return (
        <div className="users-page">
            {/* Header */}
            <div className="users-header">
                <div className="users-title-section">
                    <h1 className="users-title">
                        <User className="title-icon" />
                        Organization Users
                    </h1>
                    <p className="users-subtitle">
                        Manage team members in your organization
                    </p>
                </div>

                <button
                    className="btn-invite"
                    disabled={!canManageUsers}
                    title={canManageUsers ? 'Invite new user' : 'Coming soon'}
                >
                    <UserPlus size={18} />
                    Invite User
                    {!canManageUsers && <span className="coming-soon">Soon</span>}
                </button>
            </div>

            {/* Error */}
            {error && (
                <div className="users-error">
                    <span>⚠️</span>
                    {error}
                    <button onClick={fetchUsers} className="retry-btn">Retry</button>
                </div>
            )}

            {/* Loading */}
            {loading && (
                <div className="users-loading">
                    <div className="loading-spinner"></div>
                    <p>Loading users...</p>
                </div>
            )}

            {/* Empty State */}
            {!loading && users.length === 0 && !error && (
                <div className="users-empty">
                    <div className="empty-icon">👥</div>
                    <h3>No Users Found</h3>
                    <p>You're the only member of this organization.</p>
                </div>
            )}

            {/* Users List */}
            {!loading && users.length > 0 && (
                <div className="users-grid">
                    {users.map(user => (
                        <div key={user.id} className="user-card">
                            <div className="user-avatar">
                                {user.name ? user.name.charAt(0).toUpperCase() : user.email.charAt(0).toUpperCase()}
                            </div>

                            <div className="user-info">
                                <div className="user-name-row">
                                    <h3 className="user-name">
                                        {user.name || 'Unnamed User'}
                                    </h3>
                                    {getRoleBadge(user.role)}
                                </div>

                                <div className="user-email">
                                    <Mail size={14} />
                                    {user.email}
                                </div>

                                <div className="user-meta">
                                    <div className="meta-item">
                                        <Clock size={12} />
                                        <span>Last login: {formatDate(user.last_login)}</span>
                                    </div>
                                    <div className="meta-item">
                                        <Shield size={12} />
                                        <span>Joined: {formatDate(user.created_at)}</span>
                                    </div>
                                </div>
                            </div>

                            <div className="user-status">
                                <span className={`status-dot ${user.is_active ? 'active' : 'inactive'}`}></span>
                                {user.is_active ? 'Active' : 'Inactive'}
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Info Banner for Personal tier */}
            {!isOrganization && (
                <div className="tier-info-banner">
                    <Shield size={20} />
                    <div>
                        <strong>Personal Plan</strong>
                        <p>Upgrade to Organization plan to invite team members and manage roles.</p>
                    </div>
                </div>
            )}
        </div>
    );
}
