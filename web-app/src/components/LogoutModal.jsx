import { useState } from 'react';
import { LogOut, AlertTriangle, X, Loader2 } from 'lucide-react';
import api from '../services/tauriApi';
import './LogoutModal.css';

/**
 * LogoutModal - Confirmation modal for logout
 *
 * Props:
 * - isOpen: boolean
 * - onClose: () => void
 * - onLogoutSuccess: () => void - callback when logout completes
 */
export default function LogoutModal({ isOpen, onClose, onLogoutSuccess }) {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    if (!isOpen) return null;

    const handleLogout = async () => {
        setLoading(true);
        setError('');

        // Clear localStorage
        localStorage.removeItem('onboarding_complete');
        localStorage.removeItem('upgrade_banner_dismissed');

        try {
            const result = await api.invoke('user_logout');

            if (result && result.success) {
                // Notify parent to reset auth state
                if (onLogoutSuccess) {
                    onLogoutSuccess();
                }
                onClose();
            } else {
                setError('Logout failed. Please try again.');
            }
        } catch (e) {
            console.error('Logout error:', e);
            setError(typeof e === 'string' ? e : 'Failed to logout. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="logout-modal-overlay" onClick={onClose}>
            <div className="logout-modal" onClick={e => e.stopPropagation()}>
                <button className="logout-close" onClick={onClose} disabled={loading}>
                    <X size={20} />
                </button>

                <div className="logout-header">
                    <div className="logout-icon">
                        <AlertTriangle size={32} />
                    </div>
                    <h2>Logout</h2>
                    <p>Are you sure you want to logout?</p>
                </div>

                <div className="logout-info">
                    <div className="logout-info-item">
                        <span className="info-label">What will be cleared:</span>
                        <ul>
                            <li>Your login session</li>
                            <li>Cloud sync connection</li>
                            <li>Saved preferences</li>
                        </ul>
                    </div>
                    <div className="logout-info-item">
                        <span className="info-label">What will be kept:</span>
                        <ul>
                            <li>Security baselines</li>
                            <li>Training data</li>
                            <li>System settings</li>
                        </ul>
                    </div>
                </div>

                {error && (
                    <div className="logout-error">
                        <AlertTriangle size={16} />
                        <span>{error}</span>
                    </div>
                )}

                <div className="logout-actions">
                    <button
                        className="btn-cancel"
                        onClick={onClose}
                        disabled={loading}
                    >
                        Cancel
                    </button>
                    <button
                        className="btn-logout"
                        onClick={handleLogout}
                        disabled={loading}
                    >
                        {loading ? (
                            <>
                                <Loader2 size={18} className="spinner" />
                                Logging out...
                            </>
                        ) : (
                            <>
                                <LogOut size={18} />
                                Logout
                            </>
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
}
