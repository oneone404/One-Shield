import { useState, useEffect } from 'react';
import { api } from '../services/api';
import '../styles/tokens.css';

function TokensPage() {
    const [tokens, setTokens] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [showInstructionsModal, setShowInstructionsModal] = useState(false);
    const [newToken, setNewToken] = useState(null);
    const [copiedField, setCopiedField] = useState(null);

    // Fetch tokens on mount
    useEffect(() => {
        fetchTokens();
    }, []);

    const fetchTokens = async () => {
        try {
            setLoading(true);
            const response = await api.get('/tokens');
            setTokens(Array.isArray(response) ? response : [response]);
            setError(null);
        } catch (err) {
            console.error('Failed to fetch tokens:', err);
            setError('Failed to load tokens');
        } finally {
            setLoading(false);
        }
    };

    const handleCopy = async (text, field) => {
        try {
            await navigator.clipboard.writeText(text);
            setCopiedField(field);
            setTimeout(() => setCopiedField(null), 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    };

    const handleRevoke = async (tokenId) => {
        if (!window.confirm('Are you sure you want to revoke this token? This cannot be undone.')) {
            return;
        }

        try {
            await api.delete(`/tokens/${tokenId}`);
            await fetchTokens();
        } catch (err) {
            console.error('Failed to revoke token:', err);
            alert('Failed to revoke token');
        }
    };

    const formatDate = (dateString) => {
        if (!dateString) return 'Never';
        return new Date(dateString).toLocaleDateString('vi-VN', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    return (
        <div className="tokens-page">
            {/* Header */}
            <div className="tokens-header">
                <div className="tokens-title-section">
                    <h1 className="tokens-title">
                        <span className="tokens-icon">🔑</span>
                        Enrollment Tokens
                    </h1>
                    <p className="tokens-subtitle">
                        Manage tokens for enrolling agents into your organization
                    </p>
                </div>
                <button
                    className="btn-create-token"
                    onClick={() => setShowCreateModal(true)}
                >
                    <span className="btn-icon">+</span>
                    New Token
                </button>
            </div>

            {/* Error Message */}
            {error && (
                <div className="tokens-error">
                    <span className="error-icon">⚠️</span>
                    {error}
                    <button onClick={fetchTokens} className="retry-btn">Retry</button>
                </div>
            )}

            {/* Loading State */}
            {loading && (
                <div className="tokens-loading">
                    <div className="loading-spinner"></div>
                    <p>Loading tokens...</p>
                </div>
            )}

            {/* Empty State */}
            {!loading && tokens.length === 0 && (
                <div className="tokens-empty">
                    <div className="empty-icon">🎫</div>
                    <h3>No Enrollment Tokens Yet</h3>
                    <p>Create your first token to start enrolling agents</p>
                    <button
                        className="btn-create-token"
                        onClick={() => setShowCreateModal(true)}
                    >
                        <span className="btn-icon">+</span>
                        Create First Token
                    </button>
                </div>
            )}

            {/* Token List */}
            {!loading && tokens.length > 0 && (
                <div className="tokens-list">
                    {tokens.map(token => (
                        <div key={token.id} className={`token-card ${!token.is_active ? 'revoked' : ''}`}>
                            <div className="token-header">
                                <h3 className="token-name">{token.name}</h3>
                                <span className={`token-status ${token.is_active ? 'active' : 'revoked'}`}>
                                    {token.is_active ? '✓ Active' : '✗ Revoked'}
                                </span>
                            </div>

                            <div className="token-preview">
                                <code>{token.token_preview}</code>
                            </div>

                            <div className="token-stats">
                                <div className="stat">
                                    <span className="stat-label">Uses</span>
                                    <span className="stat-value">
                                        {token.uses_count} / {token.max_uses || '∞'}
                                    </span>
                                </div>
                                <div className="stat">
                                    <span className="stat-label">Expires</span>
                                    <span className="stat-value">
                                        {token.expires_at ? formatDate(token.expires_at) : 'Never'}
                                    </span>
                                </div>
                                <div className="stat">
                                    <span className="stat-label">Created</span>
                                    <span className="stat-value">{formatDate(token.created_at)}</span>
                                </div>
                            </div>

                            {token.is_active && (
                                <div className="token-actions">
                                    <button
                                        className="btn-revoke"
                                        onClick={() => handleRevoke(token.id)}
                                    >
                                        Revoke Token
                                    </button>
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}

            {/* Create Token Modal */}
            {showCreateModal && (
                <CreateTokenModal
                    onClose={() => setShowCreateModal(false)}
                    onCreated={(token) => {
                        setNewToken(token);
                        setShowCreateModal(false);
                        setShowInstructionsModal(true);
                        fetchTokens();
                    }}
                />
            )}

            {/* Install Instructions Modal */}
            {showInstructionsModal && newToken && (
                <InstallInstructionsModal
                    token={newToken}
                    onClose={() => {
                        setShowInstructionsModal(false);
                        setNewToken(null);
                    }}
                    onCopy={handleCopy}
                    copiedField={copiedField}
                />
            )}
        </div>
    );
}

// Create Token Modal Component
function CreateTokenModal({ onClose, onCreated }) {
    const [name, setName] = useState('');
    const [expiresInDays, setExpiresInDays] = useState('');
    const [maxUses, setMaxUses] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!name.trim()) {
            setError('Token name is required');
            return;
        }

        try {
            setLoading(true);
            setError(null);

            const payload = {
                name: name.trim(),
                expires_in_days: expiresInDays ? parseInt(expiresInDays) : null,
                max_uses: maxUses ? parseInt(maxUses) : null
            };

            const response = await api.post('/tokens', payload);
            onCreated(response);
        } catch (err) {
            console.error('Failed to create token:', err);
            setError(err.message || 'Failed to create token');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content" onClick={e => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>Create Enrollment Token</h2>
                    <button className="modal-close" onClick={onClose}>×</button>
                </div>

                <form onSubmit={handleSubmit} className="token-form">
                    {error && (
                        <div className="form-error">
                            <span>⚠️</span> {error}
                        </div>
                    )}

                    <div className="form-group">
                        <label htmlFor="name">Token Name *</label>
                        <input
                            type="text"
                            id="name"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            placeholder="e.g., Production Servers"
                            autoFocus
                        />
                        <span className="form-hint">A friendly name to identify this token</span>
                    </div>

                    <div className="form-group">
                        <label htmlFor="expires">Expires In</label>
                        <select
                            id="expires"
                            value={expiresInDays}
                            onChange={(e) => setExpiresInDays(e.target.value)}
                        >
                            <option value="">Never</option>
                            <option value="7">7 days</option>
                            <option value="30">30 days</option>
                            <option value="90">90 days</option>
                            <option value="365">1 year</option>
                        </select>
                    </div>

                    <div className="form-group">
                        <label htmlFor="maxUses">Max Uses</label>
                        <input
                            type="number"
                            id="maxUses"
                            value={maxUses}
                            onChange={(e) => setMaxUses(e.target.value)}
                            placeholder="Unlimited"
                            min="1"
                        />
                        <span className="form-hint">Leave empty for unlimited uses</span>
                    </div>

                    <div className="form-actions">
                        <button type="button" className="btn-cancel" onClick={onClose}>
                            Cancel
                        </button>
                        <button type="submit" className="btn-create" disabled={loading}>
                            {loading ? 'Creating...' : 'Generate Token'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

// Install Instructions Modal Component
function InstallInstructionsModal({ token, onClose, onCopy, copiedField }) {
    const [activeTab, setActiveTab] = useState('powershell');

    const tabs = [
        { id: 'powershell', label: 'PowerShell' },
        { id: 'manual', label: 'Manual' },
        { id: 'url', label: 'URL' }
    ];

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content instructions-modal" onClick={e => e.stopPropagation()}>
                <div className="modal-header success">
                    <h2>🎉 Token Created Successfully!</h2>
                    <button className="modal-close" onClick={onClose}>×</button>
                </div>

                <div className="token-display">
                    <label>Your Enrollment Token</label>
                    <div className="token-value">
                        <code>{token.token}</code>
                        <button
                            className={`copy-btn ${copiedField === 'token' ? 'copied' : ''}`}
                            onClick={() => onCopy(token.token, 'token')}
                        >
                            {copiedField === 'token' ? '✓ Copied!' : '📋 Copy'}
                        </button>
                    </div>
                    <p className="token-warning">
                        ⚠️ Save this token now! You won't be able to see it again.
                    </p>
                </div>

                <div className="instructions-tabs">
                    {tabs.map(tab => (
                        <button
                            key={tab.id}
                            className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
                            onClick={() => setActiveTab(tab.id)}
                        >
                            {tab.label}
                        </button>
                    ))}
                </div>

                <div className="instructions-content">
                    {activeTab === 'powershell' && (
                        <div className="instruction-panel">
                            <h4>PowerShell Installation</h4>
                            <p>Run this command on the target machine:</p>
                            <div className="code-block">
                                <code>{token.install_command}</code>
                                <button
                                    className={`copy-btn ${copiedField === 'cmd' ? 'copied' : ''}`}
                                    onClick={() => onCopy(token.install_command, 'cmd')}
                                >
                                    {copiedField === 'cmd' ? '✓ Copied!' : '📋 Copy'}
                                </button>
                            </div>
                        </div>
                    )}

                    {activeTab === 'manual' && (
                        <div className="instruction-panel">
                            <h4>Manual Installation</h4>
                            <ol className="steps-list">
                                <li>Download OneShield from the releases page</li>
                                <li>Create a file at <code>%LOCALAPPDATA%\ai-security\enrollment_token.txt</code></li>
                                <li>Paste your token: <code>{token.token}</code></li>
                                <li>Run <code>OneShield.exe</code></li>
                            </ol>
                        </div>
                    )}

                    {activeTab === 'url' && (
                        <div className="instruction-panel">
                            <h4>Direct Install URL</h4>
                            <p>Share this URL to install with one click:</p>
                            <div className="code-block">
                                <code>{token.install_url}</code>
                                <button
                                    className={`copy-btn ${copiedField === 'url' ? 'copied' : ''}`}
                                    onClick={() => onCopy(token.install_url, 'url')}
                                >
                                    {copiedField === 'url' ? '✓ Copied!' : '📋 Copy'}
                                </button>
                            </div>
                        </div>
                    )}
                </div>

                <div className="modal-footer">
                    <button className="btn-done" onClick={onClose}>Done</button>
                </div>
            </div>
        </div>
    );
}

export default TokensPage;
