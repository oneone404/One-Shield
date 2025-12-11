/**
 * Settings Page
 *
 * Configuration for Quarantine, Webhooks, and System Settings
 */

import React, { useState, useEffect } from 'react';
import {
    getQuarantinedFiles,
    restoreQuarantinedFile,
    deleteQuarantinedFile,
    getQuarantineStats,
    getWebhooks,
    addWebhook,
    removeWebhook,
    testWebhook
} from '../services/tauriApi';
import '../styles/pages/settings.css';

// Icons
const SettingsIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
);

const ShieldIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
);

const WebhookIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2" />
        <path d="m6 17 3.13-5.78c.53-.97.1-2.18-.5-3.1a4 4 0 1 1 6.89-4.06" />
        <path d="m12 6 3.13 5.73C15.66 12.7 16.9 13 18 13a4 4 0 0 1 0 8" />
    </svg>
);

const TrashIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="3 6 5 6 21 6" />
        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
    </svg>
);

const RestoreIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="1 4 1 10 7 10" />
        <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10" />
    </svg>
);

const PlusIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <line x1="12" y1="5" x2="12" y2="19" />
        <line x1="5" y1="12" x2="19" y2="12" />
    </svg>
);

const SendIcon = () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <line x1="22" y1="2" x2="11" y2="13" />
        <polygon points="22 2 15 22 11 13 2 9 22 2" />
    </svg>
);

export default function SettingsPage() {
    const [activeTab, setActiveTab] = useState('quarantine');

    return (
        <div className="settings-page">
            <div className="settings-header">
                <SettingsIcon />
                <h1>Settings</h1>
            </div>

            <div className="settings-tabs">
                <button
                    className={activeTab === 'quarantine' ? 'active' : ''}
                    onClick={() => setActiveTab('quarantine')}
                >
                    <ShieldIcon />
                    Quarantine
                </button>
                <button
                    className={activeTab === 'webhooks' ? 'active' : ''}
                    onClick={() => setActiveTab('webhooks')}
                >
                    <WebhookIcon />
                    Webhooks
                </button>
            </div>

            <div className="settings-content">
                {activeTab === 'quarantine' && <QuarantineSection />}
                {activeTab === 'webhooks' && <WebhooksSection />}
            </div>
        </div>
    );
}

// Quarantine Section Component
function QuarantineSection() {
    const [files, setFiles] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadData();
    }, []);

    const loadData = async () => {
        try {
            const [filesData, statsData] = await Promise.all([
                getQuarantinedFiles(),
                getQuarantineStats()
            ]);
            setFiles(filesData || []);
            setStats(statsData);
        } catch (error) {
            console.error('Failed to load quarantine data:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleRestore = async (id) => {
        if (!confirm('Restore this file to its original location?')) return;
        try {
            await restoreQuarantinedFile(id);
            loadData();
        } catch (error) {
            alert('Failed to restore file: ' + error);
        }
    };

    const handleDelete = async (id) => {
        if (!confirm('Permanently delete this file? This cannot be undone.')) return;
        try {
            await deleteQuarantinedFile(id);
            loadData();
        } catch (error) {
            alert('Failed to delete file: ' + error);
        }
    };

    const formatSize = (bytes) => {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    if (loading) {
        return <div className="section-loading">Loading quarantine data...</div>;
    }

    return (
        <div className="quarantine-section">
            <div className="section-header">
                <h2>File Quarantine</h2>
                <div className="quarantine-stats">
                    <span className="stat-item">
                        <strong>{stats?.total_files || 0}</strong> files
                    </span>
                    {stats?.total_size_mb && (
                        <span className="stat-item">
                            <strong>{stats.total_size_mb.toFixed(2)}</strong> MB
                        </span>
                    )}
                </div>
            </div>

            {files.length === 0 ? (
                <div className="empty-state">
                    <ShieldIcon />
                    <h3>No Quarantined Files</h3>
                    <p>Files detected as threats will appear here</p>
                </div>
            ) : (
                <div className="quarantine-list">
                    {files.map((file) => (
                        <div key={file.id} className="quarantine-item">
                            <div className="file-info">
                                <span className="file-name">{file.file_name}</span>
                                <span className="file-path">{file.original_path}</span>
                                <div className="file-meta">
                                    <span>{formatSize(file.file_size)}</span>
                                    <span>•</span>
                                    <span>{new Date(file.quarantined_at).toLocaleDateString()}</span>
                                    <span>•</span>
                                    <span className="reason">{file.reason}</span>
                                </div>
                            </div>
                            <div className="file-actions">
                                {file.can_restore && (
                                    <button
                                        className="btn-restore"
                                        onClick={() => handleRestore(file.id)}
                                        title="Restore file"
                                    >
                                        <RestoreIcon />
                                    </button>
                                )}
                                <button
                                    className="btn-delete"
                                    onClick={() => handleDelete(file.id)}
                                    title="Delete permanently"
                                >
                                    <TrashIcon />
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

// Webhooks Section Component
function WebhooksSection() {
    const [webhooks, setWebhooks] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showAddForm, setShowAddForm] = useState(false);
    const [testingId, setTestingId] = useState(null);

    // Form state
    const [newWebhook, setNewWebhook] = useState({
        name: '',
        url: '',
        platform: 'slack'
    });

    useEffect(() => {
        loadWebhooks();
    }, []);

    const loadWebhooks = async () => {
        try {
            const data = await getWebhooks();
            setWebhooks(data || []);
        } catch (error) {
            console.error('Failed to load webhooks:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleAdd = async (e) => {
        e.preventDefault();
        try {
            await addWebhook(newWebhook.name, newWebhook.url, newWebhook.platform);
            setNewWebhook({ name: '', url: '', platform: 'slack' });
            setShowAddForm(false);
            loadWebhooks();
        } catch (error) {
            alert('Failed to add webhook: ' + error);
        }
    };

    const handleRemove = async (name) => {
        if (!confirm(`Remove webhook "${name}"?`)) return;
        try {
            await removeWebhook(name);
            loadWebhooks();
        } catch (error) {
            alert('Failed to remove webhook: ' + error);
        }
    };

    const handleTest = async (name) => {
        setTestingId(name);
        try {
            const result = await testWebhook(name);
            alert(result.success ? 'Test message sent!' : 'Test failed');
        } catch (error) {
            alert('Test failed: ' + error);
        } finally {
            setTestingId(null);
        }
    };

    const getPlatformIcon = (platform) => {
        const iconStyle = { width: 24, height: 24 };
        switch (platform?.toLowerCase()) {
            case 'slack':
                return <svg style={iconStyle} viewBox="0 0 24 24" fill="currentColor"><path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z" /></svg>;
            case 'discord':
                return <svg style={iconStyle} viewBox="0 0 24 24" fill="currentColor"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" /></svg>;
            case 'telegram':
                return <svg style={iconStyle} viewBox="0 0 24 24" fill="currentColor"><path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z" /></svg>;
            case 'microsoftteams':
                return <svg style={iconStyle} viewBox="0 0 24 24" fill="currentColor"><path d="M20.625 8.073c-.156-.604-.579-1.099-1.156-1.354-.258-.112-.542-.165-.825-.165h-2.344V5.25c0-.834-.679-1.5-1.5-1.5h-1.8c-.825 0-1.5.666-1.5 1.5v1.304H8.813c-.284 0-.567.053-.825.165-.577.255-1 .75-1.156 1.354-.169.654-.077 1.302.254 1.821.297.461.753.825 1.282 1.017v6.339c0 .825.675 1.5 1.5 1.5h6.264c.825 0 1.5-.675 1.5-1.5v-6.339c.529-.192.985-.556 1.282-1.017.331-.519.423-1.167.254-1.821zm-7.125-2.823c0-.249.201-.45.45-.45h1.8c.249 0 .45.201.45.45v1.254h-2.7V5.25zM16.582 17.25H9.868a.45.45 0 0 1-.45-.45V11.1h7.614v5.7a.45.45 0 0 1-.45.45z" /><circle cx="6" cy="10.5" r="2.25" /><path d="M6 13.5c-1.657 0-3 1.007-3 2.25v.75h6v-.75c0-1.243-1.343-2.25-3-2.25z" /></svg>;
            default:
                return <svg style={iconStyle} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /></svg>;
        }
    };

    if (loading) {
        return <div className="section-loading">Loading webhooks...</div>;
    }

    return (
        <div className="webhooks-section">
            <div className="section-header">
                <h2>Webhook Alerts</h2>
                <button className="btn-add" onClick={() => setShowAddForm(!showAddForm)}>
                    <PlusIcon />
                    Add Webhook
                </button>
            </div>

            {showAddForm && (
                <form className="add-webhook-form" onSubmit={handleAdd}>
                    <div className="form-row">
                        <input
                            type="text"
                            placeholder="Webhook name"
                            value={newWebhook.name}
                            onChange={(e) => setNewWebhook({ ...newWebhook, name: e.target.value })}
                            required
                        />
                        <select
                            value={newWebhook.platform}
                            onChange={(e) => setNewWebhook({ ...newWebhook, platform: e.target.value })}
                        >
                            <option value="slack">Slack</option>
                            <option value="discord">Discord</option>
                            <option value="telegram">Telegram</option>
                            <option value="teams">Microsoft Teams</option>
                            <option value="generic">Generic</option>
                        </select>
                    </div>
                    <input
                        type="url"
                        placeholder="Webhook URL"
                        value={newWebhook.url}
                        onChange={(e) => setNewWebhook({ ...newWebhook, url: e.target.value })}
                        required
                    />
                    <div className="form-actions">
                        <button type="button" className="btn-cancel" onClick={() => setShowAddForm(false)}>
                            Cancel
                        </button>
                        <button type="submit" className="btn-save">
                            Add Webhook
                        </button>
                    </div>
                </form>
            )}

            {webhooks.length === 0 ? (
                <div className="empty-state">
                    <WebhookIcon />
                    <h3>No Webhooks Configured</h3>
                    <p>Add webhooks to receive security alerts</p>
                </div>
            ) : (
                <div className="webhooks-list">
                    {webhooks.map((webhook) => (
                        <div key={webhook.name} className="webhook-item">
                            <div className="webhook-info">
                                <span className="webhook-platform">{getPlatformIcon(webhook.platform)}</span>
                                <div className="webhook-details">
                                    <span className="webhook-name">{webhook.name}</span>
                                    <span className="webhook-url">{webhook.url}</span>
                                </div>
                                <span className={`webhook-status ${webhook.enabled ? 'enabled' : 'disabled'}`}>
                                    {webhook.enabled ? 'Active' : 'Disabled'}
                                </span>
                            </div>
                            <div className="webhook-actions">
                                <button
                                    className="btn-test"
                                    onClick={() => handleTest(webhook.name)}
                                    disabled={testingId === webhook.name}
                                    title="Send test message"
                                >
                                    {testingId === webhook.name ? '...' : <SendIcon />}
                                </button>
                                <button
                                    className="btn-delete"
                                    onClick={() => handleRemove(webhook.name)}
                                    title="Remove webhook"
                                >
                                    <TrashIcon />
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
