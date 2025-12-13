import { useState } from 'react';
import { User, Mail, Lock, Shield, Eye, EyeOff, Loader2, X, AlertCircle, CheckCircle } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import './AuthModal.css';

/**
 * AuthModal - Login/Register modal for desktop app
 *
 * Calls Tauri command: personal_enroll(email, password, name?)
 * Returns: { success, user_id, agent_id, org_name, tier, is_new_user, error }
 */
export default function AuthModal({ isOpen, onClose, onSuccess }) {
    const [mode, setMode] = useState('login'); // 'login' | 'register'
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [name, setName] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(null);

    if (!isOpen) return null;

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess(null);

        // Basic validation
        if (!email.trim()) {
            setError('Email is required');
            return;
        }
        if (!password.trim()) {
            setError('Password is required');
            return;
        }
        if (password.length < 6) {
            setError('Password must be at least 6 characters');
            return;
        }

        setLoading(true);

        try {
            // Call Tauri command
            const result = await invoke('personal_enroll', {
                email: email.trim(),
                password: password,
                name: mode === 'register' && name.trim() ? name.trim() : null,
            });

            if (result.success) {
                setSuccess({
                    isNewUser: result.is_new_user,
                    orgName: result.org_name,
                    tier: result.tier,
                });

                // Wait a moment to show success, then close
                setTimeout(() => {
                    if (onSuccess) {
                        onSuccess(result);
                    }
                    onClose();
                }, 1500);
            } else {
                setError(result.error || 'Authentication failed');
            }
        } catch (err) {
            console.error('Auth error:', err);
            setError(err?.message || 'Connection failed. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const switchMode = () => {
        setMode(mode === 'login' ? 'register' : 'login');
        setError('');
        setSuccess(null);
    };

    return (
        <div className="auth-modal-overlay" onClick={onClose}>
            <div className="auth-modal" onClick={e => e.stopPropagation()}>
                {/* Close button */}
                <button className="auth-close-btn" onClick={onClose}>
                    <X size={20} />
                </button>

                {/* Header */}
                <div className="auth-header">
                    <div className="auth-logo">
                        <Shield size={40} />
                    </div>
                    <h2>{mode === 'login' ? 'Welcome Back' : 'Create Account'}</h2>
                    <p>
                        {mode === 'login'
                            ? 'Sign in to sync your security data'
                            : 'Start protecting your device for free'
                        }
                    </p>
                </div>

                {/* Success State */}
                {success && (
                    <div className="auth-success">
                        <CheckCircle size={48} />
                        <h3>{success.isNewUser ? 'Account Created!' : 'Welcome Back!'}</h3>
                        <p>
                            {success.isNewUser
                                ? `Your ${success.tier === 'personal_free' ? 'Free' : 'Pro'} account is ready.`
                                : `Logged in as ${email}`
                            }
                        </p>
                    </div>
                )}

                {/* Form */}
                {!success && (
                    <form onSubmit={handleSubmit} className="auth-form">
                        {/* Error */}
                        {error && (
                            <div className="auth-error">
                                <AlertCircle size={16} />
                                <span>{error}</span>
                            </div>
                        )}

                        {/* Name field (register only) */}
                        {mode === 'register' && (
                            <div className="auth-field">
                                <label>
                                    <User size={16} />
                                    Your Name
                                </label>
                                <input
                                    type="text"
                                    value={name}
                                    onChange={e => setName(e.target.value)}
                                    placeholder="John Doe"
                                    disabled={loading}
                                />
                            </div>
                        )}

                        {/* Email */}
                        <div className="auth-field">
                            <label>
                                <Mail size={16} />
                                Email Address
                            </label>
                            <input
                                type="email"
                                value={email}
                                onChange={e => setEmail(e.target.value)}
                                placeholder="you@example.com"
                                disabled={loading}
                                required
                                autoFocus
                            />
                        </div>

                        {/* Password */}
                        <div className="auth-field">
                            <label>
                                <Lock size={16} />
                                Password
                            </label>
                            <div className="password-wrapper">
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    value={password}
                                    onChange={e => setPassword(e.target.value)}
                                    placeholder="••••••••"
                                    disabled={loading}
                                    required
                                />
                                <button
                                    type="button"
                                    className="password-toggle"
                                    onClick={() => setShowPassword(!showPassword)}
                                >
                                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                                </button>
                            </div>
                        </div>

                        {/* Submit */}
                        <button
                            type="submit"
                            className="auth-submit-btn"
                            disabled={loading}
                        >
                            {loading ? (
                                <>
                                    <Loader2 size={18} className="spinner" />
                                    {mode === 'login' ? 'Signing in...' : 'Creating account...'}
                                </>
                            ) : (
                                <>
                                    <Shield size={18} />
                                    {mode === 'login' ? 'Sign In' : 'Create Free Account'}
                                </>
                            )}
                        </button>

                        {/* Switch mode */}
                        <div className="auth-switch">
                            <span>
                                {mode === 'login' ? "Don't have an account?" : 'Already have an account?'}
                            </span>
                            <button type="button" onClick={switchMode}>
                                {mode === 'login' ? 'Sign Up' : 'Sign In'}
                            </button>
                        </div>

                        {/* Free tier note */}
                        {mode === 'register' && (
                            <div className="auth-note">
                                <Shield size={14} />
                                <span>Free plan includes 3 devices with AI-powered protection</span>
                            </div>
                        )}
                    </form>
                )}
            </div>
        </div>
    );
}
