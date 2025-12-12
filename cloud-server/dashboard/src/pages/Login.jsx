import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Mail, Lock, AlertCircle, Loader } from 'lucide-react';
import { login, register } from '../services/api';
import './Login.css';

export default function Login() {
    const navigate = useNavigate();
    const [isRegister, setIsRegister] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const [formData, setFormData] = useState({
        name: '',
        email: '',
        password: '',
    });

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value,
        });
        setError('');
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            if (isRegister) {
                await register(formData.name, formData.email, formData.password);
                // After register, login
                await login(formData.email, formData.password);
            } else {
                await login(formData.email, formData.password);
            }
            navigate('/');
        } catch (err) {
            setError(err.message || 'Authentication failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="login-page">
            {/* Background Effect */}
            <div className="login-bg">
                <div className="bg-gradient-1"></div>
                <div className="bg-gradient-2"></div>
            </div>

            {/* Login Card */}
            <div className="login-container">
                <div className="login-card">
                    {/* Header */}
                    <div className="login-header">
                        <div className="login-logo">
                            <Shield className="logo-icon" />
                        </div>
                        <h1>One-Shield</h1>
                        <p>Cloud Management Console</p>
                    </div>

                    {/* Form */}
                    <form onSubmit={handleSubmit} className="login-form">
                        {isRegister && (
                            <div className="form-group">
                                <label className="label" htmlFor="name">Name</label>
                                <div className="input-wrapper">
                                    <input
                                        type="text"
                                        id="name"
                                        name="name"
                                        className="input"
                                        placeholder="Your name"
                                        value={formData.name}
                                        onChange={handleChange}
                                        required={isRegister}
                                        disabled={loading}
                                    />
                                </div>
                            </div>
                        )}

                        <div className="form-group">
                            <label className="label" htmlFor="email">Email</label>
                            <div className="input-wrapper">
                                <Mail className="input-icon" size={18} />
                                <input
                                    type="email"
                                    id="email"
                                    name="email"
                                    className="input with-icon"
                                    placeholder="admin@example.com"
                                    value={formData.email}
                                    onChange={handleChange}
                                    required
                                    disabled={loading}
                                />
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="label" htmlFor="password">Password</label>
                            <div className="input-wrapper">
                                <Lock className="input-icon" size={18} />
                                <input
                                    type="password"
                                    id="password"
                                    name="password"
                                    className="input with-icon"
                                    placeholder="••••••••"
                                    value={formData.password}
                                    onChange={handleChange}
                                    required
                                    disabled={loading}
                                />
                            </div>
                        </div>

                        {error && (
                            <div className="error-message">
                                <AlertCircle size={16} />
                                <span>{error}</span>
                            </div>
                        )}

                        <button
                            type="submit"
                            className="btn btn-primary btn-lg w-full"
                            disabled={loading}
                        >
                            {loading ? (
                                <>
                                    <Loader className="animate-spin" size={18} />
                                    <span>Please wait...</span>
                                </>
                            ) : (
                                <span>{isRegister ? 'Create Account' : 'Sign In'}</span>
                            )}
                        </button>
                    </form>

                    {/* Footer */}
                    <div className="login-footer">
                        <p>
                            {isRegister ? 'Already have an account?' : "Don't have an account?"}
                            <button
                                type="button"
                                className="toggle-btn"
                                onClick={() => {
                                    setIsRegister(!isRegister);
                                    setError('');
                                }}
                            >
                                {isRegister ? 'Sign In' : 'Register'}
                            </button>
                        </p>
                    </div>

                    {/* Demo Credentials */}
                    <div className="demo-hint">
                        <p>Demo: Register a new account to start</p>
                    </div>
                </div>
            </div>
        </div>
    );
}
