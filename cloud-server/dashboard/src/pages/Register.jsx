import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Mail, Lock, Building2, User, AlertCircle, Loader, Check, ArrowRight } from 'lucide-react';
import { register, login } from '../services/api';
import './Register.css';

export default function Register() {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);

    const [formData, setFormData] = useState({
        organizationName: '',
        name: '',
        email: '',
        password: '',
        confirmPassword: '',
        agreeTerms: false,
    });

    const [validation, setValidation] = useState({
        organizationName: null,
        email: null,
        password: null,
        confirmPassword: null,
    });

    const validateField = (name, value) => {
        switch (name) {
            case 'organizationName':
                return value.length >= 3 ? 'valid' : value.length > 0 ? 'invalid' : null;
            case 'email':
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                return emailRegex.test(value) ? 'valid' : value.length > 0 ? 'invalid' : null;
            case 'password':
                return value.length >= 8 ? 'valid' : value.length > 0 ? 'invalid' : null;
            case 'confirmPassword':
                return value === formData.password && value.length > 0 ? 'valid' : value.length > 0 ? 'invalid' : null;
            default:
                return null;
        }
    };

    const handleChange = (e) => {
        const { name, value, type, checked } = e.target;
        const newValue = type === 'checkbox' ? checked : value;

        setFormData(prev => ({
            ...prev,
            [name]: newValue,
        }));

        if (type !== 'checkbox') {
            setValidation(prev => ({
                ...prev,
                [name]: validateField(name, value),
            }));
        }

        setError('');
    };

    const isFormValid = () => {
        return (
            formData.organizationName.length >= 3 &&
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email) &&
            formData.password.length >= 8 &&
            formData.password === formData.confirmPassword &&
            formData.agreeTerms
        );
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!isFormValid()) {
            setError('Please fill in all fields correctly');
            return;
        }

        setLoading(true);
        setError('');

        try {
            // Register organization
            await register({
                organization_name: formData.organizationName,
                name: formData.name,
                email: formData.email,
                password: formData.password,
            });

            setSuccess(true);

            // Auto login after 2 seconds
            setTimeout(async () => {
                try {
                    await login(formData.email, formData.password);
                    navigate('/');
                } catch (err) {
                    navigate('/login');
                }
            }, 2000);

        } catch (err) {
            setError(err.message || 'Registration failed. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    if (success) {
        return (
            <div className="register-page">
                <div className="register-bg">
                    <div className="bg-gradient-1"></div>
                    <div className="bg-gradient-2"></div>
                </div>
                <div className="register-container">
                    <div className="success-card">
                        <div className="success-icon">
                            <Check size={48} />
                        </div>
                        <h1>Organization Created!</h1>
                        <p>Your organization <strong>{formData.organizationName}</strong> has been created successfully.</p>
                        <p className="redirect-text">Redirecting to dashboard...</p>
                        <Loader className="spinner" size={24} />
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="register-page">
            {/* Background Effect */}
            <div className="register-bg">
                <div className="bg-gradient-1"></div>
                <div className="bg-gradient-2"></div>
            </div>

            {/* Register Card */}
            <div className="register-container">
                <div className="register-card">
                    {/* Header */}
                    <div className="register-header">
                        <div className="register-logo">
                            <Shield className="logo-icon" />
                        </div>
                        <h1>Create Organization</h1>
                        <p>Start protecting your endpoints today</p>
                    </div>

                    {/* Error */}
                    {error && (
                        <div className="error-banner">
                            <AlertCircle size={18} />
                            <span>{error}</span>
                        </div>
                    )}

                    {/* Form */}
                    <form onSubmit={handleSubmit} className="register-form">
                        {/* Organization Name */}
                        <div className={`form-group ${validation.organizationName}`}>
                            <label htmlFor="organizationName">
                                <Building2 size={16} />
                                Organization Name
                            </label>
                            <input
                                type="text"
                                id="organizationName"
                                name="organizationName"
                                placeholder="Your company name"
                                value={formData.organizationName}
                                onChange={handleChange}
                                required
                            />
                            {validation.organizationName === 'invalid' && (
                                <span className="hint error">At least 3 characters</span>
                            )}
                        </div>

                        {/* Admin Name */}
                        <div className="form-group">
                            <label htmlFor="name">
                                <User size={16} />
                                Your Name
                            </label>
                            <input
                                type="text"
                                id="name"
                                name="name"
                                placeholder="Admin name"
                                value={formData.name}
                                onChange={handleChange}
                            />
                        </div>

                        {/* Email */}
                        <div className={`form-group ${validation.email}`}>
                            <label htmlFor="email">
                                <Mail size={16} />
                                Email Address
                            </label>
                            <input
                                type="email"
                                id="email"
                                name="email"
                                placeholder="admin@company.com"
                                value={formData.email}
                                onChange={handleChange}
                                required
                            />
                            {validation.email === 'invalid' && (
                                <span className="hint error">Please enter a valid email</span>
                            )}
                        </div>

                        {/* Password */}
                        <div className={`form-group ${validation.password}`}>
                            <label htmlFor="password">
                                <Lock size={16} />
                                Password
                            </label>
                            <input
                                type="password"
                                id="password"
                                name="password"
                                placeholder="••••••••"
                                value={formData.password}
                                onChange={handleChange}
                                required
                            />
                            {validation.password === 'invalid' && (
                                <span className="hint error">At least 8 characters</span>
                            )}
                        </div>

                        {/* Confirm Password */}
                        <div className={`form-group ${validation.confirmPassword}`}>
                            <label htmlFor="confirmPassword">
                                <Lock size={16} />
                                Confirm Password
                            </label>
                            <input
                                type="password"
                                id="confirmPassword"
                                name="confirmPassword"
                                placeholder="••••••••"
                                value={formData.confirmPassword}
                                onChange={handleChange}
                                required
                            />
                            {validation.confirmPassword === 'invalid' && (
                                <span className="hint error">Passwords don't match</span>
                            )}
                        </div>

                        {/* Terms */}
                        <div className="form-group checkbox-group">
                            <label className="checkbox-label">
                                <input
                                    type="checkbox"
                                    name="agreeTerms"
                                    checked={formData.agreeTerms}
                                    onChange={handleChange}
                                    required
                                />
                                <span className="checkmark"></span>
                                <span>I agree to the <a href="/terms" target="_blank">Terms of Service</a></span>
                            </label>
                        </div>

                        {/* Submit */}
                        <button
                            type="submit"
                            className="submit-btn"
                            disabled={loading || !isFormValid()}
                        >
                            {loading ? (
                                <>
                                    <Loader className="spinner" size={18} />
                                    Creating...
                                </>
                            ) : (
                                <>
                                    Create Organization
                                    <ArrowRight size={18} />
                                </>
                            )}
                        </button>
                    </form>

                    {/* Footer */}
                    <div className="register-footer">
                        <p>
                            Already have an account?{' '}
                            <Link to="/login">Sign in</Link>
                        </p>
                    </div>
                </div>

                {/* Features */}
                <div className="features-sidebar">
                    <h3>What you get:</h3>
                    <ul>
                        <li>
                            <Check size={16} />
                            <span>Unlimited endpoints</span>
                        </li>
                        <li>
                            <Check size={16} />
                            <span>AI-powered threat detection</span>
                        </li>
                        <li>
                            <Check size={16} />
                            <span>Real-time monitoring</span>
                        </li>
                        <li>
                            <Check size={16} />
                            <span>Cloud dashboard</span>
                        </li>
                        <li>
                            <Check size={16} />
                            <span>Enrollment tokens</span>
                        </li>
                        <li>
                            <Check size={16} />
                            <span>Team management</span>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    );
}
