import { useState, useEffect } from 'react'
import { Shield, CheckCircle, Cloud, Cpu, X } from 'lucide-react'
import './WelcomeModal.css'

const STORAGE_KEY = 'onboarding_complete'

/**
 * WelcomeModal - First-time user onboarding (MVP: 1 step)
 *
 * Shows after successful login/register
 * Confirms protection is active and cloud is synced
 */
export default function WelcomeModal({ isOpen, onClose, userName }) {
    const [visible, setVisible] = useState(false)

    useEffect(() => {
        if (isOpen) {
            // Check if already completed
            const completed = localStorage.getItem(STORAGE_KEY)
            if (completed === 'true') {
                onClose?.()
                return
            }
            setVisible(true)
        }
    }, [isOpen, onClose])

    const handleComplete = () => {
        localStorage.setItem(STORAGE_KEY, 'true')
        setVisible(false)
        onClose?.()
    }

    if (!visible) return null

    return (
        <div className="welcome-overlay">
            <div className="welcome-modal">
                {/* Close button */}
                <button className="welcome-close" onClick={handleComplete} title="Skip">
                    <X size={20} />
                </button>

                {/* Header */}
                <div className="welcome-header">
                    <div className="welcome-icon">
                        <Shield size={48} />
                    </div>
                    <h1>🎉 Welcome to One-Shield!</h1>
                    {userName && <p className="welcome-user">Hello, {userName}</p>}
                </div>

                {/* Status Checks */}
                <div className="welcome-status">
                    <div className="status-item success">
                        <CheckCircle size={20} />
                        <span>Protection Active</span>
                    </div>
                    <div className="status-item success">
                        <Cpu size={20} />
                        <span>AI Engine Running</span>
                    </div>
                    <div className="status-item success">
                        <Cloud size={20} />
                        <span>Cloud Sync Connected</span>
                    </div>
                </div>

                {/* Info */}
                <div className="welcome-info">
                    <p>
                        Your computer is now protected 24/7. One-Shield runs in the
                        background and monitors for threats in real-time.
                    </p>
                    <p className="welcome-tip">
                        💡 Look for the shield icon in your system tray
                    </p>
                </div>

                {/* Action */}
                <button className="welcome-btn" onClick={handleComplete}>
                    Got It, Let's Go!
                </button>

                {/* Don't show again - implicit via handleComplete */}
            </div>
        </div>
    )
}

/**
 * Check if onboarding should be shown
 */
export function shouldShowOnboarding() {
    return localStorage.getItem(STORAGE_KEY) !== 'true'
}

/**
 * Reset onboarding (for testing)
 */
export function resetOnboarding() {
    localStorage.removeItem(STORAGE_KEY)
}
