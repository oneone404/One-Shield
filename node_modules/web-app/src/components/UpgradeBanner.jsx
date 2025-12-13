import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { open } from '@tauri-apps/plugin-shell'
import { Crown, X, ExternalLink } from 'lucide-react'
import './UpgradeBanner.css'

const DISMISS_KEY = 'upgrade_banner_dismissed'
const DISMISS_DAYS = 7

/**
 * UpgradeBanner - Encourage Free → Pro upgrade
 *
 * Only shows for PersonalFree tier
 * Can be dismissed (hidden for 7 days)
 */
export default function UpgradeBanner() {
    const [visible, setVisible] = useState(false)
    const [tier, setTier] = useState(null)

    useEffect(() => {
        const checkTier = async () => {
            // Check if dismissed recently
            const dismissed = localStorage.getItem(DISMISS_KEY)
            if (dismissed) {
                const dismissedAt = parseInt(dismissed, 10)
                const daysSince = (Date.now() - dismissedAt) / (1000 * 60 * 60 * 24)
                if (daysSince < DISMISS_DAYS) {
                    return // Still dismissed
                }
            }

            // Check tier
            try {
                const mode = await invoke('get_agent_mode')
                if (mode.mode === 'personal' && mode.has_identity) {
                    // Personal mode with identity = show upgrade
                    // TODO: Check if actually Free (not Pro)
                    setTier('personal_free')
                    setVisible(true)
                }
            } catch (e) {
                console.warn('Failed to check tier for upgrade:', e)
            }
        }

        // Delay check to not obstruct initial load
        const timer = setTimeout(checkTier, 5000)
        return () => clearTimeout(timer)
    }, [])

    const handleDismiss = () => {
        localStorage.setItem(DISMISS_KEY, Date.now().toString())
        setVisible(false)
    }

    const handleUpgrade = async () => {
        try {
            await open('https://oneshield.vn/pricing')
        } catch (e) {
            // Fallback: open via href
            window.location.href = 'https://oneshield.vn/pricing'
        }
    }

    if (!visible || tier !== 'personal_free') {
        return null
    }

    return (
        <div className="upgrade-banner">
            <div className="upgrade-content">
                <div className="upgrade-icon">
                    <Crown size={20} />
                </div>
                <div className="upgrade-text">
                    <span className="upgrade-title">Upgrade to Pro</span>
                    <span className="upgrade-desc">Protect up to 10 devices • $9/month</span>
                </div>
            </div>

            <div className="upgrade-actions">
                <button className="upgrade-btn" onClick={handleUpgrade}>
                    Upgrade Now
                    <ExternalLink size={14} />
                </button>
                <button className="upgrade-dismiss" onClick={handleDismiss} title="Dismiss for 7 days">
                    <X size={16} />
                </button>
            </div>
        </div>
    )
}
