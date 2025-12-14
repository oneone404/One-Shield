import { useState, useEffect } from 'react'
import api from '../services/tauriApi'
import { Crown, User, Building2 } from 'lucide-react'
import './TierBadge.css'

/**
 * TierBadge - Display user's subscription tier in header
 *
 * Tiers:
 * - PersonalFree: 👤 Free (Gray)
 * - PersonalPro: ⭐ Pro (Gold)
 * - Organization: 🏢 Org (Blue)
 */
export default function TierBadge({ compact = false }) {
    const [tier, setTier] = useState(null)
    const [orgName, setOrgName] = useState('')
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchTier = async () => {
            try {
                const mode = await api.invoke('get_agent_mode')
                if (!mode) return

                // Determine tier from mode
                if (mode.mode === 'organization') {
                    setTier('organization')
                    setOrgName(mode.org_name || 'Organization')
                } else if (mode.has_identity) {
                    // Personal mode with identity
                    // TODO: Check actual tier from cloud (Pro vs Free)
                    setTier('personal_free')
                } else {
                    setTier(null)
                }
            } catch (e) {
                console.warn('Failed to get tier:', e)
            } finally {
                setLoading(false)
            }
        }

        fetchTier()

        // Refresh every 30 seconds
        const interval = setInterval(fetchTier, 30000)
        return () => clearInterval(interval)
    }, [])

    if (loading || !tier) {
        return null
    }

    const getTierConfig = () => {
        switch (tier) {
            case 'personal_pro':
                return {
                    icon: Crown,
                    label: 'Pro',
                    className: 'tier-pro',
                    title: 'Personal Pro - 10 devices'
                }
            case 'organization':
                return {
                    icon: Building2,
                    label: compact ? 'Org' : (orgName?.slice(0, 12) || 'Org'),
                    className: 'tier-org',
                    title: `Organization: ${orgName}`
                }
            case 'personal_free':
            default:
                return {
                    icon: User,
                    label: 'Free',
                    className: 'tier-free',
                    title: 'Personal Free - 1 device'
                }
        }
    }

    const config = getTierConfig()
    const Icon = config.icon

    return (
        <div
            className={`tier-badge ${config.className} ${compact ? 'compact' : ''}`}
            title={config.title}
        >
            <Icon size={14} />
            <span className="tier-label">{config.label}</span>
        </div>
    )
}
