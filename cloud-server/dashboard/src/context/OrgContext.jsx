/**
 * Organization Context - Phase 13
 *
 * Provides org tier and feature checks for dashboard components.
 * Used for feature gating (hide Tokens/Users for Personal tier).
 */

import { createContext, useContext, useState, useEffect } from 'react';
import { getOrganization, isAuthenticated } from '../services/api';

const OrgContext = createContext(null);

export function OrgProvider({ children }) {
    const [org, setOrg] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        if (isAuthenticated()) {
            fetchOrg();
        } else {
            setLoading(false);
        }
    }, []);

    const fetchOrg = async () => {
        try {
            setLoading(true);
            setError(null);
            const data = await getOrganization();
            setOrg(data);
        } catch (err) {
            console.error('Failed to fetch org:', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    // Derived state for easy access
    const isOrganization = org?.tier === 'organization' || org?.tier === 'enterprise';
    const isPersonal = org?.tier?.startsWith('personal') || false;
    const canCreateTokens = org?.features?.can_create_tokens || false;
    const canManageUsers = org?.features?.can_manage_users || false;

    const value = {
        org,
        loading,
        error,
        refetch: fetchOrg,
        // Tier checks
        isOrganization,
        isPersonal,
        tier: org?.tier || 'unknown',
        // Feature checks
        canCreateTokens,
        canManageUsers,
        canViewAuditLogs: org?.features?.can_view_audit_logs || false,
        canAccessApi: org?.features?.can_access_api || false,
        maxDevices: org?.features?.max_devices || 1,
        // Device count
        currentDevices: org?.current_agents || 0,
    };

    return (
        <OrgContext.Provider value={value}>
            {children}
        </OrgContext.Provider>
    );
}

/**
 * Hook to access org context
 * @returns {Object} Org context with tier, features, and loading state
 */
export function useOrg() {
    const context = useContext(OrgContext);
    if (!context) {
        throw new Error('useOrg must be used within OrgProvider');
    }
    return context;
}

/**
 * Hook to check if user can access a feature
 * @param {string} feature - Feature name
 * @returns {boolean} Whether user can access the feature
 */
export function useFeature(feature) {
    const { org } = useOrg();
    return org?.features?.[feature] || false;
}

export default OrgContext;
