/**
 * useActionGuard Hook - Action Guard State Management
 *
 * Quản lý pending actions với polling và notification.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import {
    getPendingActions,
    approveAction,
    cancelAction,
    getActionGuardStatus,
    getActionHistory,
} from '../services/tauriApi';

// Check if running in Tauri for notifications
const isTauri = () => typeof window !== 'undefined' && window.__TAURI_INTERNALS__;

// Notification helper
async function showNotification(title, body) {
    if (!isTauri()) {
        // Use browser notification
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, { body, icon: '/favicon.ico' });
        }
        return;
    }

    try {
        const { sendNotification, isPermissionGranted, requestPermission } =
            await import('@tauri-apps/plugin-notification');

        let permission = await isPermissionGranted();
        if (!permission) {
            permission = await requestPermission();
        }

        if (permission === true || permission === 'granted') {
            await sendNotification({ title, body });
        }
    } catch (error) {
        console.warn('Notification not available:', error);
    }
}

// Play alert sound
function playAlertSound() {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);

        oscillator.frequency.value = 880; // A5 note
        oscillator.type = 'sine';
        gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);

        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.5);
    } catch (e) {
        console.warn('Audio not available');
    }
}

export function useActionGuard(options = {}) {
    const {
        pollingInterval = 1000,      // Poll every 1 second
        autoNotify = true,           // Show notifications
        autoSound = true,            // Play sound on new action
        enabled = true,              // Enable/disable hook
    } = options;

    const [pendingActions, setPendingActions] = useState([]);
    const [status, setStatus] = useState(null);
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    // Track previously seen action IDs to detect new ones
    const previousActionsRef = useRef(new Set());

    // Fetch pending actions
    const fetchPendingActions = useCallback(async () => {
        if (!enabled) return;

        try {
            const actions = await getPendingActions();
            const actionsList = Array.isArray(actions) ? actions : [];

            // Check for new actions
            const currentIds = new Set(actionsList.map(a => a.id));
            const previousIds = previousActionsRef.current;

            // Find new actions
            const newActions = actionsList.filter(a => !previousIds.has(a.id));

            if (newActions.length > 0 && previousIds.size > 0) {
                // New actions detected!
                if (autoSound) {
                    playAlertSound();
                }

                if (autoNotify) {
                    newActions.forEach(action => {
                        showNotification(
                            '⚠️ Yêu Cầu Phê Duyệt',
                            `${action.action_type}: ${action.target_name} (Score: ${(action.final_score * 100).toFixed(0)}%)`
                        );
                    });
                }
            }

            previousActionsRef.current = currentIds;
            setPendingActions(actionsList);
            setError(null);
        } catch (err) {
            console.error('Failed to fetch pending actions:', err);
            setError(err.message);
        }
    }, [enabled, autoNotify, autoSound]);

    // Fetch status
    const fetchStatus = useCallback(async () => {
        if (!enabled) return;

        try {
            const statusData = await getActionGuardStatus();
            setStatus(statusData);
        } catch (err) {
            console.error('Failed to fetch status:', err);
        }
    }, [enabled]);

    // Fetch history
    const fetchHistory = useCallback(async (limit = 50) => {
        if (!enabled) return;

        try {
            const historyData = await getActionHistory(limit);
            setHistory(Array.isArray(historyData) ? historyData : []);
        } catch (err) {
            console.error('Failed to fetch history:', err);
        }
    }, [enabled]);

    // Approve action
    const approve = useCallback(async (actionId) => {
        setLoading(true);
        try {
            const result = await approveAction(actionId);

            // Refresh pending actions
            await fetchPendingActions();

            // Show notification
            if (autoNotify && result?.success) {
                showNotification(
                    '✅ Hành Động Đã Thực Thi',
                    result.message || 'Hành động đã được phê duyệt và thực thi.'
                );
            }

            return result;
        } catch (err) {
            console.error('Failed to approve action:', err);
            setError(err.message);
            throw err;
        } finally {
            setLoading(false);
        }
    }, [fetchPendingActions, autoNotify]);

    // Cancel action
    const cancel = useCallback(async (actionId) => {
        setLoading(true);
        try {
            await cancelAction(actionId);

            // Refresh pending actions
            await fetchPendingActions();

            return true;
        } catch (err) {
            console.error('Failed to cancel action:', err);
            setError(err.message);
            throw err;
        } finally {
            setLoading(false);
        }
    }, [fetchPendingActions]);

    // Set up polling
    useEffect(() => {
        if (!enabled) return;

        // Initial fetch
        fetchPendingActions();
        fetchStatus();

        // Set up interval
        const interval = setInterval(() => {
            fetchPendingActions();
        }, pollingInterval);

        return () => clearInterval(interval);
    }, [enabled, pollingInterval, fetchPendingActions, fetchStatus]);

    // Request notification permission on mount
    useEffect(() => {
        if (typeof window !== 'undefined' && 'Notification' in window) {
            if (Notification.permission === 'default') {
                Notification.requestPermission();
            }
        }
    }, []);

    return {
        // State
        pendingActions,
        hasPendingActions: pendingActions.length > 0,
        pendingCount: pendingActions.length,
        status,
        history,
        loading,
        error,

        // Actions
        approve,
        cancel,
        refresh: fetchPendingActions,
        refreshStatus: fetchStatus,
        fetchHistory,
    };
}

export default useActionGuard;
