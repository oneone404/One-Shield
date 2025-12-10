/**
 * useActionGuard Hook - Action Guard State Management
 *
 * Event-driven với fallback polling.
 * Listen events từ Rust backend, giảm CPU usage.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import {
    getPendingActions,
    approveAction,
    cancelAction,
    getActionGuardStatus,
    getActionHistory,
} from '../services/tauriApi';

// Check if running in Tauri
const isTauri = () => typeof window !== 'undefined' && window.__TAURI_INTERNALS__;

// Notification helper
async function showNotification(title, body) {
    if (!isTauri()) {
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

        oscillator.frequency.value = 880;
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
        pollingInterval = 5000,      // Fallback polling every 5s (reduced from 1s)
        autoNotify = true,
        autoSound = true,
        enabled = true,
    } = options;

    const [pendingActions, setPendingActions] = useState([]);
    const [status, setStatus] = useState(null);
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const previousActionsRef = useRef(new Set());

    // Handle new action from event
    const handleNewAction = useCallback((action) => {
        if (autoSound) {
            playAlertSound();
        }

        if (autoNotify) {
            showNotification(
                '⚠️ Yêu Cầu Phê Duyệt',
                `${action.action_type}: ${action.target_name} (Score: ${(action.final_score * 100).toFixed(0)}%)`
            );
        }

        // Add to pending actions
        setPendingActions(prev => {
            const exists = prev.some(a => a.id === action.id);
            if (exists) return prev;
            return [...prev, action];
        });

        previousActionsRef.current.add(action.id);
    }, [autoNotify, autoSound]);

    // Fetch pending actions (for initial load and fallback)
    const fetchPendingActions = useCallback(async () => {
        if (!enabled) return;

        try {
            const actions = await getPendingActions();
            const actionsList = Array.isArray(actions) ? actions : [];

            const currentIds = new Set(actionsList.map(a => a.id));
            const previousIds = previousActionsRef.current;

            // Only notify for truly new actions (not on initial load)
            if (previousIds.size > 0) {
                const newActions = actionsList.filter(a => !previousIds.has(a.id));
                newActions.forEach(handleNewAction);
            }

            previousActionsRef.current = currentIds;
            setPendingActions(actionsList);
            setError(null);
        } catch (err) {
            console.error('Failed to fetch pending actions:', err);
            setError(err.message);
        }
    }, [enabled, handleNewAction]);

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

            // Remove from local state immediately
            setPendingActions(prev => prev.filter(a => a.id !== actionId));
            previousActionsRef.current.delete(actionId);

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
    }, [autoNotify]);

    // Cancel action
    const cancel = useCallback(async (actionId) => {
        setLoading(true);
        try {
            await cancelAction(actionId);

            // Remove from local state immediately
            setPendingActions(prev => prev.filter(a => a.id !== actionId));
            previousActionsRef.current.delete(actionId);

            return true;
        } catch (err) {
            console.error('Failed to cancel action:', err);
            setError(err.message);
            throw err;
        } finally {
            setLoading(false);
        }
    }, []);

    // Event listener setup
    useEffect(() => {
        if (!enabled) return;

        let unlisten = null;

        const setupEventListener = async () => {
            if (!isTauri()) return;

            try {
                const { listen } = await import('@tauri-apps/api/event');

                // Listen for pending action events
                unlisten = await listen('action-guard:pending', (event) => {
                    console.log('Received pending action event:', event.payload);
                    handleNewAction(event.payload);
                });

                console.log('Event listener setup complete');
            } catch (err) {
                console.warn('Failed to setup event listener, using polling fallback:', err);
            }
        };

        setupEventListener();

        // Initial fetch
        fetchPendingActions();
        fetchStatus();

        // Fallback polling (reduced interval since we have events)
        const interval = setInterval(() => {
            fetchPendingActions();
        }, pollingInterval);

        return () => {
            clearInterval(interval);
            if (unlisten) {
                unlisten();
            }
        };
    }, [enabled, pollingInterval, fetchPendingActions, fetchStatus, handleNewAction]);

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
