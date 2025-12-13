import { useState, useEffect, createContext, useContext, useCallback } from 'react'
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react'
import './Toast.css'

// Toast Context
const ToastContext = createContext(null)

/**
 * Toast Notification System
 *
 * Usage:
 * const { toast } = useToast()
 * toast.success('Operation completed!')
 * toast.error('Something went wrong')
 * toast.warning('Please check your input')
 * toast.info('Connecting to server...')
 */

export function ToastProvider({ children }) {
    const [toasts, setToasts] = useState([])

    const addToast = useCallback((type, message, duration = 4000) => {
        const id = Date.now() + Math.random()
        setToasts(prev => [...prev, { id, type, message }])

        if (duration > 0) {
            setTimeout(() => {
                removeToast(id)
            }, duration)
        }

        return id
    }, [])

    const removeToast = useCallback((id) => {
        setToasts(prev => prev.filter(t => t.id !== id))
    }, [])

    const toast = {
        success: (msg, duration) => addToast('success', msg, duration),
        error: (msg, duration) => addToast('error', msg, duration ?? 6000),
        warning: (msg, duration) => addToast('warning', msg, duration),
        info: (msg, duration) => addToast('info', msg, duration),
        remove: removeToast
    }

    return (
        <ToastContext.Provider value={{ toast }}>
            {children}
            <ToastContainer toasts={toasts} onRemove={removeToast} />
        </ToastContext.Provider>
    )
}

export function useToast() {
    const context = useContext(ToastContext)
    if (!context) {
        // Return a no-op toast if used outside provider
        return {
            toast: {
                success: () => { },
                error: () => { },
                warning: () => { },
                info: () => { },
                remove: () => { }
            }
        }
    }
    return context
}

// Toast Container
function ToastContainer({ toasts, onRemove }) {
    if (toasts.length === 0) return null

    return (
        <div className="toast-container">
            {toasts.map(toast => (
                <Toast key={toast.id} {...toast} onRemove={onRemove} />
            ))}
        </div>
    )
}

// Single Toast
function Toast({ id, type, message, onRemove }) {
    const [isExiting, setIsExiting] = useState(false)

    const handleRemove = () => {
        setIsExiting(true)
        setTimeout(() => onRemove(id), 200)
    }

    const icons = {
        success: CheckCircle,
        error: AlertCircle,
        warning: AlertTriangle,
        info: Info
    }
    const Icon = icons[type] || Info

    return (
        <div className={`toast toast-${type} ${isExiting ? 'toast-exit' : ''}`}>
            <Icon size={20} className="toast-icon" />
            <span className="toast-message">{message}</span>
            <button className="toast-close" onClick={handleRemove}>
                <X size={16} />
            </button>
        </div>
    )
}

export default Toast
