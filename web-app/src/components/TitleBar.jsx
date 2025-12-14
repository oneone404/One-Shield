import { useState, useEffect, useRef } from 'react'
import { Minus, X, Square, Shield, Maximize } from 'lucide-react'
import api from '../services/tauriApi'

export default function TitleBar({ theme }) {
    const [isMaximized, setIsMaximized] = useState(false)
    const appWindowRef = useRef(null)

    useEffect(() => {
        // Check if running in Tauri
        if (typeof window === 'undefined' || !window.__TAURI_INTERNALS__) {
            return // Not in Tauri, skip window API
        }

        // Dynamic import to avoid crash in browser
        const initWindow = async () => {
            try {
                const { getCurrentWindow } = await import('@tauri-apps/api/window')
                appWindowRef.current = getCurrentWindow()

                const appWindow = appWindowRef.current
                if (!appWindow) return

                const updateState = async () => {
                    try {
                        const max = await appWindow.isMaximized()
                        setIsMaximized(max)
                    } catch (e) { }
                }
                updateState()

                try {
                    const unlisten = await appWindow.onResized(updateState)
                    return unlisten
                } catch (e) { }
            } catch (e) {
                console.warn('Failed to init window:', e)
            }
        }

        let cleanup = null
        initWindow().then(unlisten => { cleanup = unlisten })
        return () => { if (cleanup) cleanup() }
    }, [])

    // --- WINDOW CONTROLS ---
    const handleStartDrag = (e) => {
        // Only drag on left click
        if (e.button === 0) {
            api.invoke('window_start_drag').catch(console.error)
        }
    }

    const handleMinimize = (e) => {
        e.stopPropagation()
        api.invoke('window_minimize').catch(console.error)
    }

    const handleToggleMaximize = async (e) => {
        e.stopPropagation()
        try {
            await api.invoke('window_toggle_maximize')
            if (appWindowRef.current) {
                const max = await appWindowRef.current.isMaximized()
                setIsMaximized(max)
            }
        } catch (e) { console.error(e) }
    }

    const handleClose = (e) => {
        e.stopPropagation()
        api.invoke('window_close').catch(console.error)
    }

    const preventDrag = (e) => e.stopPropagation()

    return (
        <div className="titlebar">
            {/*
         DRAG REGION
         We use manual onMouseDown instead of data-tauri-drag-region
         because we are managing window commands manually to bypass plugin permission issues.
      */}
            <div
                className="titlebar-drag-region"
                onMouseDown={handleStartDrag}
            >
                <div className="titlebar-logo">
                    <Shield size={16} fill="currentColor" strokeWidth={0} />
                </div>
            </div>

            <div className="titlebar-controls" onMouseDown={preventDrag}>
                <button className="titlebar-btn minimize" onClick={handleMinimize} title="Minimize">
                    <Minus size={16} />
                </button>
                <button className="titlebar-btn maximize" onClick={handleToggleMaximize} title="Maximize">
                    {isMaximized ? <Maximize size={14} style={{ transform: 'scale(0.9)' }} /> : <Square size={14} />}
                </button>
                <button className="titlebar-btn close" onClick={handleClose} title="Close">
                    <X size={16} />
                </button>
            </div>
        </div>
    )
}
