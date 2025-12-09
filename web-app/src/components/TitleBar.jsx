import { useState, useEffect } from 'react'
import { Minus, X, Square, Shield, Maximize } from 'lucide-react'
import { invoke } from '@tauri-apps/api/core'
import { getCurrentWindow } from '@tauri-apps/api/window'

export default function TitleBar({ theme }) {
    const [isMaximized, setIsMaximized] = useState(false)
    const appWindow = getCurrentWindow()

    useEffect(() => {
        const updateState = async () => {
            try {
                const max = await appWindow.isMaximized()
                setIsMaximized(max)
            } catch (e) { }
        }
        updateState()

        let unlisten = null
        const setup = async () => {
            try {
                unlisten = await appWindow.onResized(updateState)
            } catch (e) { }
        }
        setup()
        return () => { if (unlisten) unlisten() }
    }, [])

    // --- WINDOW CONTROLS ---
    const handleStartDrag = (e) => {
        // Only drag on left click
        if (e.button === 0) {
            invoke('window_start_drag').catch(console.error)
        }
    }

    const handleMinimize = (e) => {
        e.stopPropagation()
        invoke('window_minimize').catch(console.error)
    }

    const handleToggleMaximize = async (e) => {
        e.stopPropagation()
        try {
            await invoke('window_toggle_maximize')
            const max = await appWindow.isMaximized()
            setIsMaximized(max)
        } catch (e) { console.error(e) }
    }

    const handleClose = (e) => {
        e.stopPropagation()
        invoke('window_close').catch(console.error)
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
