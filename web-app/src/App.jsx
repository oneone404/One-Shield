import { useState, useEffect } from 'react'

// Components
import TitleBar from './components/TitleBar'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import ApprovalModal from './components/ApprovalModal'
import Dashboard from './pages/Dashboard'

import * as api from './services/tauriApi'
import { useActionGuard } from './hooks/useActionGuard'

// Import TitleBar CSS
import './styles/components/titlebar.css'

function App() {
  const [activePage, setActivePage] = useState('dashboard')
  const [isMonitoring, setIsMonitoring] = useState(false)
  const [showApprovalModal, setShowApprovalModal] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    // Read initial state from storage
    return localStorage.getItem('sidebarCollapsed') === 'true'
  })

  // Persist sidebar state
  useEffect(() => {
    localStorage.setItem('sidebarCollapsed', sidebarCollapsed)
  }, [sidebarCollapsed])

  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('theme') || 'dark'
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark')
  }

  // Hook logic
  const { pendingActions, hasPendingActions, approve, cancel } = useActionGuard({
    pollingInterval: 1000,
    autoNotify: true,
    autoSound: true,
    enabled: isMonitoring,
  })

  useEffect(() => {
    if (hasPendingActions && !showApprovalModal) {
      setShowApprovalModal(true)
    }
  }, [hasPendingActions, showApprovalModal])

  useEffect(() => {
    // Show window when App mounts and renders
    const showWindow = async () => {
      try {
        await new Promise(resolve => setTimeout(resolve, 100));
        await api.invoke('show_main_window');
        // Auto-start Monitoring (v1.0 Experience)
        await api.startCollector();
        setIsMonitoring(true);
      } catch (e) {
        console.error("Failed to init", e);
      }
    };
    showWindow();

    const checkStatus = async () => {
      try {
        const status = await api.getSystemStatus()
        setIsMonitoring(status.is_monitoring || false)
      } catch (error) { }
    }
    checkStatus()
  }, [])

  const handleToggleMonitoring = async () => {
    // ... toggle logic
    try {
      if (isMonitoring) {
        await api.stopCollector()
        setIsMonitoring(false)
      } else {
        await api.startCollector()
        setIsMonitoring(true)
      }
    } catch (error) { }
  }

  const getPageTitle = () => {
    const titles = {
      dashboard: 'Dashboard',
      monitoring: 'Monitoring',
      alerts: 'Alerts',
      processes: 'Processes',
      logs: 'Logs',
      data: 'Training Data',
      settings: 'Settings'
    }
    return titles[activePage] || 'Dashboard'
  }

  const PagePlaceholder = ({ title }) => (
    <div className="glass-panel" style={{ padding: '2rem', textAlign: 'center', borderRadius: '12px' }}>
      <h2 style={{ color: 'var(--text-primary)' }}>{title}</h2>
      <p style={{ color: 'var(--text-secondary)' }}>Module under development...</p>
    </div>
  )

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard': return <Dashboard isMonitoring={isMonitoring} />
      default: return <PagePlaceholder title={getPageTitle()} />
    }
  }

  return (
    <>
      <TitleBar theme={theme} />

      {/* Add padding-top to compensate for TitleBar (32px) */}
      <div className="app-container" style={{ paddingTop: '32px' }}>
        <Sidebar
          activePage={activePage}
          onPageChange={setActivePage}
          collapsed={sidebarCollapsed}
          onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        />

        <div className={`main-wrapper ${sidebarCollapsed ? 'expanded' : ''}`}>
          <main className="main-content">
            <Header
              title={getPageTitle()}
              isMonitoring={isMonitoring}
              onToggleMonitoring={handleToggleMonitoring}
              pendingActionsCount={pendingActions.length}
              onShowPendingActions={() => setShowApprovalModal(true)}
              theme={theme}
              onToggleTheme={toggleTheme}
            />

            <div className="dashboard-container fade-in">
              {renderPage()}
            </div>
          </main>
        </div>

        {showApprovalModal && pendingActions.length > 0 && (
          <ApprovalModal
            actions={pendingActions}
            onApprove={approve}
            onCancel={cancel}
            onClose={() => setShowApprovalModal(false)}
          />
        )}
      </div>
    </>
  )
}

export default App
