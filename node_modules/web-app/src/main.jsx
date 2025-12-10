import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

// Global Styles
import './styles/index.css'

// Component Styles
import './styles/components/layout.css'
import './styles/components/sidebar.css'
import './styles/components/header.css'
import './styles/components/cards.css'
import './styles/components/buttons.css'
import './styles/components/modal.css'
import './styles/components/approval-modal.css'
import './styles/components/chart.css'
import './styles/components/titlebar.css'

// Page Styles
import './styles/pages/dashboard.css'

import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
