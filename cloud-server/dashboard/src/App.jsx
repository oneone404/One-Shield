import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { isAuthenticated } from './services/api';
import Sidebar from './components/Layout/Sidebar';

// Pages
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';

// Styles
import './styles/index.css';

// Protected Route Wrapper
function ProtectedRoute() {
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />;
}

// Main Layout with Sidebar
function MainLayout() {
  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}

// Placeholder pages (will implement later)
function AgentsPage() {
  return (
    <div style={{ padding: '2rem' }}>
      <h1>Agents</h1>
      <p>Coming soon...</p>
    </div>
  );
}

function IncidentsPage() {
  return (
    <div style={{ padding: '2rem' }}>
      <h1>Incidents</h1>
      <p>Coming soon...</p>
    </div>
  );
}

function PoliciesPage() {
  return (
    <div style={{ padding: '2rem' }}>
      <h1>Policies</h1>
      <p>Coming soon...</p>
    </div>
  );
}

function ReportsPage() {
  return (
    <div style={{ padding: '2rem' }}>
      <h1>Reports</h1>
      <p>Coming soon...</p>
    </div>
  );
}

function SettingsPage() {
  return (
    <div style={{ padding: '2rem' }}>
      <h1>Settings</h1>
      <p>Coming soon...</p>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public Routes */}
        <Route path="/login" element={<Login />} />

        {/* Protected Routes */}
        <Route element={<ProtectedRoute />}>
          <Route element={<MainLayout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/agents" element={<AgentsPage />} />
            <Route path="/incidents" element={<IncidentsPage />} />
            <Route path="/policies" element={<PoliciesPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
        </Route>

        {/* Fallback */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
