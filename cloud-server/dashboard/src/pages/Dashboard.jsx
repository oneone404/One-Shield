import { useState, useEffect } from 'react';
import {
    Monitor,
    AlertTriangle,
    Shield,
    Activity,
    TrendingUp,
    TrendingDown,
    Clock,
    CheckCircle,
    XCircle,
} from 'lucide-react';
import Header from '../components/Layout/Header';
import { getEndpoints, getIncidents } from '../services/api';
import './Dashboard.css';

// Stat Card Component
function StatCard({ icon: Icon, label, value, change, changeType, color }) {
    return (
        <div className={`stat-card stat-${color}`}>
            <div className="stat-icon-wrapper">
                <Icon className="stat-icon" size={24} />
            </div>
            <div className="stat-content">
                <span className="stat-label">{label}</span>
                <span className="stat-value">{value}</span>
                {change !== undefined && (
                    <span className={`stat-change ${changeType}`}>
                        {changeType === 'positive' ? (
                            <TrendingUp size={14} />
                        ) : changeType === 'negative' ? (
                            <TrendingDown size={14} />
                        ) : null}
                        <span>{change}</span>
                    </span>
                )}
            </div>
        </div>
    );
}

// Agent Status Card
function AgentCard({ agent }) {
    const isOnline = agent.status === 'online';
    const lastSeen = agent.last_heartbeat
        ? new Date(agent.last_heartbeat).toLocaleString()
        : 'Never';

    return (
        <div className="agent-card glass-card">
            <div className="agent-header">
                <div className="agent-status">
                    <span className={`status-dot ${isOnline ? 'online' : 'offline'}`}></span>
                    <span className="agent-name">{agent.hostname}</span>
                </div>
                <span className={`badge ${isOnline ? 'badge-success' : 'badge-neutral'}`}>
                    {isOnline ? 'Online' : 'Offline'}
                </span>
            </div>
            <div className="agent-details">
                <div className="agent-detail">
                    <span className="detail-label">OS</span>
                    <span className="detail-value">{agent.os_type || 'Unknown'}</span>
                </div>
                <div className="agent-detail">
                    <span className="detail-label">Version</span>
                    <span className="detail-value">{agent.agent_version || 'N/A'}</span>
                </div>
                <div className="agent-detail">
                    <span className="detail-label">Last Seen</span>
                    <span className="detail-value text-sm">{lastSeen}</span>
                </div>
            </div>
        </div>
    );
}

// Incident Row
function IncidentRow({ incident }) {
    const severityClass = `badge-${incident.severity}`;
    const time = new Date(incident.created_at).toLocaleString();

    return (
        <tr className="incident-row">
            <td>
                <span className={`badge ${severityClass}`}>
                    {incident.severity}
                </span>
            </td>
            <td className="incident-title">
                {incident.title.length > 60
                    ? incident.title.substring(0, 60) + '...'
                    : incident.title}
            </td>
            <td className="text-sm text-secondary">{time}</td>
            <td>
                <span className={`badge ${incident.status === 'open' ? 'badge-warning' : 'badge-success'}`}>
                    {incident.status}
                </span>
            </td>
        </tr>
    );
}

export default function Dashboard() {
    const [loading, setLoading] = useState(true);
    const [stats, setStats] = useState({
        totalAgents: 0,
        onlineAgents: 0,
        totalIncidents: 0,
        openIncidents: 0,
    });
    const [agents, setAgents] = useState([]);
    const [incidents, setIncidents] = useState([]);

    useEffect(() => {
        fetchData();
    }, []);

    async function fetchData() {
        try {
            setLoading(true);

            // Fetch endpoints - API returns array directly
            const endpointsData = await getEndpoints();
            const endpointsList = Array.isArray(endpointsData) ? endpointsData : (endpointsData.endpoints || []);
            setAgents(endpointsList.slice(0, 6));

            // Fetch incidents - API may return array directly
            const incidentsData = await getIncidents(10, 0);
            const incidentsList = Array.isArray(incidentsData) ? incidentsData : (incidentsData.incidents || []);
            setIncidents(incidentsList);

            // Calculate stats
            const online = endpointsList.filter(e => e.status === 'online').length;
            const openIncidents = incidentsList.filter(i => i.status === 'open').length;

            setStats({
                totalAgents: endpointsList.length,
                onlineAgents: online,
                totalIncidents: incidentsList.length,
                openIncidents,
            });
        } catch (error) {
            console.error('Failed to fetch data:', error);
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="dashboard-page">
            <Header
                title="Dashboard"
                subtitle="Security overview and monitoring"
            />

            <main className="dashboard-content">
                {/* Stats Grid */}
                <section className="stats-section">
                    <div className="stats-grid">
                        <StatCard
                            icon={Monitor}
                            label="Total Agents"
                            value={stats.totalAgents}
                            change="Active endpoints"
                            color="blue"
                        />
                        <StatCard
                            icon={CheckCircle}
                            label="Online"
                            value={stats.onlineAgents}
                            change={`${Math.round((stats.onlineAgents / stats.totalAgents) * 100) || 0}% uptime`}
                            changeType="positive"
                            color="green"
                        />
                        <StatCard
                            icon={AlertTriangle}
                            label="Total Incidents"
                            value={stats.totalIncidents}
                            change="All time"
                            color="yellow"
                        />
                        <StatCard
                            icon={XCircle}
                            label="Open Issues"
                            value={stats.openIncidents}
                            change="Requires attention"
                            changeType={stats.openIncidents > 0 ? 'negative' : 'positive'}
                            color="red"
                        />
                    </div>
                </section>

                <div className="dashboard-grid">
                    {/* Recent Agents */}
                    <section className="agents-section glass-card">
                        <div className="section-header">
                            <h3>
                                <Monitor size={18} />
                                Recent Agents
                            </h3>
                            <a href="/agents" className="view-all">View all →</a>
                        </div>
                        <div className="agents-grid">
                            {loading ? (
                                Array(3).fill(0).map((_, i) => (
                                    <div key={i} className="skeleton agent-skeleton"></div>
                                ))
                            ) : agents.length > 0 ? (
                                agents.map(agent => (
                                    <AgentCard key={agent.id} agent={agent} />
                                ))
                            ) : (
                                <p className="empty-message">No agents registered</p>
                            )}
                        </div>
                    </section>

                    {/* Recent Incidents */}
                    <section className="incidents-section glass-card">
                        <div className="section-header">
                            <h3>
                                <AlertTriangle size={18} />
                                Recent Incidents
                            </h3>
                            <a href="/incidents" className="view-all">View all →</a>
                        </div>
                        <div className="incidents-table-wrapper">
                            {loading ? (
                                <div className="skeleton incidents-skeleton"></div>
                            ) : incidents.length > 0 ? (
                                <table className="table incidents-table">
                                    <thead>
                                        <tr>
                                            <th>Severity</th>
                                            <th>Title</th>
                                            <th>Time</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {incidents.map(incident => (
                                            <IncidentRow key={incident.id} incident={incident} />
                                        ))}
                                    </tbody>
                                </table>
                            ) : (
                                <p className="empty-message">No incidents recorded</p>
                            )}
                        </div>
                    </section>
                </div>

                {/* Security Score */}
                <section className="security-section glass-card">
                    <div className="section-header">
                        <h3>
                            <Shield size={18} />
                            Security Overview
                        </h3>
                    </div>
                    <div className="security-content">
                        <div className="security-score">
                            <div className="score-circle">
                                <svg viewBox="0 0 100 100">
                                    <circle
                                        className="score-bg"
                                        cx="50"
                                        cy="50"
                                        r="45"
                                    />
                                    <circle
                                        className="score-progress"
                                        cx="50"
                                        cy="50"
                                        r="45"
                                        strokeDasharray="283"
                                        strokeDashoffset="56"
                                    />
                                </svg>
                                <div className="score-value">
                                    <span className="score-number">80</span>
                                    <span className="score-label">Score</span>
                                </div>
                            </div>
                        </div>
                        <div className="security-details">
                            <div className="security-item">
                                <Activity size={18} />
                                <div>
                                    <span className="item-label">Detection Rate</span>
                                    <span className="item-value">98.5%</span>
                                </div>
                            </div>
                            <div className="security-item">
                                <Clock size={18} />
                                <div>
                                    <span className="item-label">Avg Response Time</span>
                                    <span className="item-value">2.3s</span>
                                </div>
                            </div>
                            <div className="security-item">
                                <Shield size={18} />
                                <div>
                                    <span className="item-label">Threats Blocked</span>
                                    <span className="item-value">{stats.totalIncidents}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>
            </main>
        </div>
    );
}
