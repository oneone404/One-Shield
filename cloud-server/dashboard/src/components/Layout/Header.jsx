import { Bell, Search, RefreshCw } from 'lucide-react';
import './Header.css';

export default function Header({ title, subtitle }) {
    return (
        <header className="header">
            <div className="header-left">
                <div className="header-title">
                    <h1>{title}</h1>
                    {subtitle && <p className="header-subtitle">{subtitle}</p>}
                </div>
            </div>

            <div className="header-right">
                {/* Search */}
                <div className="header-search">
                    <Search className="search-icon" size={18} />
                    <input
                        type="text"
                        placeholder="Search agents, incidents..."
                        className="search-input"
                    />
                </div>

                {/* Actions */}
                <div className="header-actions">
                    <button className="header-btn" title="Refresh">
                        <RefreshCw size={18} />
                    </button>
                    <button className="header-btn notification-btn" title="Notifications">
                        <Bell size={18} />
                        <span className="notification-badge">3</span>
                    </button>
                </div>

                {/* Server Status */}
                <div className="server-status">
                    <span className="status-dot online"></span>
                    <span className="status-text">Cloud Connected</span>
                </div>
            </div>
        </header>
    );
}
