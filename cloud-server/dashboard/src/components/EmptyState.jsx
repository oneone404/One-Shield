import { Shield, Key, AlertTriangle, Users, FileText, Settings, Plus } from 'lucide-react';
import './EmptyState.css';

// Predefined empty state configurations
const EMPTY_STATES = {
    agents: {
        icon: Shield,
        title: 'No Agents Connected',
        description: 'Deploy your first agent to start monitoring endpoints.',
        actionLabel: 'Create Token',
        actionLink: '/tokens',
        illustration: '🖥️',
    },
    incidents: {
        icon: AlertTriangle,
        title: 'No Incidents Detected',
        description: 'Great news! Your systems are secure. No threats have been detected.',
        illustration: '🎉',
        variant: 'success',
    },
    tokens: {
        icon: Key,
        title: 'No Enrollment Tokens',
        description: 'Create your first token to start enrolling agents.',
        actionLabel: 'Create Token',
        illustration: '🎫',
    },
    users: {
        icon: Users,
        title: 'You\'re the Only Member',
        description: 'Invite team members to collaborate on security monitoring.',
        actionLabel: 'Invite User',
        illustration: '👥',
        actionDisabled: true,
        actionNote: 'Coming Soon',
    },
    policies: {
        icon: FileText,
        title: 'No Policies Created',
        description: 'Create security policies to define rules for your endpoints.',
        actionLabel: 'Create Policy',
        illustration: '📋',
    },
    reports: {
        icon: FileText,
        title: 'No Reports Available',
        description: 'Reports will appear once you have active agents.',
        illustration: '📊',
    },
    settings: {
        icon: Settings,
        title: 'Nothing to Configure',
        description: 'All settings are up to date.',
        illustration: '⚙️',
    },
    generic: {
        icon: Shield,
        title: 'Nothing Here Yet',
        description: 'Content will appear when data is available.',
        illustration: '📭',
    },
};

export default function EmptyState({
    type = 'generic',
    title,
    description,
    actionLabel,
    actionLink,
    onAction,
    actionDisabled,
    actionNote,
    illustration,
    variant,
    showAction = true,
}) {
    // Get config from predefined or use custom props
    const config = EMPTY_STATES[type] || EMPTY_STATES.generic;

    const displayTitle = title || config.title;
    const displayDescription = description || config.description;
    const displayActionLabel = actionLabel || config.actionLabel;
    const displayActionLink = actionLink || config.actionLink;
    const displayIllustration = illustration || config.illustration;
    const displayVariant = variant || config.variant;
    const isActionDisabled = actionDisabled ?? config.actionDisabled;
    const displayActionNote = actionNote || config.actionNote;
    const IconComponent = config.icon;

    const handleAction = () => {
        if (onAction) {
            onAction();
        } else if (displayActionLink) {
            window.location.href = displayActionLink;
        }
    };

    return (
        <div className={`empty-state ${displayVariant || ''}`}>
            {/* Illustration */}
            <div className="empty-illustration">
                <span className="illustration-emoji">{displayIllustration}</span>
                <div className="illustration-glow"></div>
            </div>

            {/* Content */}
            <div className="empty-content">
                <h3 className="empty-title">{displayTitle}</h3>
                <p className="empty-description">{displayDescription}</p>
            </div>

            {/* Action Button */}
            {showAction && displayActionLabel && (
                <div className="empty-action">
                    <button
                        className="empty-action-btn"
                        onClick={handleAction}
                        disabled={isActionDisabled}
                    >
                        <Plus size={18} />
                        {displayActionLabel}
                        {displayActionNote && (
                            <span className="action-note">{displayActionNote}</span>
                        )}
                    </button>
                </div>
            )}

            {/* Tips for specific types */}
            {type === 'agents' && (
                <div className="empty-tips">
                    <p className="tip-title">Quick Start:</p>
                    <ol>
                        <li>Create an enrollment token</li>
                        <li>Download the agent installer</li>
                        <li>Run the installer on your endpoints</li>
                    </ol>
                </div>
            )}
        </div>
    );
}

// Convenience exports for specific empty states
export function EmptyAgents(props) {
    return <EmptyState type="agents" {...props} />;
}

export function EmptyIncidents(props) {
    return <EmptyState type="incidents" showAction={false} {...props} />;
}

export function EmptyTokens(props) {
    return <EmptyState type="tokens" {...props} />;
}

export function EmptyUsers(props) {
    return <EmptyState type="users" {...props} />;
}

export function EmptyPolicies(props) {
    return <EmptyState type="policies" {...props} />;
}
