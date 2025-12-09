/**
 * Action Approval Modal - Phê duyệt hành động can thiệp
 *
 * Hiển thị modal khi có pending actions yêu cầu user approval.
 * Critical UI element cho Phase III - Proactive Defense.
 */

import React, { useState } from 'react';
import { Shield, AlertTriangle, Skull, Ban, Lock, X, Check, Clock, Zap } from 'lucide-react';

const ACTION_ICONS = {
    KillProcess: Skull,
    BlockNetworkIO: Ban,
    SuspendProcess: Clock,
    IsolateSession: Lock,
    AlertOnly: AlertTriangle,
};

const ACTION_LABELS = {
    KillProcess: 'Dừng Tiến Trình',
    BlockNetworkIO: 'Chặn Network',
    SuspendProcess: 'Tạm Dừng',
    IsolateSession: 'Khóa Session',
    AlertOnly: 'Cảnh Báo',
};

const ACTION_DESCRIPTIONS = {
    KillProcess: 'Tiến trình sẽ bị dừng ngay lập tức. Có thể mất dữ liệu chưa lưu.',
    BlockNetworkIO: 'Tất cả kết nối mạng của tiến trình sẽ bị chặn.',
    SuspendProcess: 'Tiến trình sẽ bị tạm dừng và có thể resume sau.',
    IsolateSession: 'Máy tính sẽ bị khóa ngay lập tức để bảo vệ.',
    AlertOnly: 'Chỉ ghi nhận cảnh báo, không có hành động can thiệp.',
};

function ApprovalModal({ actions, onApprove, onCancel, onClose }) {
    const [processingId, setProcessingId] = useState(null);

    if (!actions || actions.length === 0) {
        return null;
    }

    const handleApprove = async (actionId) => {
        setProcessingId(actionId);
        try {
            await onApprove(actionId);
        } finally {
            setProcessingId(null);
        }
    };

    const handleCancel = async (actionId) => {
        setProcessingId(actionId);
        try {
            await onCancel(actionId);
        } finally {
            setProcessingId(null);
        }
    };

    const formatTime = (isoString) => {
        try {
            const date = new Date(isoString);
            return date.toLocaleTimeString('vi-VN', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        } catch {
            return '--:--:--';
        }
    };

    const formatExpiresIn = (expiresAt) => {
        try {
            const now = new Date();
            const expires = new Date(expiresAt);
            const diffMs = expires - now;
            const diffSecs = Math.max(0, Math.floor(diffMs / 1000));
            const mins = Math.floor(diffSecs / 60);
            const secs = diffSecs % 60;
            return `${mins}:${secs.toString().padStart(2, '0')}`;
        } catch {
            return '0:00';
        }
    };

    const getSeverityColor = (score) => {
        if (score >= 0.95) return 'critical';
        if (score >= 0.85) return 'high';
        if (score >= 0.7) return 'medium';
        return 'low';
    };

    return (
        <div className="approval-modal-overlay">
            <div className="approval-modal">
                <div className="approval-modal-header">
                    <div className="header-icon critical">
                        <Shield size={28} />
                    </div>
                    <div className="header-content">
                        <h2>Yêu Cầu Phê Duyệt</h2>
                        <p>Phát hiện {actions.length} mối đe dọa cần xử lý</p>
                    </div>
                    <button className="close-button" onClick={onClose}>
                        <X size={20} />
                    </button>
                </div>

                <div className="approval-modal-body">
                    {actions.map((action) => {
                        const ActionIcon = ACTION_ICONS[action.action_type] || AlertTriangle;
                        const severityClass = getSeverityColor(action.final_score);
                        const isProcessing = processingId === action.id;

                        return (
                            <div
                                key={action.id}
                                className={`action-card ${severityClass} ${isProcessing ? 'processing' : ''}`}
                            >
                                <div className="action-card-header">
                                    <div className={`action-icon ${severityClass}`}>
                                        <ActionIcon size={24} />
                                    </div>
                                    <div className="action-info">
                                        <h3>{ACTION_LABELS[action.action_type] || action.action_type}</h3>
                                        <span className="target-name">
                                            {action.target_name}
                                            {action.target_pid > 0 && ` (PID: ${action.target_pid})`}
                                        </span>
                                    </div>
                                    <div className="score-badge">
                                        <Zap size={14} />
                                        <span>{(action.final_score * 100).toFixed(1)}%</span>
                                    </div>
                                </div>

                                <div className="action-card-body">
                                    <p className="action-description">
                                        {ACTION_DESCRIPTIONS[action.action_type]}
                                    </p>

                                    <div className="action-details">
                                        <div className="detail-item">
                                            <span className="label">Lý do:</span>
                                            <span className="value">{action.reason}</span>
                                        </div>
                                        <div className="detail-item">
                                            <span className="label">Thời gian:</span>
                                            <span className="value">{formatTime(action.created_at)}</span>
                                        </div>
                                        <div className="detail-item expires">
                                            <span className="label">Hết hạn trong:</span>
                                            <span className="value countdown">{formatExpiresIn(action.expires_at)}</span>
                                        </div>
                                    </div>
                                </div>

                                <div className="action-card-footer">
                                    <button
                                        className="btn btn-cancel"
                                        onClick={() => handleCancel(action.id)}
                                        disabled={isProcessing}
                                    >
                                        <X size={16} />
                                        Bỏ qua
                                    </button>
                                    <button
                                        className="btn btn-approve"
                                        onClick={() => handleApprove(action.id)}
                                        disabled={isProcessing}
                                    >
                                        {isProcessing ? (
                                            <span className="spinner" />
                                        ) : (
                                            <Check size={16} />
                                        )}
                                        Phê duyệt
                                    </button>
                                </div>
                            </div>
                        );
                    })}
                </div>

                <div className="approval-modal-footer">
                    <div className="footer-info">
                        <AlertTriangle size={16} />
                        <span>Các hành động sẽ tự động hủy sau 5 phút nếu không được phê duyệt.</span>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default ApprovalModal;
