import './LoadingSpinner.css'

/**
 * LoadingSpinner - Reusable spinner component
 *
 * Sizes: sm (16px), md (24px), lg (40px), xl (64px)
 */
export function LoadingSpinner({ size = 'md', className = '' }) {
    return (
        <div className={`spinner spinner-${size} ${className}`}>
            <div className="spinner-ring"></div>
        </div>
    )
}

/**
 * LoadingButton - Button with loading state
 */
export function LoadingButton({
    children,
    loading = false,
    disabled = false,
    className = '',
    onClick,
    type = 'button',
    ...props
}) {
    return (
        <button
            type={type}
            className={`loading-btn ${className} ${loading ? 'is-loading' : ''}`}
            disabled={disabled || loading}
            onClick={onClick}
            {...props}
        >
            {loading && <LoadingSpinner size="sm" className="btn-spinner" />}
            <span className={loading ? 'btn-text-hidden' : ''}>{children}</span>
        </button>
    )
}

/**
 * LoadingOverlay - Full overlay with spinner
 */
export function LoadingOverlay({ message = 'Loading...' }) {
    return (
        <div className="loading-overlay">
            <div className="loading-content">
                <LoadingSpinner size="lg" />
                {message && <p className="loading-message">{message}</p>}
            </div>
        </div>
    )
}

/**
 * Skeleton - Loading placeholder
 */
export function Skeleton({ width, height, className = '', variant = 'rect' }) {
    const style = {
        width: width || '100%',
        height: height || '1rem'
    }

    return (
        <div
            className={`skeleton skeleton-${variant} ${className}`}
            style={style}
        />
    )
}

/**
 * SkeletonCard - Card placeholder
 */
export function SkeletonCard() {
    return (
        <div className="skeleton-card">
            <Skeleton height="120px" />
            <div className="skeleton-card-content">
                <Skeleton width="60%" height="1rem" />
                <Skeleton width="80%" height="0.875rem" />
                <Skeleton width="40%" height="0.875rem" />
            </div>
        </div>
    )
}

export default LoadingSpinner
