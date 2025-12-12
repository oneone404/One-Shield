-- One-Shield Cloud Database Initialization
-- This script runs automatically when the PostgreSQL container starts

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Organizations (Multi-tenant)
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    license_key VARCHAR(255) UNIQUE,
    max_agents INT DEFAULT 10,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Endpoints (Agents)
CREATE TABLE IF NOT EXISTS endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    os_type VARCHAR(50),
    os_version VARCHAR(100),
    agent_version VARCHAR(50),
    ip_address VARCHAR(45),
    token_hash VARCHAR(255),
    last_heartbeat TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'online',
    baseline_hash VARCHAR(64),
    baseline_version INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Incidents (Synced from agents)
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY,
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    mitre_techniques JSONB,
    threat_class VARCHAR(50),
    confidence REAL,
    status VARCHAR(20) DEFAULT 'open',
    assigned_to UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

-- Policies
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    config JSONB NOT NULL,
    version INT DEFAULT 1,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Baselines (Aggregated from agents)
CREATE TABLE IF NOT EXISTS baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE UNIQUE,
    mean_values JSONB NOT NULL,
    variance_values JSONB,
    sample_count BIGINT DEFAULT 0,
    version INT DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit Log
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID REFERENCES organizations(id),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Agent Heartbeat History (for analytics)
CREATE TABLE IF NOT EXISTS heartbeat_history (
    id BIGSERIAL PRIMARY KEY,
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE,
    cpu_usage REAL,
    memory_usage REAL,
    disk_usage REAL,
    incident_count INT,
    process_count INT,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_endpoints_org ON endpoints(org_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_heartbeat ON endpoints(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
CREATE INDEX IF NOT EXISTS idx_incidents_endpoint ON incidents(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_policies_org ON policies(org_id);
CREATE INDEX IF NOT EXISTS idx_heartbeat_endpoint ON heartbeat_history(endpoint_id, recorded_at);

-- Insert default organization
INSERT INTO organizations (name, license_key, max_agents)
VALUES ('Default Organization', 'OS-DEFAULT-001', 100)
ON CONFLICT DO NOTHING;

-- Create demo admin user (password: admin123)
-- Password hash for 'admin123' using argon2
INSERT INTO users (org_id, email, password_hash, name, role)
SELECT
    o.id,
    'admin@oneshield.local',
    '$argon2id$v=19$m=19456,t=2,p=1$5wNjXQZpOSKpIJzNFX1X3Q$VvgkzLQGNfO6YHxfBAhLAOT0cNwFYi7LKvdX6vK5bKk',
    'Admin User',
    'admin'
FROM organizations o
WHERE o.license_key = 'OS-DEFAULT-001'
ON CONFLICT (email) DO NOTHING;

-- Create default policy
INSERT INTO policies (org_id, name, description, config, is_active)
SELECT
    o.id,
    'Default Security Policy',
    'Standard EDR security policy with all detections enabled',
    '{
        "scan_interval_seconds": 2,
        "baseline_sensitivity": 0.7,
        "enable_amsi": true,
        "enable_injection_detection": true,
        "enable_keylogger_detection": true,
        "enable_iat_analysis": true,
        "auto_quarantine": false,
        "notification_channels": ["dashboard"]
    }'::jsonb,
    true
FROM organizations o
WHERE o.license_key = 'OS-DEFAULT-001'
ON CONFLICT DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO oneshield;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO oneshield;

-- Display success message
DO $$
BEGIN
    RAISE NOTICE '✅ One-Shield database initialized successfully!';
    RAISE NOTICE '📧 Default admin: admin@oneshield.local';
    RAISE NOTICE '🔑 Default password: admin123';
END $$;
