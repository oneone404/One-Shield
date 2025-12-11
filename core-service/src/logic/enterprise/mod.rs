//! Enterprise Features Module - Multi-endpoint & Central Management (Phase 6)
//!
//! Mục đích: Scale cho doanh nghiệp với quản lý tập trung
//!
//! # Components
//! - `agent.rs`: Endpoint agent for central reporting
//! - `rbac.rs`: Role-based access control
//! - `policy_sync.rs`: Policy synchronization
//! - `reporting.rs`: Central reporting & analytics
//! - `api.rs`: REST API for management console

// Allow unused for now - will be fully integrated in future phases
#![allow(unused)]

pub mod agent;
pub mod rbac;
pub mod policy_sync;
pub mod reporting;
pub mod api;
pub mod types;

// Re-exports from types
pub use types::{
    // RBAC
    UserRole, Permission, Resource, Action, User, Session,
    // Agent
    AgentInfo, AgentStatus, EndpointReport, HeartbeatData,
    // Policy
    PolicyDefinition, PolicyRule, PolicyAction,
    // Reporting
    IncidentSummary, EndpointStats, ThreatOverview,
};

// Re-exports from submodules
pub use agent::{
    get_agent_id, register_agent, send_heartbeat,
    send_report, get_agent_info,
};
pub use rbac::{
    authenticate, authorize, create_session, validate_session,
    has_permission, get_user_permissions,
};
pub use policy_sync::{
    sync_policies, get_active_policies, apply_policy,
};
pub use reporting::{
    generate_summary, get_endpoint_stats, get_threat_overview,
};
