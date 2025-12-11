//! REST API Module (Phase 6)
//!
//! Mục đích: Expose REST API cho management console
//!
//! Features:
//! - API endpoint definitions
//! - Request/response handling
//! - Authentication middleware

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::types::{ApiRequest, ApiResponse, Resource, Action, User};
use super::rbac::{self, RbacError, validate_session, authenticate_api_key};

// ============================================================================
// API ROUTES
// ============================================================================

/// API route definition
#[derive(Debug, Clone)]
pub struct ApiRoute {
    pub method: String,
    pub path: String,
    pub resource: Resource,
    pub action: Action,
    pub handler: String,
    pub description: String,
}

/// Get all available API routes
pub fn get_routes() -> Vec<ApiRoute> {
    vec![
        // Incidents
        ApiRoute {
            method: "GET".to_string(),
            path: "/api/v1/incidents".to_string(),
            resource: Resource::Incidents,
            action: Action::Read,
            handler: "list_incidents".to_string(),
            description: "List all incidents".to_string(),
        },
        ApiRoute {
            method: "GET".to_string(),
            path: "/api/v1/incidents/:id".to_string(),
            resource: Resource::Incidents,
            action: Action::Read,
            handler: "get_incident".to_string(),
            description: "Get incident by ID".to_string(),
        },
        ApiRoute {
            method: "PUT".to_string(),
            path: "/api/v1/incidents/:id".to_string(),
            resource: Resource::Incidents,
            action: Action::Write,
            handler: "update_incident".to_string(),
            description: "Update incident".to_string(),
        },

        // Endpoints
        ApiRoute {
            method: "GET".to_string(),
            path: "/api/v1/endpoints".to_string(),
            resource: Resource::Endpoints,
            action: Action::Read,
            handler: "list_endpoints".to_string(),
            description: "List all endpoints".to_string(),
        },
        ApiRoute {
            method: "GET".to_string(),
            path: "/api/v1/endpoints/:id".to_string(),
            resource: Resource::Endpoints,
            action: Action::Read,
            handler: "get_endpoint".to_string(),
            description: "Get endpoint by ID".to_string(),
        },

        // Policies
        ApiRoute {
            method: "GET".to_string(),
            path: "/api/v1/policies".to_string(),
            resource: Resource::Policies,
            action: Action::Read,
            handler: "list_policies".to_string(),
            description: "List all policies".to_string(),
        },
        ApiRoute {
            method: "POST".to_string(),
            path: "/api/v1/policies".to_string(),
            resource: Resource::Policies,
            action: Action::Write,
            handler: "create_policy".to_string(),
            description: "Create a new policy".to_string(),
        },
        ApiRoute {
            method: "PUT".to_string(),
            path: "/api/v1/policies/:id".to_string(),
            resource: Resource::Policies,
            action: Action::Write,
            handler: "update_policy".to_string(),
            description: "Update a policy".to_string(),
        },
        ApiRoute {
            method: "DELETE".to_string(),
            path: "/api/v1/policies/:id".to_string(),
            resource: Resource::Policies,
            action: Action::Delete,
            handler: "delete_policy".to_string(),
            description: "Delete a policy".to_string(),
        },

        // Actions
        ApiRoute {
            method: "POST".to_string(),
            path: "/api/v1/actions/kill".to_string(),
            resource: Resource::Actions,
            action: Action::Execute,
            handler: "kill_process".to_string(),
            description: "Kill a process".to_string(),
        },
        ApiRoute {
            method: "POST".to_string(),
            path: "/api/v1/actions/quarantine".to_string(),
            resource: Resource::Actions,
            action: Action::Execute,
            handler: "quarantine_file".to_string(),
            description: "Quarantine a file".to_string(),
        },
        ApiRoute {
            method: "POST".to_string(),
            path: "/api/v1/actions/block-network".to_string(),
            resource: Resource::Actions,
            action: Action::Execute,
            handler: "block_network".to_string(),
            description: "Block network for a process".to_string(),
        },

        // Reports
        ApiRoute {
            method: "GET".to_string(),
            path: "/api/v1/reports/summary".to_string(),
            resource: Resource::Reports,
            action: Action::Read,
            handler: "get_summary".to_string(),
            description: "Get incident summary".to_string(),
        },
        ApiRoute {
            method: "GET".to_string(),
            path: "/api/v1/reports/executive".to_string(),
            resource: Resource::Reports,
            action: Action::Read,
            handler: "get_executive_report".to_string(),
            description: "Get executive report".to_string(),
        },

        // Users (Admin only)
        ApiRoute {
            method: "GET".to_string(),
            path: "/api/v1/users".to_string(),
            resource: Resource::Users,
            action: Action::Read,
            handler: "list_users".to_string(),
            description: "List all users".to_string(),
        },
        ApiRoute {
            method: "POST".to_string(),
            path: "/api/v1/users".to_string(),
            resource: Resource::Users,
            action: Action::Write,
            handler: "create_user".to_string(),
            description: "Create a new user".to_string(),
        },

        // Auth
        ApiRoute {
            method: "POST".to_string(),
            path: "/api/v1/auth/login".to_string(),
            resource: Resource::All,
            action: Action::Read,
            handler: "login".to_string(),
            description: "Login to get session token".to_string(),
        },
        ApiRoute {
            method: "POST".to_string(),
            path: "/api/v1/auth/logout".to_string(),
            resource: Resource::All,
            action: Action::Read,
            handler: "logout".to_string(),
            description: "Logout and invalidate session".to_string(),
        },
    ]
}

// ============================================================================
// REQUEST HANDLING
// ============================================================================

/// Authenticate a request
pub fn authenticate_request(request: &ApiRequest) -> Result<User, ApiError> {
    // Check Authorization header
    let auth_header = request.headers.get("Authorization")
        .or_else(|| request.headers.get("authorization"))
        .ok_or(ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    if auth_header.starts_with("Bearer ") {
        let token = &auth_header[7..];
        validate_session(token)
            .map_err(|e| ApiError::Unauthorized(e.to_string()))
    } else if auth_header.starts_with("ApiKey ") {
        let key = &auth_header[7..];
        authenticate_api_key(key)
            .map_err(|e| ApiError::Unauthorized(e.to_string()))
    } else {
        Err(ApiError::Unauthorized("Invalid Authorization format".to_string()))
    }
}

/// Check authorization for a route
pub fn authorize_request(user: &User, route: &ApiRoute) -> Result<(), ApiError> {
    if user.has_permission(route.resource, route.action) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(format!(
            "User '{}' does not have permission for {} on {}",
            user.username,
            route.action.as_str(),
            route.resource.as_str()
        )))
    }
}

/// Find matching route
pub fn find_route(method: &str, path: &str) -> Option<ApiRoute> {
    let routes = get_routes();

    for route in routes {
        if route.method != method {
            continue;
        }

        // Simple path matching (ignores params for now)
        let route_parts: Vec<&str> = route.path.split('/').collect();
        let path_parts: Vec<&str> = path.split('/').collect();

        if route_parts.len() != path_parts.len() {
            continue;
        }

        let mut matches = true;
        for (i, part) in route_parts.iter().enumerate() {
            if part.starts_with(':') {
                // Path parameter, matches anything
                continue;
            }
            if *part != path_parts[i] {
                matches = false;
                break;
            }
        }

        if matches {
            return Some(route);
        }
    }

    None
}

/// Handle an API request
pub fn handle_request(request: &ApiRequest) -> ApiResponse {
    // Find route
    let route = match find_route(&request.method, &request.path) {
        Some(r) => r,
        None => return ApiResponse::error(404, "Route not found"),
    };

    // Skip auth for login
    if route.handler == "login" {
        return handle_login(request);
    }

    // Authenticate
    let user = match authenticate_request(request) {
        Ok(u) => u,
        Err(e) => return ApiResponse::error(401, &e.to_string()),
    };

    // Authorize
    if let Err(e) = authorize_request(&user, &route) {
        return ApiResponse::error(403, &e.to_string());
    }

    // Call handler
    match route.handler.as_str() {
        "list_incidents" => handle_list_incidents(),
        "list_endpoints" => handle_list_endpoints(),
        "list_policies" => handle_list_policies(),
        "list_users" => handle_list_users(),
        "get_summary" => handle_get_summary(request),
        "get_executive_report" => handle_get_executive_report(request),
        "logout" => handle_logout(request),
        _ => ApiResponse::error(501, "Handler not implemented"),
    }
}

// ============================================================================
// HANDLERS
// ============================================================================

fn handle_login(request: &ApiRequest) -> ApiResponse {
    #[derive(Deserialize)]
    struct LoginRequest {
        username: String,
        password: String,
    }

    let body = match &request.body {
        Some(b) => b,
        None => return ApiResponse::error(400, "Missing request body"),
    };

    let login_req: LoginRequest = match serde_json::from_value(body.clone()) {
        Ok(r) => r,
        Err(_) => return ApiResponse::error(400, "Invalid request body"),
    };

    match rbac::authenticate(&login_req.username, &login_req.password) {
        Ok(session) => {
            ApiResponse::success(serde_json::json!({
                "token": session.token,
                "expires_at": session.expires_at,
            }))
        }
        Err(e) => ApiResponse::error(401, &e.to_string()),
    }
}

fn handle_logout(request: &ApiRequest) -> ApiResponse {
    if let Some(auth) = request.headers.get("Authorization") {
        if auth.starts_with("Bearer ") {
            let token = &auth[7..];
            rbac::revoke_session(token);
        }
    }
    ApiResponse::success(serde_json::json!({"message": "Logged out"}))
}

fn handle_list_incidents() -> ApiResponse {
    // TODO: Get from incident manager
    ApiResponse::success(serde_json::json!({
        "incidents": [],
        "total": 0
    }))
}

fn handle_list_endpoints() -> ApiResponse {
    let stats = super::agent::get_stats();
    ApiResponse::success(serde_json::json!({
        "endpoints": [{
            "id": stats.agent_id,
            "hostname": stats.hostname,
            "status": stats.status,
            "connected": stats.connected,
        }],
        "total": 1
    }))
}

fn handle_list_policies() -> ApiResponse {
    let policies = super::policy_sync::get_active_policies();
    ApiResponse::success(serde_json::json!({
        "policies": policies,
        "total": policies.len()
    }))
}

fn handle_list_users() -> ApiResponse {
    let users = rbac::list_users();
    // Remove sensitive fields
    let safe_users: Vec<_> = users.into_iter()
        .map(|u| serde_json::json!({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role.as_str(),
            "enabled": u.enabled,
            "last_login": u.last_login,
        }))
        .collect();

    ApiResponse::success(serde_json::json!({
        "users": safe_users,
        "total": safe_users.len()
    }))
}

fn handle_get_summary(request: &ApiRequest) -> ApiResponse {
    let summary = super::reporting::generate_daily_summary();
    ApiResponse::success(serde_json::to_value(summary).unwrap_or_default())
}

fn handle_get_executive_report(request: &ApiRequest) -> ApiResponse {
    let period = request.headers.get("X-Period").map(|s| s.as_str()).unwrap_or("daily");
    let report = super::reporting::generate_executive_summary(period);
    ApiResponse::success(serde_json::to_value(report).unwrap_or_default())
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum ApiError {
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    BadRequest(String),
    InternalError(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            ApiError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            ApiError::NotFound(msg) => write!(f, "Not found: {}", msg),
            ApiError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            ApiError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for ApiError {}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct ApiStats {
    pub total_routes: usize,
    pub by_resource: HashMap<String, usize>,
}

pub fn get_stats() -> ApiStats {
    let routes = get_routes();

    let by_resource = routes.iter()
        .fold(HashMap::new(), |mut acc, r| {
            *acc.entry(r.resource.as_str().to_string()).or_insert(0) += 1;
            acc
        });

    ApiStats {
        total_routes: routes.len(),
        by_resource,
    }
}
