//! One-Shield Cloud Backend Server
//!
//! Central management server for One-Shield EDR agents.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    ONE-SHIELD CLOUD                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌───────────┐  ┌───────────┐  ┌─────────────────────────┐ │
//! │  │  API      │  │  Auth     │  │  Event Processing       │ │
//! │  │  Gateway  │  │  Service  │  │  (Background Jobs)      │ │
//! │  │  (Axum)   │  │  (JWT)    │  │                         │ │
//! │  └─────┬─────┘  └─────┬─────┘  └────────────┬────────────┘ │
//! │        └──────────────┼──────────────────────┘              │
//! │                       ▼                                     │
//! │                ┌─────────────┐                             │
//! │                │ PostgreSQL  │                             │
//! │                └─────────────┘                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```

mod config;
mod db;
mod models;
mod handlers;
mod middleware;
mod error;

use axum::{
    Router,
    routing::{get, post, put, delete},
    middleware as axum_middleware,
};
use tower_http::{
    cors::{CorsLayer, Any},
    trace::TraceLayer,
    compression::CompressionLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::net::SocketAddr;

pub use error::{AppError, AppResult};

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "oneshield_cloud=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    dotenvy::dotenv().ok();
    let config = config::Config::from_env();

    tracing::info!("One-Shield Cloud Server starting...");
    tracing::info!("Database: {}", config.database_url.split('@').last().unwrap_or("***"));

    // Initialize database pool
    let pool = db::create_pool(&config.database_url).await
        .expect("Failed to create database pool");

    // Run migrations
    tracing::info!("Running database migrations...");
    db::run_migrations(&pool).await
        .expect("Failed to run migrations");

    // Build application state
    let state = AppState {
        pool,
        config: config.clone(),
    };

    // Build router
    let app = create_router(state);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!("🚀 Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub config: config::Config,
}

/// Create the main router with all routes
fn create_router(state: AppState) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(handlers::health::check))
        .route("/api/v1/auth/login", post(handlers::auth::login))
        .route("/api/v1/auth/register", post(handlers::auth::register))
        // Personal enrollment (Phase 13 - desktop app login/register + agent)
        .route("/api/v1/personal/enroll", post(handlers::auth::personal_enroll))
        // Agent registration (legacy - uses registration_key)
        .route("/api/v1/agent/register", post(handlers::agent::register))
        // Agent enrollment (new - uses org enrollment token)
        .route("/api/v1/agent/enroll", post(handlers::agent::enroll));

    // Agent routes (agent token auth) - requires registered agent token
    let agent_routes = Router::new()
        .route("/api/v1/agent/heartbeat", post(handlers::agent::heartbeat))
        .route("/api/v1/agent/sync/baseline", post(handlers::agent::sync_baseline))
        .route("/api/v1/agent/sync/incidents", post(handlers::agent::sync_incidents))
        .route("/api/v1/agent/policy", get(handlers::agent::get_policy))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::require_agent_auth
        ));

    // Management routes (user JWT auth)
    let management_routes = Router::new()
        // Endpoints
        .route("/api/v1/endpoints", get(handlers::endpoints::list))
        .route("/api/v1/endpoints/:id", get(handlers::endpoints::get))
        .route("/api/v1/endpoints/:id", delete(handlers::endpoints::delete))

        // Incidents
        .route("/api/v1/incidents", get(handlers::incidents::list))
        .route("/api/v1/incidents/:id", get(handlers::incidents::get))
        .route("/api/v1/incidents/:id/status", put(handlers::incidents::update_status))

        // Policies
        .route("/api/v1/policies", get(handlers::policies::list))
        .route("/api/v1/policies", post(handlers::policies::create))
        .route("/api/v1/policies/:id", get(handlers::policies::get))
        .route("/api/v1/policies/:id", put(handlers::policies::update))

        // Reports
        .route("/api/v1/reports/executive", get(handlers::reports::executive))
        .route("/api/v1/reports/compliance", get(handlers::reports::compliance))

        // Organization
        .route("/api/v1/organization", get(handlers::organization::get))
        .route("/api/v1/organization/users", get(handlers::organization::list_users))

        // Enrollment Tokens (Phase 12)
        .route("/api/v1/tokens", get(handlers::tokens::list_tokens))
        .route("/api/v1/tokens", post(handlers::tokens::create_token))
        .route("/api/v1/tokens/:id", get(handlers::tokens::get_token))
        .route("/api/v1/tokens/:id", delete(handlers::tokens::revoke_token))

        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::require_user_auth
        ));

    // Combine all routes
    Router::new()
        .merge(public_routes)
        .merge(agent_routes)
        .merge(management_routes)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        )
        .with_state(state)
}
