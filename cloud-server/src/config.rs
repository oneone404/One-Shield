//! Configuration module

use std::env;

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Database connection URL
    pub database_url: String,

    /// Server port
    pub port: u16,

    /// JWT secret key
    pub jwt_secret: String,

    /// JWT expiration in hours
    pub jwt_expiration_hours: u64,

    /// Agent token secret
    pub agent_secret: String,

    /// Environment (development, production)
    pub environment: String,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://oneshield:oneshield@localhost/oneshield".to_string()),

            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),

            jwt_secret: env::var("JWT_SECRET")
                .unwrap_or_else(|_| "oneshield-super-secret-key-change-in-production".to_string()),

            jwt_expiration_hours: env::var("JWT_EXPIRATION_HOURS")
                .ok()
                .and_then(|h| h.parse().ok())
                .unwrap_or(24),

            agent_secret: env::var("AGENT_SECRET")
                .unwrap_or_else(|_| "dev-agent-secret-change-in-production-789012".to_string()),

            environment: env::var("ENVIRONMENT")
                .unwrap_or_else(|_| "development".to_string()),
        }
    }

    /// Check if running in production
    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }
}
