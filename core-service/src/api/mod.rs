//! API Module
//!
//! Organized with versioning for backward compatibility.
//!
//! Structure:
//! - commands.rs: Current stable API implementation
//! - v1/mod.rs: Re-exports commands as v1 API (for backward compat)
//!
//! Usage:
//! - `api::commands::get_system_status()` - Direct access
//! - `api::v1::get_system_status()` - Version 1 API
//!
//! Future:
//! - Add `v2/mod.rs` for breaking changes
//! - Keep `v1` for old clients

pub mod commands;
pub mod v1;

// Re-export current version as default
pub use commands::*;
