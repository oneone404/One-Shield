//! API Module
//!
//! Organized with versioning for backward compatibility.
//!
//! Structure:
//! - commands.rs: Current stable API implementation
//! - enterprise.rs: Enterprise features API (v2.0)
//! - v1/mod.rs: Re-exports commands as v1 API (for backward compat)
//!
//! Usage:
//! - `api::commands::get_system_status()` - Direct access
//! - `api::enterprise::get_users()` - Enterprise API
//! - `api::v1::get_system_status()` - Version 1 API
//!
//! Future:
//! - Add `v2/mod.rs` for breaking changes
//! - Keep `v1` for old clients

// Allow unused - some exports for future use
#![allow(unused)]

pub mod commands;
pub mod engine_status;
pub mod enterprise;
pub mod advanced_detection;
pub mod cloud_sync;
pub mod v1;

// Re-export current version as default
pub use commands::*;

