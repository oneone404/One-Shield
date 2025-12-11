//! Process Intelligence Module - Deep Analysis cho Process Behaviors (Phase 2)
//!
//! Mục đích: Phân tích sâu process behaviors để phát hiện suspicious activity
//!
//! # Components
//! - `signature.rs`: Kiểm tra chữ ký số của ứng dụng
//! - `tree.rs`: Phân tích Parent-Child relationships
//! - `spawn.rs`: Phát hiện LOLBins và suspicious spawns
//! - `reputation.rs`: Điểm tin cậy dựa trên lịch sử behavior

// Allow unused for now - will be fully integrated in future phases
#![allow(unused)]

pub mod signature;
pub mod tree;
pub mod spawn;
pub mod reputation;
pub mod types;

// Re-exports - only public items
pub use types::{
    SignatureStatus, ProcessInfo, SpawnSeverity, ReputationEntry,
    ReputationFlags, ProcessTreeNode, TreeAnalysisResult, SuspiciousChain,
    SuspiciousSpawnAlert, is_publisher_trusted,
};
pub use signature::{verify_signature, SignatureResult, is_trusted_publisher, is_signed};
pub use tree::{get_process_tree, get_process_parent, get_process_info, refresh_tree};
pub use spawn::{check_suspicious_spawn, is_lolbin, get_lolbin_info};
pub use reputation::{get_reputation, update_reputation, ProcessReputation, is_trusted, is_untrusted};
