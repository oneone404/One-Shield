//! External Intelligence Module - Threat Intelligence Integration (Phase 4)
//!
//! Mục đích: Kết nối với nguồn threat intelligence bên ngoài
//!
//! # Components
//! - `virustotal.rs`: VirusTotal API integration
//! - `threat_feed.rs`: Cloud threat feed sync (IPs, domains, hashes)
//! - `mitre.rs`: MITRE ATT&CK mapping and enrichment

// Allow unused for now - will be fully integrated in future phases
#![allow(unused)]

pub mod virustotal;
pub mod threat_feed;
pub mod mitre;
pub mod types;

// Re-exports from types
pub use types::{
    VTResult, VTStats, VTError,
    ThreatIndicator, IndicatorType, ThreatLevel,
    MitreTechnique, MitreTactic,
};

// Re-exports from submodules
pub use virustotal::{check_hash, check_file, get_cached_result, VTClient};
pub use threat_feed::{ThreatFeed, sync_feeds, is_malicious_ip, is_malicious_domain, is_malicious_hash};
pub use mitre::{get_technique, get_techniques_for_tag, enrich_with_mitre, MITRE_TECHNIQUES};
