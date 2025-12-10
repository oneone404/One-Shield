//! Threat Context
//!
//! Context information cho threat classification.
//! Chứa thông tin bổ sung ngoài AI score và baseline.

use serde::{Deserialize, Serialize};

// ============================================================================
// THREAT CONTEXT
// ============================================================================

/// Additional context for classification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatContext {
    /// Is this a new process (no baseline yet)?
    pub is_new_process: bool,
    /// Is this process whitelisted?
    pub is_whitelisted: bool,
    /// Number of child processes spawned
    pub child_process_count: u32,
    /// Network bytes sent in current window
    pub network_bytes_sent: u64,
    /// Network bytes received
    pub network_bytes_recv: u64,
    /// Tags from other detection modules
    pub tags: Vec<String>,
    /// Process name for logging
    pub process_name: Option<String>,
    /// Process ID
    pub pid: Option<u32>,
}

impl ThreatContext {
    /// Create new context with process info
    pub fn new(pid: u32, name: &str) -> Self {
        Self {
            pid: Some(pid),
            process_name: Some(name.to_string()),
            ..Default::default()
        }
    }

    /// Mark as new process
    pub fn with_new_process(mut self, is_new: bool) -> Self {
        self.is_new_process = is_new;
        self
    }

    /// Mark as whitelisted
    pub fn with_whitelisted(mut self, is_whitelisted: bool) -> Self {
        self.is_whitelisted = is_whitelisted;
        self
    }

    /// Add network stats
    pub fn with_network(mut self, sent: u64, recv: u64) -> Self {
        self.network_bytes_sent = sent;
        self.network_bytes_recv = recv;
        self
    }

    /// Add child process count
    pub fn with_children(mut self, count: u32) -> Self {
        self.child_process_count = count;
        self
    }

    /// Add detection tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Check if context has suspicious indicators
    pub fn has_suspicious_indicators(&self) -> bool {
        self.is_new_process
            || self.child_process_count > 5
            || self.tags.iter().any(|t| {
                t.contains("ANOMALY") || t.contains("BURST") || t.contains("CRYPTO")
            })
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder() {
        let ctx = ThreatContext::new(1234, "test.exe")
            .with_new_process(true)
            .with_network(1000, 2000)
            .with_children(3);

        assert_eq!(ctx.pid, Some(1234));
        assert_eq!(ctx.process_name, Some("test.exe".to_string()));
        assert!(ctx.is_new_process);
        assert_eq!(ctx.network_bytes_sent, 1000);
        assert_eq!(ctx.child_process_count, 3);
    }

    #[test]
    fn test_suspicious_indicators() {
        let normal = ThreatContext::default();
        assert!(!normal.has_suspicious_indicators());

        let suspicious = ThreatContext::default()
            .with_new_process(true);
        assert!(suspicious.has_suspicious_indicators());

        let many_children = ThreatContext::default()
            .with_children(10);
        assert!(many_children.has_suspicious_indicators());
    }
}
