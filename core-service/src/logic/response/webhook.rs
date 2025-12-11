//! Webhook Alert Module (Phase 5)
//!
//! Mục đích: Gửi alerts đến Slack, Discord, Teams, Telegram
//!
//! Features:
//! - Multi-platform support
//! - Severity filtering
//! - Custom formatting per platform
//! - Persistent storage (JSON)

use std::collections::HashMap;
use std::path::PathBuf;
use std::fs;
use parking_lot::RwLock;
use once_cell::sync::Lazy;
use chrono::Utc;

use super::types::{WebhookConfig, WebhookPlatform, AlertPayload, AlertSeverity, ActionError};

// ============================================================================
// STORAGE
// ============================================================================

fn get_webhooks_path() -> PathBuf {
    let base = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ai-security");
    fs::create_dir_all(&base).ok();
    base.join("webhooks.json")
}

fn load_webhooks_from_disk() -> HashMap<String, WebhookConfig> {
    let path = get_webhooks_path();
    if !path.exists() {
        return HashMap::new();
    }

    match fs::read_to_string(&path) {
        Ok(content) => {
            match serde_json::from_str::<Vec<WebhookConfig>>(&content) {
                Ok(list) => {
                    let mut map = HashMap::new();
                    for w in list {
                        map.insert(w.id.clone(), w);
                    }
                    log::info!("Loaded {} webhooks from disk", map.len());
                    map
                }
                Err(e) => {
                    log::warn!("Failed to parse webhooks.json: {}", e);
                    HashMap::new()
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to read webhooks.json: {}", e);
            HashMap::new()
        }
    }
}

fn save_webhooks_to_disk(webhooks: &HashMap<String, WebhookConfig>) {
    let path = get_webhooks_path();
    let list: Vec<&WebhookConfig> = webhooks.values().collect();

    match serde_json::to_string_pretty(&list) {
        Ok(json) => {
            if let Err(e) = fs::write(&path, json) {
                log::error!("Failed to save webhooks: {}", e);
            } else {
                log::debug!("Saved {} webhooks to disk", webhooks.len());
            }
        }
        Err(e) => {
            log::error!("Failed to serialize webhooks: {}", e);
        }
    }
}

// ============================================================================
// STATE
// ============================================================================

static ALERT_MANAGER: Lazy<RwLock<AlertManager>> =
    Lazy::new(|| RwLock::new(AlertManager::new()));

// ============================================================================
// ALERT MANAGER
// ============================================================================

pub struct AlertManager {
    webhooks: HashMap<String, WebhookConfig>,
    alert_history: Vec<AlertHistoryEntry>,
    max_history: usize,
}

struct AlertHistoryEntry {
    payload: AlertPayload,
    webhook_id: String,
    success: bool,
    timestamp: i64,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            webhooks: load_webhooks_from_disk(),
            alert_history: Vec::new(),
            max_history: 100,
        }
    }

    /// Add a webhook
    pub fn add_webhook(&mut self, config: WebhookConfig) {
        self.webhooks.insert(config.id.clone(), config);
        save_webhooks_to_disk(&self.webhooks);
    }

    /// Remove a webhook
    pub fn remove_webhook(&mut self, id: &str) -> bool {
        let removed = self.webhooks.remove(id).is_some();
        if removed {
            save_webhooks_to_disk(&self.webhooks);
        }
        removed
    }

    /// Get a webhook
    pub fn get_webhook(&self, id: &str) -> Option<WebhookConfig> {
        self.webhooks.get(id).cloned()
    }

    /// Get all webhooks
    pub fn get_all_webhooks(&self) -> Vec<WebhookConfig> {
        self.webhooks.values().cloned().collect()
    }

    /// Send alert to all matching webhooks
    pub fn send_alert(&mut self, payload: &AlertPayload) -> Vec<Result<String, ActionError>> {
        let mut results = Vec::new();

        for webhook in self.webhooks.values() {
            if !webhook.enabled {
                continue;
            }

            // Check severity threshold
            if payload.severity < webhook.min_severity {
                continue;
            }

            let result = self.send_to_webhook(webhook, payload);

            // Record in history
            self.alert_history.push(AlertHistoryEntry {
                payload: payload.clone(),
                webhook_id: webhook.id.clone(),
                success: result.is_ok(),
                timestamp: Utc::now().timestamp(),
            });

            results.push(result);
        }

        // Trim history
        if self.alert_history.len() > self.max_history {
            self.alert_history.drain(0..self.alert_history.len() - self.max_history);
        }

        results
    }

    /// Send to a specific webhook
    fn send_to_webhook(&self, webhook: &WebhookConfig, payload: &AlertPayload)
        -> Result<String, ActionError>
    {
        let formatted = self.format_payload(webhook.platform, payload, webhook.include_details);

        let response = ureq::post(&webhook.url)
            .set("Content-Type", "application/json")
            .send_string(&formatted);

        match response {
            Ok(resp) => {
                log::info!("Alert sent to {} ({})", webhook.name, webhook.platform.as_str());
                Ok(format!("Sent to {} ({})", webhook.name, resp.status()))
            }
            Err(e) => {
                log::error!("Failed to send alert to {}: {}", webhook.name, e);
                Err(ActionError::NetworkError { message: e.to_string() })
            }
        }
    }

    /// Format payload for specific platform
    fn format_payload(&self, platform: WebhookPlatform, payload: &AlertPayload, details: bool) -> String {
        match platform {
            WebhookPlatform::Slack => self.format_slack(payload, details),
            WebhookPlatform::Discord => self.format_discord(payload, details),
            WebhookPlatform::MicrosoftTeams => self.format_teams(payload, details),
            WebhookPlatform::Telegram => self.format_telegram(payload, details),
            WebhookPlatform::Generic => self.format_generic(payload),
        }
    }

    /// Format for Slack
    fn format_slack(&self, payload: &AlertPayload, details: bool) -> String {
        let mut blocks = vec![
            serde_json::json!({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": format!("{} {}", payload.severity.emoji(), payload.title),
                    "emoji": true
                }
            }),
            serde_json::json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": payload.message
                }
            }),
        ];

        if details {
            let mut fields = vec![
                serde_json::json!({
                    "type": "mrkdwn",
                    "text": format!("*Severity:* {}", payload.severity.as_str())
                }),
            ];

            if let Some(ref hostname) = payload.hostname {
                fields.push(serde_json::json!({
                    "type": "mrkdwn",
                    "text": format!("*Host:* {}", hostname)
                }));
            }

            if let Some(ref process) = payload.process_name {
                fields.push(serde_json::json!({
                    "type": "mrkdwn",
                    "text": format!("*Process:* {} (PID: {})", process, payload.process_pid.unwrap_or(0))
                }));
            }

            if !payload.mitre_techniques.is_empty() {
                fields.push(serde_json::json!({
                    "type": "mrkdwn",
                    "text": format!("*MITRE:* {}", payload.mitre_techniques.join(", "))
                }));
            }

            blocks.push(serde_json::json!({
                "type": "section",
                "fields": fields
            }));
        }

        serde_json::json!({
            "blocks": blocks,
            "attachments": [{
                "color": payload.severity.color()
            }]
        }).to_string()
    }

    /// Format for Discord
    fn format_discord(&self, payload: &AlertPayload, details: bool) -> String {
        let mut fields = Vec::new();

        if details {
            fields.push(serde_json::json!({
                "name": "Severity",
                "value": payload.severity.as_str(),
                "inline": true
            }));

            if let Some(ref hostname) = payload.hostname {
                fields.push(serde_json::json!({
                    "name": "Host",
                    "value": hostname,
                    "inline": true
                }));
            }

            if let Some(ref process) = payload.process_name {
                fields.push(serde_json::json!({
                    "name": "Process",
                    "value": format!("{} ({})", process, payload.process_pid.unwrap_or(0)),
                    "inline": true
                }));
            }

            if !payload.mitre_techniques.is_empty() {
                fields.push(serde_json::json!({
                    "name": "MITRE ATT&CK",
                    "value": payload.mitre_techniques.join(", "),
                    "inline": false
                }));
            }
        }

        serde_json::json!({
            "embeds": [{
                "title": format!("{} {}", payload.severity.emoji(), payload.title),
                "description": payload.message,
                "color": u32::from_str_radix(&payload.severity.color()[1..], 16).unwrap_or(0),
                "fields": fields,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        }).to_string()
    }

    /// Format for Microsoft Teams
    fn format_teams(&self, payload: &AlertPayload, details: bool) -> String {
        let mut facts = vec![
            serde_json::json!({
                "name": "Severity",
                "value": payload.severity.as_str()
            }),
        ];

        if details {
            if let Some(ref hostname) = payload.hostname {
                facts.push(serde_json::json!({
                    "name": "Host",
                    "value": hostname
                }));
            }

            if let Some(ref process) = payload.process_name {
                facts.push(serde_json::json!({
                    "name": "Process",
                    "value": format!("{} ({})", process, payload.process_pid.unwrap_or(0))
                }));
            }

            if !payload.mitre_techniques.is_empty() {
                facts.push(serde_json::json!({
                    "name": "MITRE ATT&CK",
                    "value": payload.mitre_techniques.join(", ")
                }));
            }
        }

        serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": payload.severity.color().replace("#", ""),
            "summary": payload.title,
            "sections": [{
                "activityTitle": format!("{} {}", payload.severity.emoji(), payload.title),
                "text": payload.message,
                "facts": facts
            }]
        }).to_string()
    }

    /// Format for Telegram
    fn format_telegram(&self, payload: &AlertPayload, details: bool) -> String {
        let mut text = format!(
            "{} *{}*\n\n{}",
            payload.severity.emoji(),
            escape_markdown(&payload.title),
            escape_markdown(&payload.message)
        );

        if details {
            text.push_str(&format!("\n\n*Severity:* {}", payload.severity.as_str()));

            if let Some(ref hostname) = payload.hostname {
                text.push_str(&format!("\n*Host:* {}", hostname));
            }

            if let Some(ref process) = payload.process_name {
                text.push_str(&format!("\n*Process:* {} ({})", process, payload.process_pid.unwrap_or(0)));
            }

            if !payload.mitre_techniques.is_empty() {
                text.push_str(&format!("\n*MITRE:* {}", payload.mitre_techniques.join(", ")));
            }
        }

        serde_json::json!({
            "text": text,
            "parse_mode": "Markdown"
        }).to_string()
    }

    /// Format for generic webhook
    fn format_generic(&self, payload: &AlertPayload) -> String {
        serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string())
    }

    /// Test a webhook
    pub fn test_webhook(&self, id: &str) -> Result<String, ActionError> {
        let webhook = self.webhooks.get(id)
            .ok_or_else(|| ActionError::Other {
                message: format!("Webhook not found: {}", id),
            })?;

        let test_payload = AlertPayload::new(
            "[One-Shield] Test Alert",
            "This is a test alert from One-Shield EDR. Your webhook is configured correctly!",
            AlertSeverity::Info,
        );

        self.send_to_webhook(webhook, &test_payload)
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UTILITIES
// ============================================================================

fn escape_markdown(text: &str) -> String {
    text.replace("*", "\\*")
        .replace("_", "\\_")
        .replace("`", "\\`")
        .replace("[", "\\[")
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Add a webhook
pub fn add_webhook(config: WebhookConfig) {
    ALERT_MANAGER.write().add_webhook(config);
}

/// Remove a webhook (by id or name)
pub fn remove_webhook(id_or_name: &str) -> bool {
    let mut manager = ALERT_MANAGER.write();

    // Try to remove by ID first
    if manager.webhooks.remove(id_or_name).is_some() {
        save_webhooks_to_disk(&manager.webhooks);
        return true;
    }

    // Try to find by name and remove
    if let Some(id) = manager.webhooks.iter()
        .find(|(_, w)| w.name.eq_ignore_ascii_case(id_or_name))
        .map(|(id, _)| id.clone())
    {
        let removed = manager.webhooks.remove(&id).is_some();
        if removed {
            save_webhooks_to_disk(&manager.webhooks);
        }
        return removed;
    }

    false
}

/// Get all webhooks
pub fn get_webhooks() -> Vec<WebhookConfig> {
    ALERT_MANAGER.read().get_all_webhooks()
}

/// Get a webhook
pub fn get_webhook(id: &str) -> Option<WebhookConfig> {
    ALERT_MANAGER.read().get_webhook(id)
}

/// Send alert to all matching webhooks
pub fn send_alert(payload: &AlertPayload) -> Vec<Result<String, ActionError>> {
    ALERT_MANAGER.write().send_alert(payload)
}

/// Send alert to a specific webhook
pub fn send_alert_to(webhook_id: &str, payload: &AlertPayload) -> Result<String, ActionError> {
    let manager = ALERT_MANAGER.read();
    let webhook = manager.get_webhook(webhook_id)
        .ok_or_else(|| ActionError::Other {
            message: format!("Webhook not found: {}", webhook_id),
        })?;

    manager.send_to_webhook(&webhook, payload)
}

/// Test a webhook (by id or name)
pub fn test_webhook(id_or_name: &str) -> Result<String, ActionError> {
    let manager = ALERT_MANAGER.read();

    // Try to find by ID first, then by name
    let webhook = manager.webhooks.get(id_or_name)
        .or_else(|| manager.webhooks.values().find(|w| w.name.eq_ignore_ascii_case(id_or_name)))
        .ok_or_else(|| ActionError::Other {
            message: format!("Webhook not found: {}", id_or_name),
        })?;

    let test_payload = AlertPayload::new(
        "[One-Shield] Test Alert",
        "This is a test alert from One-Shield EDR. Your webhook is configured correctly!",
        AlertSeverity::Info,
    );

    manager.send_to_webhook(webhook, &test_payload)
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct WebhookStats {
    pub total_webhooks: usize,
    pub enabled_webhooks: usize,
    pub alerts_sent: usize,
    pub alerts_failed: usize,
}

pub fn get_stats() -> WebhookStats {
    let manager = ALERT_MANAGER.read();

    let (success, failed) = manager.alert_history.iter()
        .fold((0, 0), |(s, f), e| {
            if e.success { (s + 1, f) } else { (s, f + 1) }
        });

    WebhookStats {
        total_webhooks: manager.webhooks.len(),
        enabled_webhooks: manager.webhooks.values().filter(|w| w.enabled).count(),
        alerts_sent: success,
        alerts_failed: failed,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_slack() {
        let manager = AlertManager::new();
        let payload = AlertPayload::new("Test Alert", "This is a test", AlertSeverity::High);

        let formatted = manager.format_slack(&payload, true);
        assert!(formatted.contains("Test Alert"));
        assert!(formatted.contains("blocks"));
    }

    #[test]
    fn test_format_discord() {
        let manager = AlertManager::new();
        let payload = AlertPayload::new("Test Alert", "This is a test", AlertSeverity::Critical);

        let formatted = manager.format_discord(&payload, false);
        assert!(formatted.contains("embeds"));
    }
}
