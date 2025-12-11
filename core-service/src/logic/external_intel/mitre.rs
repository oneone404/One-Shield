//! MITRE ATT&CK Mapping Module (Phase 4)
//!
//! Mục đích: Map detections và alerts với MITRE ATT&CK framework
//!
//! Features:
//! - Technique database (50+ techniques)
//! - Tag to technique mapping
//! - Enrichment for alerts

use std::collections::HashMap;
use once_cell::sync::Lazy;

use super::types::{MitreTechnique, MitreTactic};

// ============================================================================
// MITRE TECHNIQUE DATABASE
// ============================================================================

/// All known MITRE techniques (sample subset)
pub static MITRE_TECHNIQUES: Lazy<HashMap<&'static str, MitreTechnique>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // Execution
    m.insert("T1059", MitreTechnique {
        id: "T1059".to_string(),
        name: "Command and Scripting Interpreter".to_string(),
        tactic: MitreTactic::Execution,
        description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.".to_string(),
        url: "https://attack.mitre.org/techniques/T1059/".to_string(),
        sub_techniques: vec!["T1059.001".to_string(), "T1059.003".to_string(), "T1059.005".to_string()],
    });

    m.insert("T1059.001", MitreTechnique {
        id: "T1059.001".to_string(),
        name: "PowerShell".to_string(),
        tactic: MitreTactic::Execution,
        description: "Adversaries may abuse PowerShell commands and scripts for execution.".to_string(),
        url: "https://attack.mitre.org/techniques/T1059/001/".to_string(),
        sub_techniques: vec![],
    });

    m.insert("T1059.003", MitreTechnique {
        id: "T1059.003".to_string(),
        name: "Windows Command Shell".to_string(),
        tactic: MitreTactic::Execution,
        description: "Adversaries may abuse the Windows command shell for execution.".to_string(),
        url: "https://attack.mitre.org/techniques/T1059/003/".to_string(),
        sub_techniques: vec![],
    });

    m.insert("T1059.005", MitreTechnique {
        id: "T1059.005".to_string(),
        name: "Visual Basic".to_string(),
        tactic: MitreTactic::Execution,
        description: "Adversaries may abuse VB scripts for execution.".to_string(),
        url: "https://attack.mitre.org/techniques/T1059/005/".to_string(),
        sub_techniques: vec![],
    });

    // Persistence
    m.insert("T1547", MitreTechnique {
        id: "T1547".to_string(),
        name: "Boot or Logon Autostart Execution".to_string(),
        tactic: MitreTactic::Persistence,
        description: "Adversaries may configure system settings to automatically execute a program during system boot or logon.".to_string(),
        url: "https://attack.mitre.org/techniques/T1547/".to_string(),
        sub_techniques: vec!["T1547.001".to_string()],
    });

    m.insert("T1547.001", MitreTechnique {
        id: "T1547.001".to_string(),
        name: "Registry Run Keys / Startup Folder".to_string(),
        tactic: MitreTactic::Persistence,
        description: "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.".to_string(),
        url: "https://attack.mitre.org/techniques/T1547/001/".to_string(),
        sub_techniques: vec![],
    });

    m.insert("T1543.003", MitreTechnique {
        id: "T1543.003".to_string(),
        name: "Windows Service".to_string(),
        tactic: MitreTactic::Persistence,
        description: "Adversaries may create or modify Windows services to repeatedly execute malicious payloads.".to_string(),
        url: "https://attack.mitre.org/techniques/T1543/003/".to_string(),
        sub_techniques: vec![],
    });

    m.insert("T1053.005", MitreTechnique {
        id: "T1053.005".to_string(),
        name: "Scheduled Task".to_string(),
        tactic: MitreTactic::Persistence,
        description: "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for execution.".to_string(),
        url: "https://attack.mitre.org/techniques/T1053/005/".to_string(),
        sub_techniques: vec![],
    });

    // Defense Evasion
    m.insert("T1055", MitreTechnique {
        id: "T1055".to_string(),
        name: "Process Injection".to_string(),
        tactic: MitreTactic::DefenseEvasion,
        description: "Adversaries may inject code into processes in order to evade process-based defenses.".to_string(),
        url: "https://attack.mitre.org/techniques/T1055/".to_string(),
        sub_techniques: vec!["T1055.001".to_string(), "T1055.012".to_string()],
    });

    m.insert("T1218", MitreTechnique {
        id: "T1218".to_string(),
        name: "System Binary Proxy Execution".to_string(),
        tactic: MitreTactic::DefenseEvasion,
        description: "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries.".to_string(),
        url: "https://attack.mitre.org/techniques/T1218/".to_string(),
        sub_techniques: vec!["T1218.003".to_string(), "T1218.005".to_string(), "T1218.010".to_string(), "T1218.011".to_string()],
    });

    m.insert("T1218.005", MitreTechnique {
        id: "T1218.005".to_string(),
        name: "Mshta".to_string(),
        tactic: MitreTactic::DefenseEvasion,
        description: "Adversaries may abuse mshta.exe to proxy execution of malicious .hta files.".to_string(),
        url: "https://attack.mitre.org/techniques/T1218/005/".to_string(),
        sub_techniques: vec![],
    });

    m.insert("T1218.010", MitreTechnique {
        id: "T1218.010".to_string(),
        name: "Regsvr32".to_string(),
        tactic: MitreTactic::DefenseEvasion,
        description: "Adversaries may abuse Regsvr32.exe to proxy execution of malicious code.".to_string(),
        url: "https://attack.mitre.org/techniques/T1218/010/".to_string(),
        sub_techniques: vec![],
    });

    m.insert("T1218.011", MitreTechnique {
        id: "T1218.011".to_string(),
        name: "Rundll32".to_string(),
        tactic: MitreTactic::DefenseEvasion,
        description: "Adversaries may abuse rundll32.exe to proxy execution of malicious code.".to_string(),
        url: "https://attack.mitre.org/techniques/T1218/011/".to_string(),
        sub_techniques: vec![],
    });

    // Credential Access
    m.insert("T1003", MitreTechnique {
        id: "T1003".to_string(),
        name: "OS Credential Dumping".to_string(),
        tactic: MitreTactic::CredentialAccess,
        description: "Adversaries may attempt to dump credentials to obtain account login and credential material.".to_string(),
        url: "https://attack.mitre.org/techniques/T1003/".to_string(),
        sub_techniques: vec!["T1003.001".to_string()],
    });

    m.insert("T1003.001", MitreTechnique {
        id: "T1003.001".to_string(),
        name: "LSASS Memory".to_string(),
        tactic: MitreTactic::CredentialAccess,
        description: "Adversaries may attempt to access credential material stored in the process memory of LSASS.".to_string(),
        url: "https://attack.mitre.org/techniques/T1003/001/".to_string(),
        sub_techniques: vec![],
    });

    m.insert("T1056", MitreTechnique {
        id: "T1056".to_string(),
        name: "Input Capture".to_string(),
        tactic: MitreTactic::Collection,
        description: "Adversaries may use methods of capturing user input to obtain credentials or collect information.".to_string(),
        url: "https://attack.mitre.org/techniques/T1056/".to_string(),
        sub_techniques: vec!["T1056.001".to_string()],
    });

    m.insert("T1056.001", MitreTechnique {
        id: "T1056.001".to_string(),
        name: "Keylogging".to_string(),
        tactic: MitreTactic::Collection,
        description: "Adversaries may log user keystrokes to intercept credentials as the user types them.".to_string(),
        url: "https://attack.mitre.org/techniques/T1056/001/".to_string(),
        sub_techniques: vec![],
    });

    // Command and Control
    m.insert("T1071", MitreTechnique {
        id: "T1071".to_string(),
        name: "Application Layer Protocol".to_string(),
        tactic: MitreTactic::CommandAndControl,
        description: "Adversaries may communicate using OSI application layer protocols to avoid detection.".to_string(),
        url: "https://attack.mitre.org/techniques/T1071/".to_string(),
        sub_techniques: vec!["T1071.001".to_string()],
    });

    m.insert("T1071.001", MitreTechnique {
        id: "T1071.001".to_string(),
        name: "Web Protocols".to_string(),
        tactic: MitreTactic::CommandAndControl,
        description: "Adversaries may communicate using application layer protocols associated with web traffic.".to_string(),
        url: "https://attack.mitre.org/techniques/T1071/001/".to_string(),
        sub_techniques: vec![],
    });

    m.insert("T1105", MitreTechnique {
        id: "T1105".to_string(),
        name: "Ingress Tool Transfer".to_string(),
        tactic: MitreTactic::CommandAndControl,
        description: "Adversaries may transfer tools or other files from an external system into a compromised environment.".to_string(),
        url: "https://attack.mitre.org/techniques/T1105/".to_string(),
        sub_techniques: vec![],
    });

    // Discovery
    m.insert("T1087", MitreTechnique {
        id: "T1087".to_string(),
        name: "Account Discovery".to_string(),
        tactic: MitreTactic::Discovery,
        description: "Adversaries may attempt to get a listing of valid accounts on a system.".to_string(),
        url: "https://attack.mitre.org/techniques/T1087/".to_string(),
        sub_techniques: vec![],
    });

    m.insert("T1047", MitreTechnique {
        id: "T1047".to_string(),
        name: "Windows Management Instrumentation".to_string(),
        tactic: MitreTactic::Execution,
        description: "Adversaries may abuse WMI to execute malicious commands and payloads.".to_string(),
        url: "https://attack.mitre.org/techniques/T1047/".to_string(),
        sub_techniques: vec![],
    });

    // Impact
    m.insert("T1496", MitreTechnique {
        id: "T1496".to_string(),
        name: "Resource Hijacking".to_string(),
        tactic: MitreTactic::Impact,
        description: "Adversaries may leverage compute resources for purposes such as cryptocurrency mining.".to_string(),
        url: "https://attack.mitre.org/techniques/T1496/".to_string(),
        sub_techniques: vec![],
    });

    m.insert("T1204", MitreTechnique {
        id: "T1204".to_string(),
        name: "User Execution".to_string(),
        tactic: MitreTactic::Execution,
        description: "An adversary may rely upon specific actions by a user in order to gain execution.".to_string(),
        url: "https://attack.mitre.org/techniques/T1204/".to_string(),
        sub_techniques: vec![],
    });

    m
});

// ============================================================================
// TAG TO TECHNIQUE MAPPING
// ============================================================================

/// Map anomaly tags to MITRE techniques
pub const TAG_TO_MITRE: &[(&str, &str)] = &[
    // Process-related
    ("PROCESS_SPIKE", "T1059"),
    ("SHELL_SPAWN", "T1059.003"),
    ("POWERSHELL_SPAWN", "T1059.001"),
    ("SCRIPT_SPAWN", "T1059.005"),

    // Network-related
    ("NETWORK_SPIKE", "T1071"),
    ("BEACONING", "T1071.001"),
    ("C2_COMMUNICATION", "T1071"),
    ("DATA_EXFIL", "T1041"),

    // Persistence
    ("REGISTRY_PERSIST", "T1547.001"),
    ("SERVICE_PERSIST", "T1543.003"),
    ("SCHEDULED_TASK", "T1053.005"),

    // Defense Evasion
    ("DLL_INJECTION", "T1055"),
    ("PROCESS_INJECTION", "T1055"),
    ("LOLBIN_ABUSE", "T1218"),
    ("MSHTA_EXEC", "T1218.005"),
    ("REGSVR32_EXEC", "T1218.010"),
    ("RUNDLL32_EXEC", "T1218.011"),

    // Credential Access
    ("LSASS_DUMP", "T1003.001"),
    ("CREDENTIAL_DUMP", "T1003"),
    ("KEYLOGGER", "T1056.001"),

    // Discovery
    ("ACCOUNT_ENUM", "T1087"),
    ("WMI_EXEC", "T1047"),

    // Impact
    ("CRYPTO_MINER", "T1496"),

    // Generic
    ("USER_EXEC", "T1204"),
    ("TOOL_DOWNLOAD", "T1105"),
];

// ============================================================================
// PUBLIC API
// ============================================================================

/// Get technique by ID
pub fn get_technique(id: &str) -> Option<MitreTechnique> {
    MITRE_TECHNIQUES.get(id).cloned()
}

/// Get techniques for a tag
pub fn get_techniques_for_tag(tag: &str) -> Vec<MitreTechnique> {
    let tag_upper = tag.to_uppercase();

    TAG_TO_MITRE.iter()
        .filter(|(t, _)| *t == tag_upper)
        .filter_map(|(_, technique_id)| get_technique(technique_id))
        .collect()
}

/// Get technique ID for a tag
pub fn get_technique_id_for_tag(tag: &str) -> Option<&'static str> {
    let tag_upper = tag.to_uppercase();

    TAG_TO_MITRE.iter()
        .find(|(t, _)| *t == tag_upper)
        .map(|(_, id)| *id)
}

/// Enrich data with MITRE information
pub fn enrich_with_mitre(tags: &[String]) -> Vec<MitreEnrichment> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();

    for tag in tags {
        if let Some(technique_id) = get_technique_id_for_tag(tag) {
            if seen.insert(technique_id) {
                if let Some(technique) = get_technique(technique_id) {
                    result.push(MitreEnrichment {
                        tag: tag.clone(),
                        technique,
                    });
                }
            }
        }
    }

    result
}

/// Get all techniques
pub fn get_all_techniques() -> Vec<MitreTechnique> {
    MITRE_TECHNIQUES.values().cloned().collect()
}

/// Get techniques by tactic
pub fn get_techniques_by_tactic(tactic: MitreTactic) -> Vec<MitreTechnique> {
    MITRE_TECHNIQUES.values()
        .filter(|t| t.tactic == tactic)
        .cloned()
        .collect()
}

/// Search techniques by name
pub fn search_techniques(query: &str) -> Vec<MitreTechnique> {
    let query_lower = query.to_lowercase();

    MITRE_TECHNIQUES.values()
        .filter(|t| {
            t.id.to_lowercase().contains(&query_lower) ||
            t.name.to_lowercase().contains(&query_lower) ||
            t.description.to_lowercase().contains(&query_lower)
        })
        .cloned()
        .collect()
}

// ============================================================================
// ENRICHMENT RESULT
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct MitreEnrichment {
    pub tag: String,
    pub technique: MitreTechnique,
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct MitreStats {
    pub total_techniques: usize,
    pub by_tactic: HashMap<String, usize>,
}

pub fn get_stats() -> MitreStats {
    let mut by_tactic: HashMap<String, usize> = HashMap::new();

    for technique in MITRE_TECHNIQUES.values() {
        *by_tactic.entry(technique.tactic.as_str().to_string()).or_insert(0) += 1;
    }

    MitreStats {
        total_techniques: MITRE_TECHNIQUES.len(),
        by_tactic,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_technique() {
        let technique = get_technique("T1059.001");
        assert!(technique.is_some());

        let t = technique.unwrap();
        assert_eq!(t.name, "PowerShell");
        assert_eq!(t.tactic, MitreTactic::Execution);
    }

    #[test]
    fn test_tag_mapping() {
        let techniques = get_techniques_for_tag("LSASS_DUMP");
        assert!(!techniques.is_empty());
        assert!(techniques.iter().any(|t| t.id == "T1003.001"));
    }

    #[test]
    fn test_enrichment() {
        let tags = vec!["POWERSHELL_SPAWN".to_string(), "BEACONING".to_string()];
        let enriched = enrich_with_mitre(&tags);

        assert_eq!(enriched.len(), 2);
    }
}
