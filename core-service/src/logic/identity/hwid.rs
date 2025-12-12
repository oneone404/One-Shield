//! Hardware ID (HWID) Generation
//!
//! Generates a unique, stable hardware fingerprint for the machine.
//! Uses multiple hardware identifiers to create a tamper-resistant ID.
//!
//! Enterprise standard: CrowdStrike, SentinelOne, Defender ATP approach

use sha2::{Sha256, Digest};
use std::process::Command;

/// Hardware ID components
#[derive(Debug, Clone)]
pub struct HardwareInfo {
    pub cpu_id: String,
    pub bios_serial: String,
    pub machine_sid: String,
    pub motherboard_serial: String,
    pub machine_guid: String,
}

impl HardwareInfo {
    /// Compute the final HWID hash
    pub fn compute_hwid(&self) -> String {
        let combined = format!(
            "{}|{}|{}|{}|{}",
            self.cpu_id,
            self.bios_serial,
            self.machine_sid,
            self.motherboard_serial,
            self.machine_guid
        );

        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}

/// Collect hardware information from the system
pub fn collect_hardware_info() -> HardwareInfo {
    HardwareInfo {
        cpu_id: get_cpu_id(),
        bios_serial: get_bios_serial(),
        machine_sid: get_machine_sid(),
        motherboard_serial: get_motherboard_serial(),
        machine_guid: get_machine_guid(),
    }
}

/// Generate the HWID for this machine
pub fn generate_hwid() -> String {
    let info = collect_hardware_info();
    let hwid = info.compute_hwid();

    log::info!("Generated HWID: {}...{}", &hwid[..8], &hwid[hwid.len()-8..]);
    log::debug!("HWID components: CPU={}, BIOS={}, SID={}",
        &info.cpu_id[..std::cmp::min(8, info.cpu_id.len())],
        &info.bios_serial[..std::cmp::min(8, info.bios_serial.len())],
        &info.machine_sid[..std::cmp::min(8, info.machine_sid.len())]
    );

    hwid
}

/// Get CPU ID via WMIC
fn get_cpu_id() -> String {
    run_wmic_query("cpu", "ProcessorId")
        .unwrap_or_else(|_| "UNKNOWN_CPU".to_string())
}

/// Get BIOS Serial Number
fn get_bios_serial() -> String {
    run_wmic_query("bios", "SerialNumber")
        .unwrap_or_else(|_| "UNKNOWN_BIOS".to_string())
}

/// Get Windows Machine SID
fn get_machine_sid() -> String {
    // Try to get computer SID from registry or WMIC
    run_powershell_command(
        "(Get-WmiObject Win32_ComputerSystem).Name + '_' + (Get-WmiObject Win32_OperatingSystem).SerialNumber"
    ).unwrap_or_else(|_| {
        // Fallback to computer name + install date
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "UNKNOWN".to_string());
        format!("SID_{}", hostname)
    })
}

/// Get Motherboard Serial Number
fn get_motherboard_serial() -> String {
    run_wmic_query("baseboard", "SerialNumber")
        .unwrap_or_else(|_| "UNKNOWN_MB".to_string())
}

/// Get Windows Machine GUID from registry
fn get_machine_guid() -> String {
    run_powershell_command(
        "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid).MachineGuid"
    ).unwrap_or_else(|_| "UNKNOWN_GUID".to_string())
}

/// Run a WMIC query and return the result
fn run_wmic_query(category: &str, field: &str) -> Result<String, String> {
    let output = Command::new("wmic")
        .args([category, "get", field])
        .output()
        .map_err(|e| format!("Failed to run wmic: {}", e))?;

    if !output.status.success() {
        return Err("WMIC command failed".to_string());
    }

    let result = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = result.lines().collect();

    // Skip header line, get the value
    if lines.len() >= 2 {
        let value = lines[1].trim();
        if !value.is_empty() {
            return Ok(value.to_string());
        }
    }

    Err("No value found".to_string())
}

/// Run a PowerShell command and return the result
fn run_powershell_command(cmd: &str) -> Result<String, String> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", cmd])
        .output()
        .map_err(|e| format!("Failed to run powershell: {}", e))?;

    if !output.status.success() {
        return Err("PowerShell command failed".to_string());
    }

    let result = String::from_utf8_lossy(&output.stdout);
    let trimmed = result.trim();

    if !trimmed.is_empty() {
        Ok(trimmed.to_string())
    } else {
        Err("Empty result".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hwid_generation() {
        let hwid1 = generate_hwid();
        let hwid2 = generate_hwid();

        // HWID should be consistent
        assert_eq!(hwid1, hwid2);

        // HWID should be 64 characters (SHA256 hex)
        assert_eq!(hwid1.len(), 64);
    }

    #[test]
    fn test_hardware_info() {
        let info = collect_hardware_info();

        // Should have some non-empty values
        assert!(!info.cpu_id.is_empty());
        assert!(!info.machine_guid.is_empty());
    }
}
