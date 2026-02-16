//! `HyperV` Command Builder
//!
//! Builds `PowerShell` commands for Hyper-V virtual machine management via SSH.
//! Supports VM listing, info, start, stop, snapshots, host info, and virtual
//! switch operations.

use std::fmt::Write;

use crate::config::ShellType;
use crate::domain::use_cases::shell;
use crate::error::{BridgeError, Result};

/// Escape a string for safe interpolation into a `PowerShell` command.
fn ps_escape(s: &str) -> String {
    shell::escape(s, ShellType::PowerShell)
}

/// Validate a VM name to prevent injection attacks.
///
/// Rejects empty names and names containing shell metacharacters.
pub fn validate_vm_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::McpInvalidRequest(
            "VM name cannot be empty".to_string(),
        ));
    }
    if name.len() > 200 {
        return Err(BridgeError::McpInvalidRequest(
            "VM name is too long (max 200 characters)".to_string(),
        ));
    }
    if name.contains(';') || name.contains('|') || name.contains('`') || name.contains("$(") {
        return Err(BridgeError::McpInvalidRequest(format!(
            "VM name contains forbidden characters: {name}"
        )));
    }
    Ok(())
}

/// Validate a snapshot name to prevent injection attacks.
///
/// Rejects empty names and names containing shell metacharacters.
pub fn validate_snapshot_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::McpInvalidRequest(
            "Snapshot name cannot be empty".to_string(),
        ));
    }
    if name.len() > 200 {
        return Err(BridgeError::McpInvalidRequest(
            "Snapshot name is too long (max 200 characters)".to_string(),
        ));
    }
    if name.contains(';') || name.contains('|') || name.contains('`') || name.contains("$(") {
        return Err(BridgeError::McpInvalidRequest(format!(
            "Snapshot name contains forbidden characters: {name}"
        )));
    }
    Ok(())
}

/// Builds `PowerShell` commands for Hyper-V management.
pub struct HyperVCommandBuilder;

impl HyperVCommandBuilder {
    /// Build command to list all VMs with key properties.
    ///
    /// Constructs: `Get-VM | Select-Object Name,State,CPUUsage,MemoryAssigned,Uptime
    /// | ConvertTo-Json`
    #[must_use]
    pub fn vm_list() -> String {
        "Get-VM | Select-Object Name,State,CPUUsage,MemoryAssigned,Uptime \
         | ConvertTo-Json"
            .to_string()
    }

    /// Build command to get detailed VM info.
    ///
    /// Constructs: `Get-VM -Name '{name}' | Format-List *`
    #[must_use]
    pub fn vm_info(name: &str) -> String {
        format!("Get-VM -Name {} | Format-List *", ps_escape(name))
    }

    /// Build command to start a VM.
    ///
    /// Constructs: `Start-VM -Name '{name}'`
    #[must_use]
    pub fn vm_start(name: &str) -> String {
        format!("Start-VM -Name {}", ps_escape(name))
    }

    /// Build command to stop a VM.
    ///
    /// Constructs: `Stop-VM -Name '{name}' [-Force]`
    #[must_use]
    pub fn vm_stop(name: &str, force: bool) -> String {
        let mut cmd = format!("Stop-VM -Name {}", ps_escape(name));
        if force {
            cmd.push_str(" -Force");
        }
        cmd
    }

    /// Build command to list snapshots for a VM.
    ///
    /// Constructs: `Get-VMSnapshot -VMName '{vm_name}'`
    #[must_use]
    pub fn snapshot_list(vm_name: &str) -> String {
        format!("Get-VMSnapshot -VMName {}", ps_escape(vm_name))
    }

    /// Build command to create a snapshot for a VM.
    ///
    /// Constructs: `Checkpoint-VM -Name '{vm_name}' -SnapshotName '{snapshot_name}'`
    #[must_use]
    pub fn snapshot_create(vm_name: &str, snapshot_name: &str) -> String {
        let mut cmd = String::new();
        let _ = write!(
            cmd,
            "Checkpoint-VM -Name {} -SnapshotName {}",
            ps_escape(vm_name),
            ps_escape(snapshot_name),
        );
        cmd
    }

    /// Build command to get Hyper-V host information.
    ///
    /// Constructs: `Get-VMHost | Select-Object *`
    #[must_use]
    pub fn host_info() -> String {
        "Get-VMHost | Select-Object *".to_string()
    }

    /// Build command to list virtual switches.
    ///
    /// Constructs: `Get-VMSwitch | Select-Object
    /// Name,SwitchType,NetAdapterInterfaceDescription`
    #[must_use]
    pub fn switch_list() -> String {
        "Get-VMSwitch | Select-Object Name,SwitchType,NetAdapterInterfaceDescription".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── vm_list ─────────────────────────────────────────────────────

    #[test]
    fn test_vm_list() {
        let cmd = HyperVCommandBuilder::vm_list();
        assert!(cmd.contains("Get-VM"));
        assert!(cmd.contains("Select-Object Name,State,CPUUsage,MemoryAssigned,Uptime"));
        assert!(cmd.contains("ConvertTo-Json"));
    }

    // ── vm_info ─────────────────────────────────────────────────────

    #[test]
    fn test_vm_info() {
        let cmd = HyperVCommandBuilder::vm_info("TestVM");
        assert_eq!(cmd, "Get-VM -Name 'TestVM' | Format-List *");
    }

    #[test]
    fn test_vm_info_with_space() {
        let cmd = HyperVCommandBuilder::vm_info("My VM");
        assert!(cmd.contains("'My VM'"));
    }

    #[test]
    fn test_vm_info_injection() {
        let cmd = HyperVCommandBuilder::vm_info("vm; Remove-Item C:\\");
        assert!(cmd.contains("'vm; Remove-Item C:\\'"));
    }

    #[test]
    fn test_vm_info_single_quote_escape() {
        let cmd = HyperVCommandBuilder::vm_info("it's a vm");
        assert!(cmd.contains("'it''s a vm'"));
    }

    // ── vm_start ────────────────────────────────────────────────────

    #[test]
    fn test_vm_start() {
        let cmd = HyperVCommandBuilder::vm_start("TestVM");
        assert_eq!(cmd, "Start-VM -Name 'TestVM'");
    }

    #[test]
    fn test_vm_start_injection() {
        let cmd = HyperVCommandBuilder::vm_start("vm$(hostname)");
        assert!(cmd.contains("'vm$(hostname)'"));
    }

    // ── vm_stop ─────────────────────────────────────────────────────

    #[test]
    fn test_vm_stop_graceful() {
        let cmd = HyperVCommandBuilder::vm_stop("TestVM", false);
        assert_eq!(cmd, "Stop-VM -Name 'TestVM'");
        assert!(!cmd.contains("-Force"));
    }

    #[test]
    fn test_vm_stop_force() {
        let cmd = HyperVCommandBuilder::vm_stop("TestVM", true);
        assert_eq!(cmd, "Stop-VM -Name 'TestVM' -Force");
    }

    #[test]
    fn test_vm_stop_injection() {
        let cmd = HyperVCommandBuilder::vm_stop("vm|Out-File", true);
        assert!(cmd.contains("'vm|Out-File'"));
    }

    // ── snapshot_list ───────────────────────────────────────────────

    #[test]
    fn test_snapshot_list() {
        let cmd = HyperVCommandBuilder::snapshot_list("TestVM");
        assert_eq!(cmd, "Get-VMSnapshot -VMName 'TestVM'");
    }

    #[test]
    fn test_snapshot_list_injection() {
        let cmd = HyperVCommandBuilder::snapshot_list("vm; whoami");
        assert!(cmd.contains("'vm; whoami'"));
    }

    // ── snapshot_create ─────────────────────────────────────────────

    #[test]
    fn test_snapshot_create() {
        let cmd = HyperVCommandBuilder::snapshot_create("TestVM", "Before Update");
        assert_eq!(
            cmd,
            "Checkpoint-VM -Name 'TestVM' -SnapshotName 'Before Update'"
        );
    }

    #[test]
    fn test_snapshot_create_injection_in_vm_name() {
        let cmd = HyperVCommandBuilder::snapshot_create("vm; whoami", "snap");
        assert!(cmd.contains("'vm; whoami'"));
    }

    #[test]
    fn test_snapshot_create_injection_in_snapshot_name() {
        let cmd = HyperVCommandBuilder::snapshot_create("TestVM", "snap$(hostname)");
        assert!(cmd.contains("'snap$(hostname)'"));
    }

    #[test]
    fn test_snapshot_create_single_quote_in_names() {
        let cmd = HyperVCommandBuilder::snapshot_create("vm'test", "snap'shot");
        assert!(cmd.contains("'vm''test'"));
        assert!(cmd.contains("'snap''shot'"));
    }

    // ── host_info ───────────────────────────────────────────────────

    #[test]
    fn test_host_info() {
        let cmd = HyperVCommandBuilder::host_info();
        assert_eq!(cmd, "Get-VMHost | Select-Object *");
    }

    // ── switch_list ─────────────────────────────────────────────────

    #[test]
    fn test_switch_list() {
        let cmd = HyperVCommandBuilder::switch_list();
        assert!(cmd.contains("Get-VMSwitch"));
        assert!(cmd.contains("Name,SwitchType,NetAdapterInterfaceDescription"));
    }

    // ── Shell Injection Prevention ──────────────────────────────────

    #[test]
    fn test_dollar_variable_neutralized() {
        let cmd = HyperVCommandBuilder::vm_start("$env:COMPUTERNAME");
        assert!(cmd.contains("'$env:COMPUTERNAME'"));
    }

    #[test]
    fn test_backtick_neutralized() {
        let cmd = HyperVCommandBuilder::vm_stop("vm`n", false);
        assert!(cmd.contains("'vm`n'"));
    }

    #[test]
    fn test_pipe_neutralized() {
        let cmd = HyperVCommandBuilder::vm_info("vm|Out-File");
        assert!(cmd.contains("'vm|Out-File'"));
    }

    // ── validate_vm_name ─────────────────────────────────────────────

    #[test]
    fn test_validate_vm_name_valid() {
        assert!(validate_vm_name("TestVM").is_ok());
        assert!(validate_vm_name("My VM").is_ok());
        assert!(validate_vm_name("vm-01").is_ok());
    }

    #[test]
    fn test_validate_vm_name_empty() {
        assert!(validate_vm_name("").is_err());
    }

    #[test]
    fn test_validate_vm_name_injection() {
        assert!(validate_vm_name("vm; whoami").is_err());
        assert!(validate_vm_name("vm|Out-File").is_err());
        assert!(validate_vm_name("vm$(hostname)").is_err());
        assert!(validate_vm_name("vm`n").is_err());
    }

    #[test]
    fn test_validate_vm_name_too_long() {
        let long = "a".repeat(201);
        assert!(validate_vm_name(&long).is_err());
    }

    // ── validate_snapshot_name ───────────────────────────────────────

    #[test]
    fn test_validate_snapshot_name_valid() {
        assert!(validate_snapshot_name("Before Update").is_ok());
        assert!(validate_snapshot_name("snap-01").is_ok());
    }

    #[test]
    fn test_validate_snapshot_name_empty() {
        assert!(validate_snapshot_name("").is_err());
    }

    #[test]
    fn test_validate_snapshot_name_injection() {
        assert!(validate_snapshot_name("snap; whoami").is_err());
        assert!(validate_snapshot_name("snap|Out-File").is_err());
        assert!(validate_snapshot_name("snap$(hostname)").is_err());
    }
}
