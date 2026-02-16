//! `ESXi` Command Builder
//!
//! Builds `VMware` `ESXi` CLI commands for remote execution via SSH.
//! Uses `vim-cmd` for VM management (power, snapshots, listing) and
//! `esxcli` for host information (system, storage, network).

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds `ESXi` CLI commands for remote execution.
pub struct EsxiCommandBuilder;

impl EsxiCommandBuilder {
    /// Build a `vim-cmd vmsvc/getallvms` command.
    ///
    /// Lists all VMs registered on the `ESXi` host.
    #[must_use]
    pub fn build_vm_list_command() -> String {
        "vim-cmd vmsvc/getallvms".to_string()
    }

    /// Build a `vim-cmd vmsvc/get.summary` command.
    ///
    /// Returns detailed summary of a specific VM by its ID.
    #[must_use]
    pub fn build_vm_info_command(vm_id: &str) -> String {
        let escaped_id = shell_escape(vm_id);
        format!("vim-cmd vmsvc/get.summary {escaped_id}")
    }

    /// Build a `vim-cmd vmsvc/power.*` command.
    ///
    /// Performs a power action on a VM. Action must be validated first
    /// via [`validate_power_action`](Self::validate_power_action).
    #[must_use]
    pub fn build_vm_power_command(vm_id: &str, action: &str) -> String {
        let escaped_id = shell_escape(vm_id);
        format!("vim-cmd vmsvc/power.{action} {escaped_id}")
    }

    /// Build a `vim-cmd vmsvc/snapshot.*` command.
    ///
    /// Performs a snapshot action on a VM. Action must be validated first
    /// via [`validate_snapshot_action`](Self::validate_snapshot_action).
    ///
    /// - `list`: `vim-cmd vmsvc/snapshot.get {vm_id}`
    /// - `create`: `vim-cmd vmsvc/snapshot.create {vm_id} {name} {desc} {memory} {quiesce}`
    /// - `revert`: `vim-cmd vmsvc/snapshot.revert {vm_id} {snapshot_id}`
    /// - `remove_all`: `vim-cmd vmsvc/snapshot.removeall {vm_id}`
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build_snapshot_command(
        vm_id: &str,
        action: &str,
        name: Option<&str>,
        description: Option<&str>,
        include_memory: bool,
        quiesce: bool,
        snapshot_id: Option<&str>,
    ) -> String {
        let escaped_id = shell_escape(vm_id);

        match action {
            "create" => {
                let snap_name = shell_escape(name.unwrap_or("snapshot"));
                let snap_desc = shell_escape(description.unwrap_or(""));
                let memory = if include_memory { "1" } else { "0" };
                let quiesce_flag = if quiesce { "1" } else { "0" };
                format!(
                    "vim-cmd vmsvc/snapshot.create {escaped_id} {snap_name} {snap_desc} {memory} {quiesce_flag}"
                )
            }
            "revert" => {
                let snap_id = shell_escape(snapshot_id.unwrap_or("0"));
                format!("vim-cmd vmsvc/snapshot.revert {escaped_id} {snap_id}")
            }
            "remove_all" => format!("vim-cmd vmsvc/snapshot.removeall {escaped_id}"),
            // "list" and any other action default to snapshot.get
            _ => format!("vim-cmd vmsvc/snapshot.get {escaped_id}"),
        }
    }

    /// Build an `ESXi` host information command.
    ///
    /// Subsystem options:
    /// - `hostname`: `esxcli system hostname get`
    /// - `memory`: `esxcli hardware memory get`
    /// - `cpu`: `esxcli hardware cpu global get`
    /// - `version`: `esxcli system version get`
    /// - `maintenance`: `vim-cmd hostsvc/maintenance_mode_get`
    /// - `all` (default): all of the above combined
    #[must_use]
    pub fn build_host_info_command(subsystem: Option<&str>) -> String {
        match subsystem.unwrap_or("all") {
            "hostname" => "esxcli system hostname get".to_string(),
            "memory" => "esxcli hardware memory get".to_string(),
            "cpu" => "esxcli hardware cpu global get".to_string(),
            "version" => "esxcli system version get".to_string(),
            "maintenance" => "vim-cmd hostsvc/maintenance_mode_get".to_string(),
            _ => {
                // "all" or any default
                let mut cmd = String::new();
                cmd.push_str("echo '=== Hostname ===' && esxcli system hostname get");
                cmd.push_str(" && echo '=== Version ===' && esxcli system version get");
                cmd.push_str(" && echo '=== Memory ===' && esxcli hardware memory get");
                cmd.push_str(" && echo '=== CPU ===' && esxcli hardware cpu global get");
                cmd.push_str(
                    " && echo '=== Maintenance Mode ===' && vim-cmd hostsvc/maintenance_mode_get",
                );
                cmd
            }
        }
    }

    /// Build an `esxcli storage filesystem list` command.
    ///
    /// Lists all datastores/filesystems on the `ESXi` host.
    #[must_use]
    pub fn build_datastore_list_command() -> String {
        "esxcli storage filesystem list".to_string()
    }

    /// Build an `ESXi` network information command.
    ///
    /// Component options:
    /// - `interface`: `esxcli network ip interface list`
    /// - `vswitch`: `esxcli network vswitch standard list`
    /// - `nic`: `esxcli network nic list`
    /// - `all` (default): all of the above combined
    #[must_use]
    pub fn build_network_list_command(component: Option<&str>) -> String {
        match component.unwrap_or("all") {
            "interface" => "esxcli network ip interface list".to_string(),
            "vswitch" => "esxcli network vswitch standard list".to_string(),
            "nic" => "esxcli network nic list".to_string(),
            _ => {
                // "all" or any default
                let mut cmd = String::new();
                cmd.push_str("echo '=== Interfaces ===' && esxcli network ip interface list");
                cmd.push_str(
                    " && echo '=== vSwitches ===' && esxcli network vswitch standard list",
                );
                cmd.push_str(" && echo '=== NICs ===' && esxcli network nic list");
                cmd
            }
        }
    }

    /// Validate a VM power action.
    ///
    /// Only allows: `on`, `off`, `reset`, `shutdown`, `suspend`, `getstate`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the action is not allowed.
    pub fn validate_power_action(action: &str) -> Result<()> {
        const ALLOWED: &[&str] = &["on", "off", "reset", "shutdown", "suspend", "getstate"];
        if ALLOWED.contains(&action) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Power action '{}' is not allowed. Allowed actions: {}",
                    action,
                    ALLOWED.join(", ")
                ),
            })
        }
    }

    /// Validate a snapshot action.
    ///
    /// Only allows: `list`, `create`, `revert`, `remove_all`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the action is not allowed.
    pub fn validate_snapshot_action(action: &str) -> Result<()> {
        const ALLOWED: &[&str] = &["list", "create", "revert", "remove_all"];
        if ALLOWED.contains(&action) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Snapshot action '{}' is not allowed. Allowed actions: {}",
                    action,
                    ALLOWED.join(", ")
                ),
            })
        }
    }

    /// Validate a host info subsystem.
    ///
    /// Only allows: `hostname`, `memory`, `cpu`, `version`, `maintenance`, `all`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the subsystem is not allowed.
    pub fn validate_host_subsystem(subsystem: &str) -> Result<()> {
        const ALLOWED: &[&str] = &["hostname", "memory", "cpu", "version", "maintenance", "all"];
        if ALLOWED.contains(&subsystem) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Host subsystem '{}' is not allowed. Allowed subsystems: {}",
                    subsystem,
                    ALLOWED.join(", ")
                ),
            })
        }
    }

    /// Validate a network component.
    ///
    /// Only allows: `interface`, `vswitch`, `nic`, `all`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the component is not allowed.
    pub fn validate_network_component(component: &str) -> Result<()> {
        const ALLOWED: &[&str] = &["interface", "vswitch", "nic", "all"];
        if ALLOWED.contains(&component) {
            Ok(())
        } else {
            Err(BridgeError::CommandDenied {
                reason: format!(
                    "Network component '{}' is not allowed. Allowed components: {}",
                    component,
                    ALLOWED.join(", ")
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_vm_list_command ────────────────────────────────────────

    #[test]
    fn test_vm_list() {
        let cmd = EsxiCommandBuilder::build_vm_list_command();
        assert_eq!(cmd, "vim-cmd vmsvc/getallvms");
    }

    // ── build_vm_info_command ───────────────────────────────────────

    #[test]
    fn test_vm_info() {
        let cmd = EsxiCommandBuilder::build_vm_info_command("42");
        assert_eq!(cmd, "vim-cmd vmsvc/get.summary '42'");
    }

    #[test]
    fn test_vm_info_shell_escape() {
        let cmd = EsxiCommandBuilder::build_vm_info_command("1; rm -rf /");
        assert!(cmd.contains("'1; rm -rf /'"));
    }

    // ── build_vm_power_command ──────────────────────────────────────

    #[test]
    fn test_vm_power_on() {
        let cmd = EsxiCommandBuilder::build_vm_power_command("1", "on");
        assert_eq!(cmd, "vim-cmd vmsvc/power.on '1'");
    }

    #[test]
    fn test_vm_power_off() {
        let cmd = EsxiCommandBuilder::build_vm_power_command("1", "off");
        assert_eq!(cmd, "vim-cmd vmsvc/power.off '1'");
    }

    #[test]
    fn test_vm_power_reset() {
        let cmd = EsxiCommandBuilder::build_vm_power_command("42", "reset");
        assert_eq!(cmd, "vim-cmd vmsvc/power.reset '42'");
    }

    #[test]
    fn test_vm_power_shutdown() {
        let cmd = EsxiCommandBuilder::build_vm_power_command("10", "shutdown");
        assert_eq!(cmd, "vim-cmd vmsvc/power.shutdown '10'");
    }

    #[test]
    fn test_vm_power_suspend() {
        let cmd = EsxiCommandBuilder::build_vm_power_command("5", "suspend");
        assert_eq!(cmd, "vim-cmd vmsvc/power.suspend '5'");
    }

    #[test]
    fn test_vm_power_getstate() {
        let cmd = EsxiCommandBuilder::build_vm_power_command("3", "getstate");
        assert_eq!(cmd, "vim-cmd vmsvc/power.getstate '3'");
    }

    #[test]
    fn test_vm_power_shell_escape() {
        let cmd = EsxiCommandBuilder::build_vm_power_command("1; echo pwned", "on");
        assert!(cmd.contains("'1; echo pwned'"));
    }

    // ── build_snapshot_command ──────────────────────────────────────

    #[test]
    fn test_snapshot_list() {
        let cmd = EsxiCommandBuilder::build_snapshot_command(
            "42", "list", None, None, false, false, None,
        );
        assert_eq!(cmd, "vim-cmd vmsvc/snapshot.get '42'");
    }

    #[test]
    fn test_snapshot_create_minimal() {
        let cmd = EsxiCommandBuilder::build_snapshot_command(
            "42", "create", None, None, false, false, None,
        );
        assert!(cmd.contains("vim-cmd vmsvc/snapshot.create '42'"));
        assert!(cmd.contains("'snapshot'"));
    }

    #[test]
    fn test_snapshot_create_full() {
        let cmd = EsxiCommandBuilder::build_snapshot_command(
            "42",
            "create",
            Some("before-upgrade"),
            Some("Pre-upgrade snapshot"),
            true,
            true,
            None,
        );
        assert!(cmd.contains("vim-cmd vmsvc/snapshot.create '42'"));
        assert!(cmd.contains("'before-upgrade'"));
        assert!(cmd.contains("'Pre-upgrade snapshot'"));
        assert!(cmd.contains(" 1 1"));
    }

    #[test]
    fn test_snapshot_create_no_memory_no_quiesce() {
        let cmd = EsxiCommandBuilder::build_snapshot_command(
            "1",
            "create",
            Some("snap1"),
            Some("test"),
            false,
            false,
            None,
        );
        assert!(cmd.contains(" 0 0"));
    }

    #[test]
    fn test_snapshot_revert() {
        let cmd = EsxiCommandBuilder::build_snapshot_command(
            "42",
            "revert",
            None,
            None,
            false,
            false,
            Some("12345"),
        );
        assert_eq!(cmd, "vim-cmd vmsvc/snapshot.revert '42' '12345'");
    }

    #[test]
    fn test_snapshot_revert_default_id() {
        let cmd = EsxiCommandBuilder::build_snapshot_command(
            "42", "revert", None, None, false, false, None,
        );
        assert!(cmd.contains("'0'"));
    }

    #[test]
    fn test_snapshot_remove_all() {
        let cmd = EsxiCommandBuilder::build_snapshot_command(
            "42",
            "remove_all",
            None,
            None,
            false,
            false,
            None,
        );
        assert_eq!(cmd, "vim-cmd vmsvc/snapshot.removeall '42'");
    }

    #[test]
    fn test_snapshot_shell_escape() {
        let cmd = EsxiCommandBuilder::build_snapshot_command(
            "1; rm -rf /",
            "create",
            Some("snap'; echo pwned"),
            None,
            false,
            false,
            None,
        );
        assert!(cmd.contains("'1; rm -rf /'"));
        assert!(cmd.contains("'snap'\\''; echo pwned'"));
    }

    // ── build_host_info_command ─────────────────────────────────────

    #[test]
    fn test_host_info_hostname() {
        let cmd = EsxiCommandBuilder::build_host_info_command(Some("hostname"));
        assert_eq!(cmd, "esxcli system hostname get");
    }

    #[test]
    fn test_host_info_memory() {
        let cmd = EsxiCommandBuilder::build_host_info_command(Some("memory"));
        assert_eq!(cmd, "esxcli hardware memory get");
    }

    #[test]
    fn test_host_info_cpu() {
        let cmd = EsxiCommandBuilder::build_host_info_command(Some("cpu"));
        assert_eq!(cmd, "esxcli hardware cpu global get");
    }

    #[test]
    fn test_host_info_version() {
        let cmd = EsxiCommandBuilder::build_host_info_command(Some("version"));
        assert_eq!(cmd, "esxcli system version get");
    }

    #[test]
    fn test_host_info_maintenance() {
        let cmd = EsxiCommandBuilder::build_host_info_command(Some("maintenance"));
        assert_eq!(cmd, "vim-cmd hostsvc/maintenance_mode_get");
    }

    #[test]
    fn test_host_info_all_explicit() {
        let cmd = EsxiCommandBuilder::build_host_info_command(Some("all"));
        assert!(cmd.contains("esxcli system hostname get"));
        assert!(cmd.contains("esxcli system version get"));
        assert!(cmd.contains("esxcli hardware memory get"));
        assert!(cmd.contains("esxcli hardware cpu global get"));
        assert!(cmd.contains("vim-cmd hostsvc/maintenance_mode_get"));
    }

    #[test]
    fn test_host_info_all_default() {
        let cmd = EsxiCommandBuilder::build_host_info_command(None);
        assert!(cmd.contains("esxcli system hostname get"));
        assert!(cmd.contains("esxcli system version get"));
        assert!(cmd.contains("esxcli hardware memory get"));
        assert!(cmd.contains("esxcli hardware cpu global get"));
        assert!(cmd.contains("vim-cmd hostsvc/maintenance_mode_get"));
    }

    // ── build_datastore_list_command ────────────────────────────────

    #[test]
    fn test_datastore_list() {
        let cmd = EsxiCommandBuilder::build_datastore_list_command();
        assert_eq!(cmd, "esxcli storage filesystem list");
    }

    // ── build_network_list_command ──────────────────────────────────

    #[test]
    fn test_network_interface() {
        let cmd = EsxiCommandBuilder::build_network_list_command(Some("interface"));
        assert_eq!(cmd, "esxcli network ip interface list");
    }

    #[test]
    fn test_network_vswitch() {
        let cmd = EsxiCommandBuilder::build_network_list_command(Some("vswitch"));
        assert_eq!(cmd, "esxcli network vswitch standard list");
    }

    #[test]
    fn test_network_nic() {
        let cmd = EsxiCommandBuilder::build_network_list_command(Some("nic"));
        assert_eq!(cmd, "esxcli network nic list");
    }

    #[test]
    fn test_network_all_explicit() {
        let cmd = EsxiCommandBuilder::build_network_list_command(Some("all"));
        assert!(cmd.contains("esxcli network ip interface list"));
        assert!(cmd.contains("esxcli network vswitch standard list"));
        assert!(cmd.contains("esxcli network nic list"));
    }

    #[test]
    fn test_network_all_default() {
        let cmd = EsxiCommandBuilder::build_network_list_command(None);
        assert!(cmd.contains("esxcli network ip interface list"));
        assert!(cmd.contains("esxcli network vswitch standard list"));
        assert!(cmd.contains("esxcli network nic list"));
    }

    // ── validate_power_action ───────────────────────────────────────

    #[test]
    fn test_validate_power_action_allowed() {
        for action in &["on", "off", "reset", "shutdown", "suspend", "getstate"] {
            assert!(
                EsxiCommandBuilder::validate_power_action(action).is_ok(),
                "Action '{action}' should be allowed"
            );
        }
    }

    #[test]
    fn test_validate_power_action_denied() {
        for action in &["destroy", "reboot", "kill", "invalid", ""] {
            let result = EsxiCommandBuilder::validate_power_action(action);
            assert!(result.is_err(), "Action '{action}' should be denied");
            match result.unwrap_err() {
                BridgeError::CommandDenied { reason } => {
                    assert!(reason.contains(action));
                }
                e => panic!("Expected CommandDenied, got: {e:?}"),
            }
        }
    }

    #[test]
    fn test_validate_power_action_case_sensitive() {
        assert!(EsxiCommandBuilder::validate_power_action("On").is_err());
        assert!(EsxiCommandBuilder::validate_power_action("OFF").is_err());
    }

    // ── validate_snapshot_action ────────────────────────────────────

    #[test]
    fn test_validate_snapshot_action_allowed() {
        for action in &["list", "create", "revert", "remove_all"] {
            assert!(
                EsxiCommandBuilder::validate_snapshot_action(action).is_ok(),
                "Action '{action}' should be allowed"
            );
        }
    }

    #[test]
    fn test_validate_snapshot_action_denied() {
        for action in &["delete", "remove", "invalid", ""] {
            let result = EsxiCommandBuilder::validate_snapshot_action(action);
            assert!(result.is_err(), "Action '{action}' should be denied");
            match result.unwrap_err() {
                BridgeError::CommandDenied { reason } => {
                    assert!(reason.contains(action));
                }
                e => panic!("Expected CommandDenied, got: {e:?}"),
            }
        }
    }

    #[test]
    fn test_validate_snapshot_action_case_sensitive() {
        assert!(EsxiCommandBuilder::validate_snapshot_action("List").is_err());
        assert!(EsxiCommandBuilder::validate_snapshot_action("CREATE").is_err());
    }

    // ── validate_host_subsystem ─────────────────────────────────────

    #[test]
    fn test_validate_host_subsystem_allowed() {
        for sub in &["hostname", "memory", "cpu", "version", "maintenance", "all"] {
            assert!(
                EsxiCommandBuilder::validate_host_subsystem(sub).is_ok(),
                "Subsystem '{sub}' should be allowed"
            );
        }
    }

    #[test]
    fn test_validate_host_subsystem_denied() {
        for sub in &["disk", "network", "invalid", ""] {
            let result = EsxiCommandBuilder::validate_host_subsystem(sub);
            assert!(result.is_err(), "Subsystem '{sub}' should be denied");
            match result.unwrap_err() {
                BridgeError::CommandDenied { reason } => {
                    assert!(reason.contains(sub));
                }
                e => panic!("Expected CommandDenied, got: {e:?}"),
            }
        }
    }

    // ── validate_network_component ──────────────────────────────────

    #[test]
    fn test_validate_network_component_allowed() {
        for comp in &["interface", "vswitch", "nic", "all"] {
            assert!(
                EsxiCommandBuilder::validate_network_component(comp).is_ok(),
                "Component '{comp}' should be allowed"
            );
        }
    }

    #[test]
    fn test_validate_network_component_denied() {
        for comp in &["firewall", "dns", "invalid", ""] {
            let result = EsxiCommandBuilder::validate_network_component(comp);
            assert!(result.is_err(), "Component '{comp}' should be denied");
            match result.unwrap_err() {
                BridgeError::CommandDenied { reason } => {
                    assert!(reason.contains(comp));
                }
                e => panic!("Expected CommandDenied, got: {e:?}"),
            }
        }
    }

    #[test]
    fn test_validate_network_component_case_sensitive() {
        assert!(EsxiCommandBuilder::validate_network_component("NIC").is_err());
        assert!(EsxiCommandBuilder::validate_network_component("All").is_err());
    }
}
