//! Host Discovery & Inventory Command Builder
//!
//! Builds network discovery, host inventory sync, and tag management
//! commands for remote execution via SSH.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds host discovery and inventory commands for remote execution.
pub struct InventoryCommandBuilder;

impl InventoryCommandBuilder {
    /// Validate a network address/CIDR notation.
    ///
    /// # Errors
    ///
    /// Returns `CommandDenied` if the network string contains invalid characters.
    pub fn validate_network(network: &str) -> Result<()> {
        if network.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Network address cannot be empty".to_string(),
            });
        }
        // Allow IP addresses, CIDR notation, and hostnames
        if !network
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | ':' | '-'))
        {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid network address '{network}': \
                     only alphanumeric, dots, slashes, colons, and hyphens allowed"
                ),
            });
        }
        Ok(())
    }

    /// Validate a tag action.
    ///
    /// # Errors
    ///
    /// Returns `CommandDenied` if the action is not one of: list, add, remove.
    pub fn validate_tag_action(action: &str) -> Result<()> {
        match action {
            "list" | "add" | "remove" => Ok(()),
            _ => Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid tag action '{action}': must be one of: list, add, remove"
                ),
            }),
        }
    }

    /// Build a host discovery command for scanning a network.
    ///
    /// Uses nmap, arp-scan, or ip neigh as fallbacks.
    #[must_use]
    pub fn build_discover_hosts_command(network: &str, method: Option<&str>) -> String {
        let escaped_net = shell_escape(network);
        match method {
            Some("nmap") => format!("nmap -sn {escaped_net} 2>&1"),
            Some("arp") => format!("arp-scan {escaped_net} 2>&1"),
            Some("ip") => "ip neigh show 2>&1".to_string(),
            _ => {
                // Auto-detect: try nmap, then arp-scan, then ip neigh
                format!(
                    "nmap -sn {escaped_net} 2>/dev/null \
                     || arp-scan {escaped_net} 2>/dev/null \
                     || ip neigh show"
                )
            }
        }
    }

    /// Build a host inventory sync command.
    ///
    /// Gathers hostname, OS info, uptime, and IP addresses.
    #[must_use]
    pub fn build_inventory_sync_command() -> String {
        "hostname && cat /etc/os-release 2>/dev/null \
         && uptime && ip -4 addr show 2>/dev/null | grep inet"
            .to_string()
    }

    /// Build a host tags management command.
    ///
    /// Supports list, add, and remove actions using a local tags file.
    #[must_use]
    pub fn build_host_tags_command(action: &str, tags: Option<&str>) -> String {
        let tags_file = "/etc/host-tags";
        match action {
            "list" => format!("cat {tags_file} 2>/dev/null || echo 'No tags file found'"),
            "add" => {
                if let Some(t) = tags {
                    format!(
                        "echo {} >> {tags_file} && echo 'Tags added' && cat {tags_file}",
                        shell_escape(t)
                    )
                } else {
                    format!("cat {tags_file} 2>/dev/null || echo 'No tags file found'")
                }
            }
            "remove" => {
                if let Some(t) = tags {
                    format!(
                        "grep -v {} {tags_file} > {tags_file}.tmp \
                         && mv {tags_file}.tmp {tags_file} \
                         && echo 'Tags removed' && cat {tags_file}",
                        shell_escape(t)
                    )
                } else {
                    format!("cat {tags_file} 2>/dev/null || echo 'No tags file found'")
                }
            }
            _ => format!("cat {tags_file} 2>/dev/null || echo 'No tags file found'"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_network ──

    #[test]
    fn test_validate_network_valid() {
        assert!(InventoryCommandBuilder::validate_network("192.168.1.0/24").is_ok());
        assert!(InventoryCommandBuilder::validate_network("10.0.0.0/8").is_ok());
        assert!(InventoryCommandBuilder::validate_network("172.16.0.0/12").is_ok());
    }

    #[test]
    fn test_validate_network_empty() {
        assert!(InventoryCommandBuilder::validate_network("").is_err());
    }

    #[test]
    fn test_validate_network_injection() {
        assert!(InventoryCommandBuilder::validate_network("10.0.0.0; rm -rf /").is_err());
        assert!(InventoryCommandBuilder::validate_network("10.0.0.0 | cat").is_err());
        assert!(InventoryCommandBuilder::validate_network("$(whoami)").is_err());
    }

    // ── validate_tag_action ──

    #[test]
    fn test_validate_tag_action_valid() {
        assert!(InventoryCommandBuilder::validate_tag_action("list").is_ok());
        assert!(InventoryCommandBuilder::validate_tag_action("add").is_ok());
        assert!(InventoryCommandBuilder::validate_tag_action("remove").is_ok());
    }

    #[test]
    fn test_validate_tag_action_invalid() {
        assert!(InventoryCommandBuilder::validate_tag_action("delete").is_err());
        assert!(InventoryCommandBuilder::validate_tag_action("").is_err());
        assert!(InventoryCommandBuilder::validate_tag_action("update").is_err());
    }

    // ── build_discover_hosts_command ──

    #[test]
    fn test_discover_hosts_default() {
        let cmd = InventoryCommandBuilder::build_discover_hosts_command("192.168.1.0/24", None);
        assert!(cmd.contains("nmap -sn"));
        assert!(cmd.contains("arp-scan"));
        assert!(cmd.contains("ip neigh"));
    }

    #[test]
    fn test_discover_hosts_nmap() {
        let cmd =
            InventoryCommandBuilder::build_discover_hosts_command("10.0.0.0/24", Some("nmap"));
        assert!(cmd.contains("nmap -sn"));
        assert!(!cmd.contains("arp-scan"));
    }

    #[test]
    fn test_discover_hosts_arp() {
        let cmd =
            InventoryCommandBuilder::build_discover_hosts_command("10.0.0.0/24", Some("arp"));
        assert!(cmd.contains("arp-scan"));
        assert!(!cmd.contains("nmap"));
    }

    #[test]
    fn test_discover_hosts_ip() {
        let cmd =
            InventoryCommandBuilder::build_discover_hosts_command("10.0.0.0/24", Some("ip"));
        assert!(cmd.contains("ip neigh show"));
    }

    // ── build_inventory_sync_command ──

    #[test]
    fn test_inventory_sync() {
        let cmd = InventoryCommandBuilder::build_inventory_sync_command();
        assert!(cmd.contains("hostname"));
        assert!(cmd.contains("/etc/os-release"));
        assert!(cmd.contains("uptime"));
        assert!(cmd.contains("ip -4 addr"));
    }

    // ── build_host_tags_command ──

    #[test]
    fn test_host_tags_list() {
        let cmd = InventoryCommandBuilder::build_host_tags_command("list", None);
        assert!(cmd.contains("cat /etc/host-tags"));
    }

    #[test]
    fn test_host_tags_add() {
        let cmd = InventoryCommandBuilder::build_host_tags_command("add", Some("web,production"));
        assert!(cmd.contains("echo"));
        assert!(cmd.contains(">> /etc/host-tags"));
        assert!(cmd.contains("Tags added"));
    }

    #[test]
    fn test_host_tags_add_no_tags() {
        let cmd = InventoryCommandBuilder::build_host_tags_command("add", None);
        assert!(cmd.contains("cat /etc/host-tags"));
    }

    #[test]
    fn test_host_tags_remove() {
        let cmd =
            InventoryCommandBuilder::build_host_tags_command("remove", Some("deprecated"));
        assert!(cmd.contains("grep -v"));
        assert!(cmd.contains("Tags removed"));
    }

    #[test]
    fn test_host_tags_remove_no_tags() {
        let cmd = InventoryCommandBuilder::build_host_tags_command("remove", None);
        assert!(cmd.contains("cat /etc/host-tags"));
    }
}
