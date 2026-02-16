//! Windows Network Command Builder
//!
//! Builds `PowerShell` commands for Windows network diagnostics and
//! management via SSH. Supports adapter listing, IP addresses, routes,
//! TCP connections, ping, and DNS lookup operations.

use std::fmt::Write;

use crate::config::ShellType;
use crate::domain::use_cases::shell;
use crate::error::{BridgeError, Result};

/// Escape a string for safe interpolation into a `PowerShell` command.
fn ps_escape(s: &str) -> String {
    shell::escape(s, ShellType::PowerShell)
}

/// Validates a network target (hostname or IP address) to prevent command injection.
///
/// Targets must contain only alphanumeric characters, hyphens, dots, colons
/// (for IPv6), and square brackets.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the target is invalid.
pub fn validate_network_target(target: &str) -> Result<()> {
    if target.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Network target cannot be empty".to_string(),
        });
    }
    if target
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '.' || c == ':' || c == '[' || c == ']')
    {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid network target '{target}'. \
                 Only alphanumeric, hyphen, dot, colon, and brackets allowed.",
            ),
        })
    }
}

/// Builds `PowerShell` commands for Windows network management.
pub struct WindowsNetworkCommandBuilder;

impl WindowsNetworkCommandBuilder {
    /// Build command to list network adapters.
    ///
    /// Constructs: `Get-NetAdapter | Select-Object Name,Status,LinkSpeed,MacAddress
    /// | ConvertTo-Json`
    #[must_use]
    pub fn adapters() -> String {
        "Get-NetAdapter | Select-Object Name,Status,LinkSpeed,MacAddress \
         | ConvertTo-Json"
            .to_string()
    }

    /// Build command to list IP addresses.
    ///
    /// Constructs: `Get-NetIPAddress | Select-Object
    /// InterfaceAlias,IPAddress,PrefixLength,AddressFamily | ConvertTo-Json`
    #[must_use]
    pub fn ip_addresses() -> String {
        "Get-NetIPAddress \
         | Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressFamily \
         | ConvertTo-Json"
            .to_string()
    }

    /// Build command to list network routes.
    ///
    /// Constructs: `Get-NetRoute | Select-Object
    /// DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | ConvertTo-Json`
    #[must_use]
    pub fn routes() -> String {
        "Get-NetRoute \
         | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric \
         | ConvertTo-Json"
            .to_string()
    }

    /// Build command to list TCP connections, optionally filtered by state.
    ///
    /// Constructs: `Get-NetTCPConnection [-State {state}] | Select-Object
    /// LocalAddress,LocalPort,RemoteAddress,RemotePort,State | ConvertTo-Json`
    #[must_use]
    pub fn connections(state: Option<&str>) -> String {
        let mut cmd = String::from("Get-NetTCPConnection");
        if let Some(s) = state {
            let _ = write!(cmd, " -State {}", ps_escape(s));
        }
        cmd.push_str(
            " | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State \
             | ConvertTo-Json",
        );
        cmd
    }

    /// Build command to ping a host.
    ///
    /// Constructs: `Test-Connection -ComputerName '{host}' -Count {count}`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `host` is not a valid hostname or IP.
    pub fn ping(host: &str, count: u32) -> Result<String> {
        validate_network_target(host)?;
        Ok(format!(
            "Test-Connection -ComputerName {} -Count {count}",
            ps_escape(host),
        ))
    }

    /// Build command to perform a DNS lookup.
    ///
    /// Constructs: `Resolve-DnsName -Name '{name}' [-Type {type}]`
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `name` is not a valid hostname or IP.
    pub fn dns_lookup(name: &str, record_type: Option<&str>) -> Result<String> {
        validate_network_target(name)?;
        let mut cmd = format!("Resolve-DnsName -Name {}", ps_escape(name));
        if let Some(rt) = record_type {
            let _ = write!(cmd, " -Type {}", ps_escape(rt));
        }
        Ok(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_network_target ─────────────────────────────────────

    #[test]
    fn test_validate_network_target_valid() {
        assert!(validate_network_target("192.168.1.1").is_ok());
        assert!(validate_network_target("example.com").is_ok());
        assert!(validate_network_target("my-server").is_ok());
        assert!(validate_network_target("::1").is_ok());
        assert!(validate_network_target("[::1]").is_ok());
    }

    #[test]
    fn test_validate_network_target_empty() {
        assert!(validate_network_target("").is_err());
    }

    #[test]
    fn test_validate_network_target_injection() {
        assert!(validate_network_target("host; whoami").is_err());
        assert!(validate_network_target("host$(hostname)").is_err());
        assert!(validate_network_target("host|Out-File").is_err());
        assert!(validate_network_target("host`id`").is_err());
    }

    #[test]
    fn test_validate_network_target_error_message() {
        let result = validate_network_target("bad;host");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bad;host"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    // ── adapters ────────────────────────────────────────────────────

    #[test]
    fn test_adapters() {
        let cmd = WindowsNetworkCommandBuilder::adapters();
        assert!(cmd.contains("Get-NetAdapter"));
        assert!(cmd.contains("Select-Object Name,Status,LinkSpeed,MacAddress"));
        assert!(cmd.contains("ConvertTo-Json"));
    }

    // ── ip_addresses ────────────────────────────────────────────────

    #[test]
    fn test_ip_addresses() {
        let cmd = WindowsNetworkCommandBuilder::ip_addresses();
        assert!(cmd.contains("Get-NetIPAddress"));
        assert!(cmd.contains("InterfaceAlias,IPAddress,PrefixLength,AddressFamily"));
        assert!(cmd.contains("ConvertTo-Json"));
    }

    // ── routes ──────────────────────────────────────────────────────

    #[test]
    fn test_routes() {
        let cmd = WindowsNetworkCommandBuilder::routes();
        assert!(cmd.contains("Get-NetRoute"));
        assert!(cmd.contains("DestinationPrefix,NextHop,InterfaceAlias,RouteMetric"));
        assert!(cmd.contains("ConvertTo-Json"));
    }

    // ── connections ─────────────────────────────────────────────────

    #[test]
    fn test_connections_without_state() {
        let cmd = WindowsNetworkCommandBuilder::connections(None);
        assert!(cmd.contains("Get-NetTCPConnection"));
        assert!(!cmd.contains("-State"));
        assert!(
            cmd.contains("Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State")
        );
        assert!(cmd.contains("ConvertTo-Json"));
    }

    #[test]
    fn test_connections_with_state() {
        let cmd = WindowsNetworkCommandBuilder::connections(Some("Established"));
        assert!(cmd.contains("Get-NetTCPConnection -State 'Established'"));
    }

    #[test]
    fn test_connections_injection_in_state() {
        let cmd = WindowsNetworkCommandBuilder::connections(Some("Listen; whoami"));
        assert!(cmd.contains("'Listen; whoami'"));
    }

    // ── ping ────────────────────────────────────────────────────────

    #[test]
    fn test_ping() {
        let cmd = WindowsNetworkCommandBuilder::ping("192.168.1.1", 4).unwrap();
        assert_eq!(cmd, "Test-Connection -ComputerName '192.168.1.1' -Count 4");
    }

    #[test]
    fn test_ping_hostname() {
        let cmd = WindowsNetworkCommandBuilder::ping("example.com", 10).unwrap();
        assert!(cmd.contains("'example.com'"));
        assert!(cmd.contains("-Count 10"));
    }

    #[test]
    fn test_ping_injection_rejected() {
        assert!(WindowsNetworkCommandBuilder::ping("host; whoami", 1).is_err());
    }

    #[test]
    fn test_ping_single_quote_rejected() {
        assert!(WindowsNetworkCommandBuilder::ping("it's", 1).is_err());
    }

    #[test]
    fn test_ping_zero_count() {
        let cmd = WindowsNetworkCommandBuilder::ping("host", 0).unwrap();
        assert!(cmd.contains("-Count 0"));
    }

    // ── dns_lookup ──────────────────────────────────────────────────

    #[test]
    fn test_dns_lookup_without_type() {
        let cmd = WindowsNetworkCommandBuilder::dns_lookup("example.com", None).unwrap();
        assert_eq!(cmd, "Resolve-DnsName -Name 'example.com'");
    }

    #[test]
    fn test_dns_lookup_with_type() {
        let cmd = WindowsNetworkCommandBuilder::dns_lookup("example.com", Some("MX")).unwrap();
        assert_eq!(cmd, "Resolve-DnsName -Name 'example.com' -Type 'MX'");
    }

    #[test]
    fn test_dns_lookup_injection_in_name_rejected() {
        assert!(WindowsNetworkCommandBuilder::dns_lookup("host$(hostname)", None).is_err());
    }

    #[test]
    fn test_dns_lookup_injection_in_type() {
        let cmd =
            WindowsNetworkCommandBuilder::dns_lookup("example.com", Some("A; whoami")).unwrap();
        assert!(cmd.contains("'A; whoami'"));
    }

    // ── Shell Injection Prevention ──────────────────────────────────

    #[test]
    fn test_dollar_variable_rejected() {
        assert!(WindowsNetworkCommandBuilder::ping("$env:COMPUTERNAME", 1).is_err());
    }

    #[test]
    fn test_backtick_rejected() {
        assert!(WindowsNetworkCommandBuilder::dns_lookup("host`n", None).is_err());
    }

    #[test]
    fn test_pipe_rejected() {
        assert!(WindowsNetworkCommandBuilder::ping("host|Out-File", 1).is_err());
    }

    #[test]
    fn test_semicolon_rejected() {
        assert!(WindowsNetworkCommandBuilder::dns_lookup("host;bad", None).is_err());
    }
}
