//! Windows Firewall Command Builder
//!
//! Builds `PowerShell` commands for remote Windows Firewall management via SSH.
//! Supports status, list, allow, deny, and remove operations using
//! `NetFirewallRule` cmdlets.

use crate::config::ShellType;
use crate::domain::use_cases::shell::escape;
use crate::error::{BridgeError, Result};

/// Escape a string for safe interpolation into a `PowerShell` command.
fn ps_escape(s: &str) -> String {
    escape(s, ShellType::PowerShell)
}

/// Validates a Windows Firewall rule name to prevent command injection.
///
/// Rule names must contain only alphanumeric characters, hyphens, underscores,
/// spaces, and dots.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the rule name is invalid.
pub fn validate_firewall_rule_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Firewall rule name cannot be empty".to_string(),
        });
    }
    if name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.')
    {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid firewall rule name '{name}'. \
                 Only alphanumeric, hyphen, underscore, space, and dot allowed.",
            ),
        })
    }
}

/// Builds `PowerShell` commands for remote Windows Firewall management.
pub struct WindowsFirewallCommandBuilder;

impl WindowsFirewallCommandBuilder {
    /// Build a `Get-NetFirewallProfile` status command.
    ///
    /// Constructs: `Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,
    /// DefaultOutboundAction | Format-Table -AutoSize`
    #[must_use]
    pub fn build_status_command() -> String {
        "Get-NetFirewallProfile \
         | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction \
         | Format-Table -AutoSize"
            .to_string()
    }

    /// Build a `Get-NetFirewallRule` list command for enabled rules.
    ///
    /// Constructs: `Get-NetFirewallRule -Enabled True | Select-Object
    /// DisplayName,Direction,Action,Protocol | Sort-Object DisplayName
    /// | Format-Table -AutoSize`
    #[must_use]
    pub fn build_list_command() -> String {
        "Get-NetFirewallRule -Enabled True \
         | Select-Object DisplayName,Direction,Action,Protocol \
         | Sort-Object DisplayName \
         | Format-Table -AutoSize"
            .to_string()
    }

    /// Build a `New-NetFirewallRule` allow command.
    ///
    /// Constructs: `New-NetFirewallRule -DisplayName {name} -Direction Inbound
    /// -Action Allow -Protocol {protocol} -LocalPort {port} -Enabled True`
    #[must_use]
    pub fn build_allow_command(name: &str, port: u16, protocol: &str) -> String {
        format!(
            "New-NetFirewallRule -DisplayName {} \
             -Direction Inbound -Action Allow \
             -Protocol {} -LocalPort {port} -Enabled True",
            ps_escape(name),
            ps_escape(protocol),
        )
    }

    /// Build a `New-NetFirewallRule` deny (block) command.
    ///
    /// Constructs: `New-NetFirewallRule -DisplayName {name} -Direction Inbound
    /// -Action Block -Protocol {protocol} -LocalPort {port} -Enabled True`
    #[must_use]
    pub fn build_deny_command(name: &str, port: u16, protocol: &str) -> String {
        format!(
            "New-NetFirewallRule -DisplayName {} \
             -Direction Inbound -Action Block \
             -Protocol {} -LocalPort {port} -Enabled True",
            ps_escape(name),
            ps_escape(protocol),
        )
    }

    /// Build a `Remove-NetFirewallRule` command.
    ///
    /// Constructs: `Remove-NetFirewallRule -DisplayName {name}`
    #[must_use]
    pub fn build_remove_command(name: &str) -> String {
        format!("Remove-NetFirewallRule -DisplayName {}", ps_escape(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_firewall_rule_name ─────────────────────────────────

    #[test]
    fn test_validate_rule_name_valid() {
        assert!(validate_firewall_rule_name("Allow HTTP").is_ok());
        assert!(validate_firewall_rule_name("my-rule").is_ok());
        assert!(validate_firewall_rule_name("my_rule").is_ok());
        assert!(validate_firewall_rule_name("rule.v2").is_ok());
        assert!(validate_firewall_rule_name("AllowPort443").is_ok());
    }

    #[test]
    fn test_validate_rule_name_empty() {
        assert!(validate_firewall_rule_name("").is_err());
    }

    #[test]
    fn test_validate_rule_name_injection() {
        assert!(validate_firewall_rule_name("rule; Remove-Item C:\\").is_err());
        assert!(validate_firewall_rule_name("rule && whoami").is_err());
        assert!(validate_firewall_rule_name("rule$(hostname)").is_err());
        assert!(validate_firewall_rule_name("rule|Out-File").is_err());
    }

    #[test]
    fn test_validate_rule_name_special_chars_rejected() {
        assert!(validate_firewall_rule_name("rule`id`").is_err());
        assert!(validate_firewall_rule_name("rule@host").is_err());
        assert!(validate_firewall_rule_name("rule#1").is_err());
        assert!(validate_firewall_rule_name("rule$env").is_err());
    }

    #[test]
    fn test_validate_rule_name_error_message_contains_input() {
        let result = validate_firewall_rule_name("bad;name");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bad;name"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_rule_name_empty_error_message() {
        let result = validate_firewall_rule_name("");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("cannot be empty"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_rule_name_with_spaces() {
        assert!(validate_firewall_rule_name("Allow Inbound HTTP").is_ok());
        assert!(validate_firewall_rule_name("My Custom Rule").is_ok());
    }

    #[test]
    fn test_validate_rule_name_with_dots() {
        assert!(validate_firewall_rule_name("rule.name.v2").is_ok());
    }

    #[test]
    fn test_validate_rule_name_pipe_rejected() {
        assert!(validate_firewall_rule_name("rule|bad").is_err());
    }

    #[test]
    fn test_validate_rule_name_semicolon_rejected() {
        assert!(validate_firewall_rule_name("rule;bad").is_err());
    }

    #[test]
    fn test_validate_rule_name_ampersand_rejected() {
        assert!(validate_firewall_rule_name("rule&bad").is_err());
    }

    // ── build_status_command ────────────────────────────────────────

    #[test]
    fn test_status_command() {
        let cmd = WindowsFirewallCommandBuilder::build_status_command();
        assert!(cmd.contains("Get-NetFirewallProfile"));
        assert!(
            cmd.contains("Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction")
        );
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    // ── build_list_command ──────────────────────────────────────────

    #[test]
    fn test_list_command() {
        let cmd = WindowsFirewallCommandBuilder::build_list_command();
        assert!(cmd.contains("Get-NetFirewallRule -Enabled True"));
        assert!(cmd.contains("Select-Object DisplayName,Direction,Action,Protocol"));
        assert!(cmd.contains("Sort-Object DisplayName"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    // ── build_allow_command ─────────────────────────────────────────

    #[test]
    fn test_allow_command() {
        let cmd = WindowsFirewallCommandBuilder::build_allow_command("Allow HTTP", 80, "TCP");
        assert!(cmd.contains("New-NetFirewallRule"));
        assert!(cmd.contains("-DisplayName 'Allow HTTP'"));
        assert!(cmd.contains("-Direction Inbound"));
        assert!(cmd.contains("-Action Allow"));
        assert!(cmd.contains("-Protocol 'TCP'"));
        assert!(cmd.contains("-LocalPort 80"));
        assert!(cmd.contains("-Enabled True"));
    }

    #[test]
    fn test_allow_command_udp() {
        let cmd = WindowsFirewallCommandBuilder::build_allow_command("Allow DNS", 53, "UDP");
        assert!(cmd.contains("-Protocol 'UDP'"));
        assert!(cmd.contains("-LocalPort 53"));
    }

    #[test]
    fn test_allow_command_injection_in_name() {
        let cmd = WindowsFirewallCommandBuilder::build_allow_command("rule; whoami", 80, "TCP");
        assert!(cmd.contains("'rule; whoami'"));
    }

    #[test]
    fn test_allow_command_injection_in_protocol() {
        let cmd =
            WindowsFirewallCommandBuilder::build_allow_command("Allow HTTP", 80, "TCP; whoami");
        assert!(cmd.contains("'TCP; whoami'"));
    }

    #[test]
    fn test_allow_command_single_quote_in_name() {
        let cmd = WindowsFirewallCommandBuilder::build_allow_command("it's a rule", 443, "TCP");
        assert!(cmd.contains("'it''s a rule'"));
    }

    #[test]
    fn test_allow_command_dollar_sign_in_name() {
        let cmd =
            WindowsFirewallCommandBuilder::build_allow_command("$env:COMPUTERNAME", 80, "TCP");
        assert!(cmd.contains("'$env:COMPUTERNAME'"));
    }

    // ── build_deny_command ──────────────────────────────────────────

    #[test]
    fn test_deny_command() {
        let cmd = WindowsFirewallCommandBuilder::build_deny_command("Block Telnet", 23, "TCP");
        assert!(cmd.contains("New-NetFirewallRule"));
        assert!(cmd.contains("-DisplayName 'Block Telnet'"));
        assert!(cmd.contains("-Direction Inbound"));
        assert!(cmd.contains("-Action Block"));
        assert!(cmd.contains("-Protocol 'TCP'"));
        assert!(cmd.contains("-LocalPort 23"));
        assert!(cmd.contains("-Enabled True"));
    }

    #[test]
    fn test_deny_command_injection_in_name() {
        let cmd = WindowsFirewallCommandBuilder::build_deny_command("rule$(hostname)", 80, "TCP");
        assert!(cmd.contains("'rule$(hostname)'"));
    }

    #[test]
    fn test_deny_command_injection_in_protocol() {
        let cmd = WindowsFirewallCommandBuilder::build_deny_command("Block", 80, "TCP|Out-File");
        assert!(cmd.contains("'TCP|Out-File'"));
    }

    // ── build_remove_command ────────────────────────────────────────

    #[test]
    fn test_remove_command() {
        let cmd = WindowsFirewallCommandBuilder::build_remove_command("Allow HTTP");
        assert_eq!(cmd, "Remove-NetFirewallRule -DisplayName 'Allow HTTP'");
    }

    #[test]
    fn test_remove_command_injection() {
        let cmd = WindowsFirewallCommandBuilder::build_remove_command("rule; Remove-Item C:\\");
        assert!(cmd.contains("'rule; Remove-Item C:\\'"));
    }

    #[test]
    fn test_remove_command_single_quote() {
        let cmd = WindowsFirewallCommandBuilder::build_remove_command("it's a rule");
        assert!(cmd.contains("'it''s a rule'"));
    }

    #[test]
    fn test_remove_command_backtick() {
        let cmd = WindowsFirewallCommandBuilder::build_remove_command("rule`n");
        assert!(cmd.contains("'rule`n'"));
    }

    // ── Shell Injection Prevention ──────────────────────────────────

    #[test]
    fn test_single_quote_escaping_in_allow() {
        let cmd = WindowsFirewallCommandBuilder::build_allow_command("rule'test", 80, "TCP");
        assert!(cmd.contains("'rule''test'"));
    }

    #[test]
    fn test_dollar_variable_neutralized_in_deny() {
        let cmd = WindowsFirewallCommandBuilder::build_deny_command("$env:PATH", 80, "TCP");
        assert!(cmd.contains("'$env:PATH'"));
    }

    #[test]
    fn test_backtick_neutralized_in_remove() {
        let cmd = WindowsFirewallCommandBuilder::build_remove_command("rule`id`");
        assert!(cmd.contains("'rule`id`'"));
    }

    #[test]
    fn test_pipe_neutralized_in_allow() {
        let cmd = WindowsFirewallCommandBuilder::build_allow_command("rule|bad", 80, "TCP");
        assert!(cmd.contains("'rule|bad'"));
    }

    #[test]
    fn test_semicolon_neutralized_in_deny() {
        let cmd = WindowsFirewallCommandBuilder::build_deny_command("rule;bad", 80, "TCP");
        assert!(cmd.contains("'rule;bad'"));
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn test_allow_command_max_port() {
        let cmd = WindowsFirewallCommandBuilder::build_allow_command("Max Port", 65535, "TCP");
        assert!(cmd.contains("-LocalPort 65535"));
    }

    #[test]
    fn test_allow_command_min_port() {
        let cmd = WindowsFirewallCommandBuilder::build_allow_command("Min Port", 0, "TCP");
        assert!(cmd.contains("-LocalPort 0"));
    }

    #[test]
    fn test_deny_vs_allow_action_difference() {
        let allow = WindowsFirewallCommandBuilder::build_allow_command("Test", 80, "TCP");
        let deny = WindowsFirewallCommandBuilder::build_deny_command("Test", 80, "TCP");
        assert!(allow.contains("-Action Allow"));
        assert!(deny.contains("-Action Block"));
    }
}
