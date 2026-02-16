//! IIS Command Builder
//!
//! Builds `PowerShell` commands for remote IIS (Internet Information Services)
//! management via SSH. Supports site status, listing sites and application pools,
//! starting, stopping sites, and restarting application pools.

use crate::config::ShellType;
use crate::domain::use_cases::shell::escape;
use crate::error::{BridgeError, Result};

/// Escape a string for safe interpolation into a `PowerShell` command.
fn ps_escape(s: &str) -> String {
    escape(s, ShellType::PowerShell)
}

/// Validates an IIS site or application pool name to prevent command injection.
///
/// Names must contain only alphanumeric characters, hyphens, underscores,
/// spaces, and dots.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the site name is invalid.
pub fn validate_site_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Site name cannot be empty".to_string(),
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
                "Invalid site name '{name}'. \
                 Only alphanumeric, hyphen, underscore, space, and dot allowed.",
            ),
        })
    }
}

/// Builds `PowerShell` commands for remote IIS management.
pub struct IisCommandBuilder;

impl IisCommandBuilder {
    /// Build a command to get the status of all IIS websites.
    ///
    /// Constructs: `Import-Module WebAdministration; Get-Website
    /// | Select-Object Name,State,Bindings | Format-Table -AutoSize`
    #[must_use]
    pub fn build_status_command() -> String {
        "Import-Module WebAdministration; \
         Get-Website | Select-Object Name,State,Bindings \
         | Format-Table -AutoSize"
            .to_string()
    }

    /// Build a command to list all IIS websites with details.
    ///
    /// Constructs: `Get-Website | Select-Object Name,ID,State,PhysicalPath
    /// | Format-Table -AutoSize`
    #[must_use]
    pub fn build_list_sites_command() -> String {
        "Get-Website | Select-Object Name,ID,State,PhysicalPath \
         | Format-Table -AutoSize"
            .to_string()
    }

    /// Build a command to list all IIS application pools.
    ///
    /// Constructs: `Get-IISAppPool | Select-Object Name,State,ManagedRuntimeVersion
    /// | Format-Table -AutoSize`
    #[must_use]
    pub fn build_list_pools_command() -> String {
        "Get-IISAppPool | Select-Object Name,State,ManagedRuntimeVersion \
         | Format-Table -AutoSize"
            .to_string()
    }

    /// Build a `Start-Website` command.
    ///
    /// Constructs: `Start-Website -Name {name}; Get-Website -Name {name}
    /// | Select-Object Name,State`
    #[must_use]
    pub fn build_start_command(name: &str) -> String {
        let escaped = ps_escape(name);
        format!(
            "Start-Website -Name {escaped}; \
             Get-Website -Name {escaped} | Select-Object Name,State",
        )
    }

    /// Build a `Stop-Website` command.
    ///
    /// Constructs: `Stop-Website -Name {name}; Get-Website -Name {name}
    /// | Select-Object Name,State`
    #[must_use]
    pub fn build_stop_command(name: &str) -> String {
        let escaped = ps_escape(name);
        format!(
            "Stop-Website -Name {escaped}; \
             Get-Website -Name {escaped} | Select-Object Name,State",
        )
    }

    /// Build a `Restart-WebAppPool` command.
    ///
    /// Constructs: `Restart-WebAppPool -Name {name};
    /// Get-WebAppPoolState -Name {name}`
    #[must_use]
    pub fn build_restart_pool_command(name: &str) -> String {
        let escaped = ps_escape(name);
        format!(
            "Restart-WebAppPool -Name {escaped}; \
             Get-WebAppPoolState -Name {escaped}",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_site_name ──────────────────────────────────────────

    #[test]
    fn test_validate_site_name_valid() {
        assert!(validate_site_name("Default Web Site").is_ok());
        assert!(validate_site_name("my-site").is_ok());
        assert!(validate_site_name("my_site").is_ok());
        assert!(validate_site_name("site.v2").is_ok());
        assert!(validate_site_name("MyWebApp").is_ok());
    }

    #[test]
    fn test_validate_site_name_empty() {
        assert!(validate_site_name("").is_err());
    }

    #[test]
    fn test_validate_site_name_injection() {
        assert!(validate_site_name("site; Remove-Item C:\\").is_err());
        assert!(validate_site_name("site && whoami").is_err());
        assert!(validate_site_name("site$(hostname)").is_err());
        assert!(validate_site_name("site|Out-File").is_err());
    }

    #[test]
    fn test_validate_site_name_special_chars_rejected() {
        assert!(validate_site_name("site`id`").is_err());
        assert!(validate_site_name("site@host").is_err());
        assert!(validate_site_name("site#1").is_err());
        assert!(validate_site_name("site$env").is_err());
    }

    #[test]
    fn test_validate_site_name_error_message_contains_input() {
        let result = validate_site_name("bad;name");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bad;name"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_site_name_empty_error_message() {
        let result = validate_site_name("");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("cannot be empty"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_site_name_with_spaces() {
        assert!(validate_site_name("Default Web Site").is_ok());
        assert!(validate_site_name("My Custom Site").is_ok());
    }

    #[test]
    fn test_validate_site_name_with_dots() {
        assert!(validate_site_name("site.name.v2").is_ok());
    }

    #[test]
    fn test_validate_site_name_pipe_rejected() {
        assert!(validate_site_name("site|bad").is_err());
    }

    #[test]
    fn test_validate_site_name_semicolon_rejected() {
        assert!(validate_site_name("site;bad").is_err());
    }

    #[test]
    fn test_validate_site_name_ampersand_rejected() {
        assert!(validate_site_name("site&bad").is_err());
    }

    // ── build_status_command ────────────────────────────────────────

    #[test]
    fn test_status_command() {
        let cmd = IisCommandBuilder::build_status_command();
        assert!(cmd.contains("Import-Module WebAdministration"));
        assert!(cmd.contains("Get-Website"));
        assert!(cmd.contains("Select-Object Name,State,Bindings"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    // ── build_list_sites_command ────────────────────────────────────

    #[test]
    fn test_list_sites_command() {
        let cmd = IisCommandBuilder::build_list_sites_command();
        assert!(cmd.contains("Get-Website"));
        assert!(cmd.contains("Select-Object Name,ID,State,PhysicalPath"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    // ── build_list_pools_command ────────────────────────────────────

    #[test]
    fn test_list_pools_command() {
        let cmd = IisCommandBuilder::build_list_pools_command();
        assert!(cmd.contains("Get-IISAppPool"));
        assert!(cmd.contains("Select-Object Name,State,ManagedRuntimeVersion"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    // ── build_start_command ─────────────────────────────────────────

    #[test]
    fn test_start_command() {
        let cmd = IisCommandBuilder::build_start_command("Default Web Site");
        assert_eq!(
            cmd,
            "Start-Website -Name 'Default Web Site'; \
             Get-Website -Name 'Default Web Site' | Select-Object Name,State"
        );
    }

    #[test]
    fn test_start_command_injection() {
        let cmd = IisCommandBuilder::build_start_command("site; whoami");
        assert!(cmd.contains("'site; whoami'"));
    }

    #[test]
    fn test_start_command_single_quote() {
        let cmd = IisCommandBuilder::build_start_command("it's a site");
        assert!(cmd.contains("'it''s a site'"));
    }

    #[test]
    fn test_start_command_dollar_sign() {
        let cmd = IisCommandBuilder::build_start_command("$env:COMPUTERNAME");
        assert!(cmd.contains("'$env:COMPUTERNAME'"));
    }

    // ── build_stop_command ──────────────────────────────────────────

    #[test]
    fn test_stop_command() {
        let cmd = IisCommandBuilder::build_stop_command("Default Web Site");
        assert_eq!(
            cmd,
            "Stop-Website -Name 'Default Web Site'; \
             Get-Website -Name 'Default Web Site' | Select-Object Name,State"
        );
    }

    #[test]
    fn test_stop_command_injection() {
        let cmd = IisCommandBuilder::build_stop_command("site$(hostname)");
        assert!(cmd.contains("'site$(hostname)'"));
    }

    #[test]
    fn test_stop_command_pipe_injection() {
        let cmd = IisCommandBuilder::build_stop_command("site|Out-File");
        assert!(cmd.contains("'site|Out-File'"));
    }

    // ── build_restart_pool_command ──────────────────────────────────

    #[test]
    fn test_restart_pool_command() {
        let cmd = IisCommandBuilder::build_restart_pool_command("DefaultAppPool");
        assert_eq!(
            cmd,
            "Restart-WebAppPool -Name 'DefaultAppPool'; \
             Get-WebAppPoolState -Name 'DefaultAppPool'"
        );
    }

    #[test]
    fn test_restart_pool_command_with_space() {
        let cmd = IisCommandBuilder::build_restart_pool_command("My App Pool");
        assert!(cmd.contains("'My App Pool'"));
    }

    #[test]
    fn test_restart_pool_command_injection() {
        let cmd = IisCommandBuilder::build_restart_pool_command("pool; whoami");
        assert!(cmd.contains("'pool; whoami'"));
    }

    #[test]
    fn test_restart_pool_command_single_quote() {
        let cmd = IisCommandBuilder::build_restart_pool_command("pool'test");
        assert!(cmd.contains("'pool''test'"));
    }

    #[test]
    fn test_restart_pool_command_backtick() {
        let cmd = IisCommandBuilder::build_restart_pool_command("pool`n");
        assert!(cmd.contains("'pool`n'"));
    }

    // ── Shell Injection Prevention ──────────────────────────────────

    #[test]
    fn test_single_quote_escaping_in_start() {
        let cmd = IisCommandBuilder::build_start_command("it's a site");
        assert!(cmd.contains("'it''s a site'"));
    }

    #[test]
    fn test_dollar_variable_neutralized_in_stop() {
        let cmd = IisCommandBuilder::build_stop_command("$env:COMPUTERNAME");
        assert!(cmd.contains("'$env:COMPUTERNAME'"));
    }

    #[test]
    fn test_backtick_neutralized_in_start() {
        let cmd = IisCommandBuilder::build_start_command("site`n");
        assert!(cmd.contains("'site`n'"));
    }

    #[test]
    fn test_pipe_neutralized_in_restart_pool() {
        let cmd = IisCommandBuilder::build_restart_pool_command("pool|bad");
        assert!(cmd.contains("'pool|bad'"));
    }

    #[test]
    fn test_semicolon_neutralized_in_start() {
        let cmd = IisCommandBuilder::build_start_command("site;bad");
        assert!(cmd.contains("'site;bad'"));
    }

    // ── Edge Cases ──────────────────────────────────────────────────

    #[test]
    fn test_start_stop_symmetry() {
        let start = IisCommandBuilder::build_start_command("MySite");
        let stop = IisCommandBuilder::build_stop_command("MySite");
        assert!(start.contains("Start-Website"));
        assert!(stop.contains("Stop-Website"));
        // Both should query status after the action
        assert!(start.contains("Get-Website -Name 'MySite' | Select-Object Name,State"));
        assert!(stop.contains("Get-Website -Name 'MySite' | Select-Object Name,State"));
    }

    #[test]
    fn test_restart_pool_queries_state() {
        let cmd = IisCommandBuilder::build_restart_pool_command("DefaultAppPool");
        assert!(cmd.contains("Get-WebAppPoolState"));
    }

    #[test]
    fn test_status_imports_module() {
        let cmd = IisCommandBuilder::build_status_command();
        assert!(cmd.starts_with("Import-Module WebAdministration"));
    }
}
