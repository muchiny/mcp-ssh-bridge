//! Windows Feature Command Builder
//!
//! Builds `PowerShell` commands for managing Windows Server features via SSH.
//! Supports listing installed features, querying feature info, installing,
//! and removing features.

use crate::config::ShellType;
use crate::domain::use_cases::shell;
use crate::error::{BridgeError, Result};

/// Escape a string for safe interpolation into a `PowerShell` command.
fn ps_escape(s: &str) -> String {
    shell::escape(s, ShellType::PowerShell)
}

/// Validates a Windows feature name to prevent command injection.
///
/// Feature names must contain only alphanumeric characters, hyphens,
/// underscores, and dots.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the feature name is invalid.
pub fn validate_feature_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Feature name cannot be empty".to_string(),
        });
    }
    if name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid feature name '{name}'. \
                 Only alphanumeric, hyphen, underscore, and dot allowed.",
            ),
        })
    }
}

/// Builds `PowerShell` commands for Windows feature management.
pub struct WindowsFeatureCommandBuilder;

impl WindowsFeatureCommandBuilder {
    /// Build command to list installed Windows features.
    ///
    /// Constructs: `Get-WindowsFeature | Where-Object Installed
    /// | Select-Object Name,DisplayName,InstallState`
    #[must_use]
    pub fn list_installed() -> String {
        "Get-WindowsFeature | Where-Object Installed \
         | Select-Object Name,DisplayName,InstallState"
            .to_string()
    }

    /// Build command to get info about a specific feature.
    ///
    /// Constructs: `Get-WindowsFeature -Name '{name}'`
    #[must_use]
    pub fn info(name: &str) -> String {
        format!("Get-WindowsFeature -Name {}", ps_escape(name))
    }

    /// Build command to install a Windows feature.
    ///
    /// Constructs: `Install-WindowsFeature -Name '{name}'
    /// [-IncludeManagementTools]`
    #[must_use]
    pub fn install(name: &str, include_management: bool) -> String {
        let mut cmd = format!("Install-WindowsFeature -Name {}", ps_escape(name));
        if include_management {
            cmd.push_str(" -IncludeManagementTools");
        }
        cmd
    }

    /// Build command to remove a Windows feature.
    ///
    /// Constructs: `Uninstall-WindowsFeature -Name '{name}'`
    #[must_use]
    pub fn remove(name: &str) -> String {
        format!("Uninstall-WindowsFeature -Name {}", ps_escape(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_feature_name ───────────────────────────────────────

    #[test]
    fn test_validate_feature_name_valid() {
        assert!(validate_feature_name("Web-Server").is_ok());
        assert!(validate_feature_name("NET-Framework-45-Core").is_ok());
        assert!(validate_feature_name("RSAT.AD").is_ok());
        assert!(validate_feature_name("Hyper_V").is_ok());
    }

    #[test]
    fn test_validate_feature_name_empty() {
        assert!(validate_feature_name("").is_err());
    }

    #[test]
    fn test_validate_feature_name_injection() {
        assert!(validate_feature_name("feat; whoami").is_err());
        assert!(validate_feature_name("feat$(hostname)").is_err());
        assert!(validate_feature_name("feat|Out-File").is_err());
        assert!(validate_feature_name("feat`id`").is_err());
    }

    #[test]
    fn test_validate_feature_name_error_message() {
        let result = validate_feature_name("bad;name");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bad;name"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    // ── list_installed ──────────────────────────────────────────────

    #[test]
    fn test_list_installed() {
        let cmd = WindowsFeatureCommandBuilder::list_installed();
        assert!(cmd.contains("Get-WindowsFeature"));
        assert!(cmd.contains("Where-Object Installed"));
        assert!(cmd.contains("Select-Object Name,DisplayName,InstallState"));
    }

    // ── info ────────────────────────────────────────────────────────

    #[test]
    fn test_info() {
        let cmd = WindowsFeatureCommandBuilder::info("Web-Server");
        assert_eq!(cmd, "Get-WindowsFeature -Name 'Web-Server'");
    }

    #[test]
    fn test_info_injection() {
        let cmd = WindowsFeatureCommandBuilder::info("feat; whoami");
        assert!(cmd.contains("'feat; whoami'"));
    }

    #[test]
    fn test_info_single_quote_escape() {
        let cmd = WindowsFeatureCommandBuilder::info("it's");
        assert!(cmd.contains("'it''s'"));
    }

    #[test]
    fn test_info_dollar_variable() {
        let cmd = WindowsFeatureCommandBuilder::info("$env:PATH");
        assert!(cmd.contains("'$env:PATH'"));
    }

    // ── install ─────────────────────────────────────────────────────

    #[test]
    fn test_install_without_management_tools() {
        let cmd = WindowsFeatureCommandBuilder::install("Web-Server", false);
        assert_eq!(cmd, "Install-WindowsFeature -Name 'Web-Server'");
        assert!(!cmd.contains("-IncludeManagementTools"));
    }

    #[test]
    fn test_install_with_management_tools() {
        let cmd = WindowsFeatureCommandBuilder::install("Web-Server", true);
        assert_eq!(
            cmd,
            "Install-WindowsFeature -Name 'Web-Server' -IncludeManagementTools"
        );
    }

    #[test]
    fn test_install_injection() {
        let cmd = WindowsFeatureCommandBuilder::install("feat$(hostname)", true);
        assert!(cmd.contains("'feat$(hostname)'"));
    }

    #[test]
    fn test_install_pipe_neutralized() {
        let cmd = WindowsFeatureCommandBuilder::install("feat|Out-File", false);
        assert!(cmd.contains("'feat|Out-File'"));
    }

    // ── remove ──────────────────────────────────────────────────────

    #[test]
    fn test_remove() {
        let cmd = WindowsFeatureCommandBuilder::remove("Web-Server");
        assert_eq!(cmd, "Uninstall-WindowsFeature -Name 'Web-Server'");
    }

    #[test]
    fn test_remove_injection() {
        let cmd = WindowsFeatureCommandBuilder::remove("feat; Remove-Item C:\\");
        assert!(cmd.contains("'feat; Remove-Item C:\\'"));
    }

    #[test]
    fn test_remove_backtick_neutralized() {
        let cmd = WindowsFeatureCommandBuilder::remove("feat`n");
        assert!(cmd.contains("'feat`n'"));
    }

    // ── Shell Injection Prevention ──────────────────────────────────

    #[test]
    fn test_dollar_variable_neutralized() {
        let cmd = WindowsFeatureCommandBuilder::info("$env:COMPUTERNAME");
        assert!(cmd.contains("'$env:COMPUTERNAME'"));
    }

    #[test]
    fn test_backtick_neutralized() {
        let cmd = WindowsFeatureCommandBuilder::info("feat`id`");
        assert!(cmd.contains("'feat`id`'"));
    }

    #[test]
    fn test_pipe_neutralized() {
        let cmd = WindowsFeatureCommandBuilder::info("feat|Out-File");
        assert!(cmd.contains("'feat|Out-File'"));
    }

    #[test]
    fn test_semicolon_neutralized() {
        let cmd = WindowsFeatureCommandBuilder::info("feat;bad");
        assert!(cmd.contains("'feat;bad'"));
    }
}
