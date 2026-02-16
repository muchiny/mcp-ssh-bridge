//! Scheduled Task Command Builder
//!
//! Builds `PowerShell` commands for Windows Scheduled Tasks management
//! via SSH. Supports listing, info, run, enable, and disable operations.

use crate::config::ShellType;
use crate::domain::use_cases::shell::escape;
use crate::error::{BridgeError, Result};

/// Validates a scheduled task name to prevent command injection.
///
/// Task names must be alphanumeric with hyphens, underscores, spaces,
/// and backslashes (for task paths like `\Microsoft\Windows\Defrag\ScheduledDefrag`).
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the task name is invalid.
pub fn validate_task_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Task name cannot be empty".to_string(),
        });
    }
    if name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '\\')
    {
        Ok(())
    } else {
        Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid task name '{name}'. \
                 Only alphanumeric, hyphen, underscore, space, and backslash allowed.",
            ),
        })
    }
}

/// Builds `PowerShell` commands for Windows Scheduled Tasks management.
pub struct ScheduledTaskCommandBuilder;

impl ScheduledTaskCommandBuilder {
    /// Build a `Get-ScheduledTask` list command.
    ///
    /// Constructs:
    /// `Get-ScheduledTask | Select-Object TaskName,State,TaskPath
    ///  | Sort-Object TaskPath,TaskName | Format-Table -AutoSize`
    #[must_use]
    pub fn build_list_command() -> String {
        "Get-ScheduledTask \
         | Select-Object TaskName,State,TaskPath \
         | Sort-Object TaskPath,TaskName \
         | Format-Table -AutoSize"
            .to_string()
    }

    /// Build a `Get-ScheduledTask` info command for a specific task.
    ///
    /// Constructs:
    /// `Get-ScheduledTask -TaskName '{name}' | Format-List *;
    ///  Write-Output '---';
    ///  Get-ScheduledTaskInfo -TaskName '{name}' | Format-List`
    #[must_use]
    pub fn build_info_command(name: &str) -> String {
        let escaped = escape(name, ShellType::PowerShell);
        format!(
            "Get-ScheduledTask -TaskName {escaped} | Format-List *; \
             Write-Output '---'; \
             Get-ScheduledTaskInfo -TaskName {escaped} | Format-List"
        )
    }

    /// Build a `Start-ScheduledTask` command.
    ///
    /// Constructs:
    /// `Start-ScheduledTask -TaskName '{name}';
    ///  Get-ScheduledTask -TaskName '{name}' | Select-Object TaskName,State`
    #[must_use]
    pub fn build_run_command(name: &str) -> String {
        let escaped = escape(name, ShellType::PowerShell);
        format!(
            "Start-ScheduledTask -TaskName {escaped}; \
             Get-ScheduledTask -TaskName {escaped} | Select-Object TaskName,State"
        )
    }

    /// Build an `Enable-ScheduledTask` command.
    ///
    /// Constructs:
    /// `Enable-ScheduledTask -TaskName '{name}';
    ///  Get-ScheduledTask -TaskName '{name}' | Select-Object TaskName,State`
    #[must_use]
    pub fn build_enable_command(name: &str) -> String {
        let escaped = escape(name, ShellType::PowerShell);
        format!(
            "Enable-ScheduledTask -TaskName {escaped}; \
             Get-ScheduledTask -TaskName {escaped} | Select-Object TaskName,State"
        )
    }

    /// Build a `Disable-ScheduledTask` command.
    ///
    /// Constructs:
    /// `Disable-ScheduledTask -TaskName '{name}';
    ///  Get-ScheduledTask -TaskName '{name}' | Select-Object TaskName,State`
    #[must_use]
    pub fn build_disable_command(name: &str) -> String {
        let escaped = escape(name, ShellType::PowerShell);
        format!(
            "Disable-ScheduledTask -TaskName {escaped}; \
             Get-ScheduledTask -TaskName {escaped} | Select-Object TaskName,State"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_task_name ─────────────────────────────────────────

    #[test]
    fn test_validate_task_name_valid_simple() {
        assert!(validate_task_name("MyTask").is_ok());
    }

    #[test]
    fn test_validate_task_name_valid_with_hyphen() {
        assert!(validate_task_name("my-task").is_ok());
    }

    #[test]
    fn test_validate_task_name_valid_with_underscore() {
        assert!(validate_task_name("my_task").is_ok());
    }

    #[test]
    fn test_validate_task_name_valid_with_space() {
        assert!(validate_task_name("My Task").is_ok());
    }

    #[test]
    fn test_validate_task_name_valid_with_backslash_path() {
        assert!(validate_task_name("\\Microsoft\\Windows\\Defrag\\ScheduledDefrag").is_ok());
    }

    #[test]
    fn test_validate_task_name_empty() {
        assert!(validate_task_name("").is_err());
    }

    #[test]
    fn test_validate_task_name_semicolon_rejected() {
        assert!(validate_task_name("task; Remove-Item C:\\").is_err());
    }

    #[test]
    fn test_validate_task_name_pipe_rejected() {
        assert!(validate_task_name("task|bad").is_err());
    }

    #[test]
    fn test_validate_task_name_dollar_rejected() {
        assert!(validate_task_name("task$var").is_err());
    }

    #[test]
    fn test_validate_task_name_backtick_rejected() {
        assert!(validate_task_name("task`id`").is_err());
    }

    #[test]
    fn test_validate_task_name_parentheses_rejected() {
        assert!(validate_task_name("task(bad)").is_err());
    }

    #[test]
    fn test_validate_task_name_ampersand_rejected() {
        assert!(validate_task_name("task&bad").is_err());
    }

    #[test]
    fn test_validate_task_name_error_message() {
        let result = validate_task_name("bad;name");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bad;name"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    // ── build_list_command ─────────────────────────────────────────

    #[test]
    fn test_list_command() {
        let cmd = ScheduledTaskCommandBuilder::build_list_command();
        assert!(cmd.contains("Get-ScheduledTask"));
        assert!(cmd.contains("Select-Object TaskName,State,TaskPath"));
        assert!(cmd.contains("Sort-Object TaskPath,TaskName"));
        assert!(cmd.contains("Format-Table -AutoSize"));
    }

    // ── build_info_command ─────────────────────────────────────────

    #[test]
    fn test_info_command() {
        let cmd = ScheduledTaskCommandBuilder::build_info_command("MyTask");
        assert!(cmd.contains("Get-ScheduledTask -TaskName 'MyTask'"));
        assert!(cmd.contains("Format-List *"));
        assert!(cmd.contains("Write-Output '---'"));
        assert!(cmd.contains("Get-ScheduledTaskInfo -TaskName 'MyTask'"));
    }

    #[test]
    fn test_info_command_with_quote() {
        let cmd = ScheduledTaskCommandBuilder::build_info_command("it's");
        assert!(cmd.contains("'it''s'"));
    }

    // ── build_run_command ──────────────────────────────────────────

    #[test]
    fn test_run_command() {
        let cmd = ScheduledTaskCommandBuilder::build_run_command("MyTask");
        assert!(cmd.contains("Start-ScheduledTask -TaskName 'MyTask'"));
        assert!(cmd.contains("Get-ScheduledTask -TaskName 'MyTask'"));
        assert!(cmd.contains("Select-Object TaskName,State"));
    }

    // ── build_enable_command ───────────────────────────────────────

    #[test]
    fn test_enable_command() {
        let cmd = ScheduledTaskCommandBuilder::build_enable_command("MyTask");
        assert!(cmd.contains("Enable-ScheduledTask -TaskName 'MyTask'"));
        assert!(cmd.contains("Get-ScheduledTask -TaskName 'MyTask'"));
        assert!(cmd.contains("Select-Object TaskName,State"));
    }

    // ── build_disable_command ──────────────────────────────────────

    #[test]
    fn test_disable_command() {
        let cmd = ScheduledTaskCommandBuilder::build_disable_command("MyTask");
        assert!(cmd.contains("Disable-ScheduledTask -TaskName 'MyTask'"));
        assert!(cmd.contains("Get-ScheduledTask -TaskName 'MyTask'"));
        assert!(cmd.contains("Select-Object TaskName,State"));
    }

    // ── Shell injection prevention ─────────────────────────────────

    #[test]
    fn test_info_command_injection() {
        let cmd = ScheduledTaskCommandBuilder::build_info_command("task; Remove-Item C:\\");
        // The semicolon and path are safely wrapped in single quotes
        assert!(cmd.contains("'task; Remove-Item C:\\'"));
    }

    #[test]
    fn test_run_command_injection() {
        let cmd = ScheduledTaskCommandBuilder::build_run_command("task$(whoami)");
        assert!(cmd.contains("'task$(whoami)'"));
    }

    #[test]
    fn test_enable_command_injection() {
        let cmd = ScheduledTaskCommandBuilder::build_enable_command("task`hostname`");
        assert!(cmd.contains("'task`hostname`'"));
    }

    #[test]
    fn test_disable_command_injection() {
        let cmd = ScheduledTaskCommandBuilder::build_disable_command("task|bad");
        assert!(cmd.contains("'task|bad'"));
    }

    // ── Edge cases ─────────────────────────────────────────────────

    #[test]
    fn test_info_command_with_backslash_path() {
        let cmd = ScheduledTaskCommandBuilder::build_info_command(
            "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
        );
        assert!(cmd.contains("'\\Microsoft\\Windows\\Defrag\\ScheduledDefrag'"));
    }

    #[test]
    fn test_run_command_with_spaces() {
        let cmd = ScheduledTaskCommandBuilder::build_run_command("My Scheduled Task");
        assert!(cmd.contains("'My Scheduled Task'"));
    }

    #[test]
    fn test_validate_task_name_numeric_only() {
        assert!(validate_task_name("12345").is_ok());
    }

    #[test]
    fn test_validate_task_name_single_char() {
        assert!(validate_task_name("A").is_ok());
    }

    #[test]
    fn test_validate_task_name_mixed_valid() {
        assert!(validate_task_name("My-Task_01 Backup\\Daily").is_ok());
    }
}
