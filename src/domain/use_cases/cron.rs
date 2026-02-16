//! Cron Command Builder
//!
//! Builds cron job management CLI commands for remote execution via SSH.
//! Supports listing, adding, and removing cron jobs.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate that a cron schedule has the expected format (5 fields).
/// Each field is separated by whitespace. Accepts standard cron syntax:
/// minute hour day-of-month month day-of-week
pub fn validate_cron_schedule(schedule: &str) -> Result<()> {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid cron schedule: expected 5 fields (minute hour day month weekday), got {}",
                fields.len()
            ),
        });
    }
    // Each field should only contain: digits, *, /, -, comma
    for (i, field) in fields.iter().enumerate() {
        if !field
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '*' | '/' | '-' | ','))
        {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid cron field {}: '{}' contains invalid characters",
                    i + 1,
                    field
                ),
            });
        }
    }
    Ok(())
}

/// Validate that a cron comment does not contain newlines.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the comment contains newline characters.
pub fn validate_cron_comment(comment: &str) -> Result<()> {
    if comment.contains('\n') || comment.contains('\r') {
        return Err(BridgeError::CommandDenied {
            reason: "Cron comment must not contain newlines".to_string(),
        });
    }
    Ok(())
}

/// Builds cron management commands for remote execution.
pub struct CronCommandBuilder;

impl CronCommandBuilder {
    /// Build a command to list cron jobs.
    ///
    /// Constructs: `crontab -l [-u {user}]` and optionally reads `/etc/cron.d/`
    #[must_use]
    pub fn build_list_command(user: Option<&str>, system: bool) -> String {
        let mut cmd = String::from("crontab -l");

        if let Some(u) = user {
            cmd = format!("crontab -l -u {}", shell_escape(u));
        }

        if system {
            let _ = write!(
                cmd,
                " 2>/dev/null; echo '--- /etc/cron.d/ ---'; ls -la /etc/cron.d/ 2>/dev/null; \
                 echo '--- /etc/crontab ---'; cat /etc/crontab 2>/dev/null"
            );
        }

        cmd
    }

    /// Build a command to add a cron job.
    ///
    /// Constructs: `(crontab -l 2>/dev/null; echo "{schedule} {command}") | crontab -`
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the schedule or comment is invalid.
    pub fn build_add_command(
        schedule: &str,
        command: &str,
        user: Option<&str>,
        comment: Option<&str>,
    ) -> Result<String> {
        validate_cron_schedule(schedule)?;
        if let Some(c) = comment {
            validate_cron_comment(c)?;
        }

        let mut cron_line = String::new();

        if let Some(c) = comment {
            let _ = writeln!(cron_line, "# {c}");
        }

        let _ = write!(cron_line, "{schedule} {command}");

        let crontab_cmd = if let Some(u) = user {
            format!("crontab -u {} -l", shell_escape(u))
        } else {
            String::from("crontab -l")
        };

        let set_cmd = if let Some(u) = user {
            format!("crontab -u {} -", shell_escape(u))
        } else {
            String::from("crontab -")
        };

        Ok(format!(
            "({crontab_cmd} 2>/dev/null; echo {}) | {set_cmd}",
            shell_escape(&cron_line)
        ))
    }

    /// Build a command to remove a cron job by pattern.
    ///
    /// Constructs: `crontab -l | grep -v "{pattern}" | crontab -`
    #[must_use]
    pub fn build_remove_command(pattern: &str, user: Option<&str>) -> String {
        let crontab_cmd = if let Some(u) = user {
            format!("crontab -u {} -l", shell_escape(u))
        } else {
            String::from("crontab -l")
        };

        let set_cmd = if let Some(u) = user {
            format!("crontab -u {} -", shell_escape(u))
        } else {
            String::from("crontab -")
        };

        format!(
            "{crontab_cmd} | grep -v {} | {set_cmd}",
            shell_escape(pattern)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_default() {
        let cmd = CronCommandBuilder::build_list_command(None, false);
        assert_eq!(cmd, "crontab -l");
    }

    #[test]
    fn test_list_with_user() {
        let cmd = CronCommandBuilder::build_list_command(Some("www-data"), false);
        assert!(cmd.contains("-u 'www-data'"));
    }

    #[test]
    fn test_list_system() {
        let cmd = CronCommandBuilder::build_list_command(None, true);
        assert!(cmd.contains("/etc/cron.d/"));
        assert!(cmd.contains("/etc/crontab"));
    }

    #[test]
    fn test_add_simple() {
        let cmd =
            CronCommandBuilder::build_add_command("0 * * * *", "/usr/bin/backup.sh", None, None)
                .unwrap();
        assert!(cmd.contains("crontab -l"));
        assert!(cmd.contains("0 * * * * /usr/bin/backup.sh"));
        assert!(cmd.contains("crontab -"));
    }

    #[test]
    fn test_add_with_user() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 2 * * *",
            "/opt/cleanup.sh",
            Some("root"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("-u 'root'"));
    }

    #[test]
    fn test_add_with_comment() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 3 * * *",
            "/opt/backup.sh",
            None,
            Some("Daily backup"),
        )
        .unwrap();
        assert!(cmd.contains("# Daily backup"));
    }

    #[test]
    fn test_add_comment_produces_real_newline() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 3 * * *",
            "/opt/backup.sh",
            None,
            Some("Daily backup"),
        )
        .unwrap();
        // Comment and schedule must be on separate lines (real newline, not literal \n)
        assert!(!cmd.contains("\\n"));
        assert!(cmd.contains("# Daily backup\n0 3"));
    }

    #[test]
    fn test_remove() {
        let cmd = CronCommandBuilder::build_remove_command("backup.sh", None);
        assert!(cmd.contains("grep -v 'backup.sh'"));
        assert!(cmd.contains("crontab -"));
    }

    #[test]
    fn test_remove_with_user() {
        let cmd = CronCommandBuilder::build_remove_command("cleanup", Some("root"));
        assert!(cmd.contains("-u 'root'"));
        assert!(cmd.contains("grep -v 'cleanup'"));
    }

    // ── validate_cron_schedule ─────────────────────────────────────

    #[test]
    fn test_validate_cron_valid() {
        assert!(validate_cron_schedule("0 * * * *").is_ok());
        assert!(validate_cron_schedule("0 2 * * *").is_ok());
        assert!(validate_cron_schedule("*/5 * * * *").is_ok());
        assert!(validate_cron_schedule("0 0 1 1 *").is_ok());
        assert!(validate_cron_schedule("0,30 * * * *").is_ok());
        assert!(validate_cron_schedule("0 9-17 * * 1-5").is_ok());
    }

    #[test]
    fn test_validate_cron_invalid_field_count() {
        assert!(validate_cron_schedule("* * *").is_err());
        assert!(validate_cron_schedule("* * * * * *").is_err());
        assert!(validate_cron_schedule("*").is_err());
        assert!(validate_cron_schedule("").is_err());
    }

    #[test]
    fn test_validate_cron_invalid_chars() {
        assert!(validate_cron_schedule("0 * * * ; rm -rf /").is_err());
    }

    // ============== Shell Injection Prevention ==============

    #[test]
    fn test_add_injection_in_command() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 * * * *",
            "/opt/backup.sh; rm -rf /",
            None,
            None,
        )
        .unwrap();
        assert!(cmd.contains("'0 * * * * /opt/backup.sh; rm -rf /'"));
    }

    #[test]
    fn test_add_injection_in_user() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 * * * *",
            "/opt/job.sh",
            Some("root; cat /etc/shadow"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("-u 'root; cat /etc/shadow'"));
    }

    #[test]
    fn test_remove_injection_in_pattern() {
        let cmd = CronCommandBuilder::build_remove_command("backup.sh; rm -rf /", None);
        assert!(cmd.contains("grep -v 'backup.sh; rm -rf /'"));
    }

    #[test]
    fn test_list_injection_in_user() {
        let cmd = CronCommandBuilder::build_list_command(Some("$(whoami)"), false);
        assert!(cmd.contains("-u '$(whoami)'"));
    }

    // ============== All-Options Combination ==============

    #[test]
    fn test_add_all_options() {
        let cmd = CronCommandBuilder::build_add_command(
            "0 2 * * *",
            "/opt/backup.sh",
            Some("backupuser"),
            Some("Nightly backup"),
        )
        .unwrap();
        assert!(cmd.contains("-u 'backupuser'"));
        assert!(cmd.contains("# Nightly backup"));
        assert!(cmd.contains("0 2 * * * /opt/backup.sh"));
    }

    #[test]
    fn test_list_user_and_system() {
        let cmd = CronCommandBuilder::build_list_command(Some("www-data"), true);
        assert!(cmd.contains("-u 'www-data'"));
        assert!(cmd.contains("/etc/cron.d/"));
        assert!(cmd.contains("/etc/crontab"));
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_add_command_with_single_quotes() {
        let cmd =
            CronCommandBuilder::build_add_command("0 * * * *", "echo 'hello world'", None, None)
                .unwrap();
        // The whole cron_line is shell-escaped, so internal quotes get escaped
        assert!(cmd.contains("hello"));
    }

    #[test]
    fn test_remove_pattern_with_special_chars() {
        let cmd = CronCommandBuilder::build_remove_command("backup.*\\.sh", None);
        assert!(cmd.contains("grep -v 'backup.*\\.sh'"));
    }

    #[test]
    fn test_add_long_command() {
        let long_cmd = "x".repeat(500);
        let cmd =
            CronCommandBuilder::build_add_command("0 * * * *", &long_cmd, None, None).unwrap();
        assert!(cmd.contains(&long_cmd));
    }

    // ============== validate_cron_comment ==============

    #[test]
    fn test_validate_cron_comment_valid() {
        assert!(validate_cron_comment("Daily backup").is_ok());
        assert!(validate_cron_comment("Run at midnight").is_ok());
    }

    #[test]
    fn test_validate_cron_comment_newline_rejected() {
        assert!(validate_cron_comment("line1\nline2").is_err());
        assert!(validate_cron_comment("line1\rline2").is_err());
    }

    #[test]
    fn test_add_invalid_schedule_rejected() {
        let result = CronCommandBuilder::build_add_command("bad", "/bin/test", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_invalid_comment_rejected() {
        let result = CronCommandBuilder::build_add_command(
            "0 * * * *",
            "/bin/test",
            None,
            Some("line1\nline2"),
        );
        assert!(result.is_err());
    }

    // ============== validate_cron_schedule Additional Tests ==============

    #[test]
    fn test_validate_cron_step_and_range() {
        assert!(validate_cron_schedule("*/15 0-23 * * *").is_ok());
    }

    #[test]
    fn test_validate_cron_injection_in_field() {
        assert!(validate_cron_schedule("0 * * * $(rm -rf /)").is_err());
    }

    #[test]
    fn test_validate_cron_semicolon_in_field() {
        assert!(validate_cron_schedule("0 * * * ;").is_err());
    }

    #[test]
    fn test_validate_cron_letters_rejected() {
        assert!(validate_cron_schedule("0 0 * jan *").is_err());
        assert!(validate_cron_schedule("0 0 * * mon").is_err());
    }

    #[test]
    fn test_validate_cron_pipe_rejected() {
        assert!(validate_cron_schedule("0 * * | *").is_err());
    }

    #[test]
    fn test_validate_cron_extra_whitespace() {
        // split_whitespace handles leading/trailing whitespace
        assert!(validate_cron_schedule("  0 * * * *  ").is_ok());
    }

    #[test]
    fn test_validate_cron_error_message_field_count() {
        let result = validate_cron_schedule("* * *");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("got 3"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_cron_error_message_invalid_char() {
        let result = validate_cron_schedule("0 * * * abc");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("field 5"));
                assert!(reason.contains("abc"));
            }
            other => panic!("Expected BridgeError::CommandDenied, got: {other:?}"),
        }
    }
}
