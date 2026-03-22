//! Cron Analysis Command Builder
//!
//! Builds intelligent cron/job analysis commands for remote execution via SSH.
//! Provides comprehensive cron analysis, history querying, and at-job inspection.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate that the requested number of lines is within bounds.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if `lines` exceeds 5000.
pub fn validate_cron_lines(lines: Option<u64>) -> Result<()> {
    if let Some(n) = lines {
        if n > 5000 {
            return Err(BridgeError::CommandDenied {
                reason: format!("lines must be <= 5000, got {n}"),
            });
        }
    }
    Ok(())
}

/// Builds cron analysis commands for remote execution.
pub struct CronAnalysisCommandBuilder;

impl CronAnalysisCommandBuilder {
    /// Build a comprehensive cron analysis command.
    ///
    /// Gathers user crontabs, system crontabs, recent CRON failures from
    /// journal/syslog, and detects overlapping schedules.
    #[must_use]
    pub fn build_cron_analyze_command() -> String {
        [
            "echo '=== User Crontabs ==='",
            "crontab -l 2>/dev/null || echo 'No user crontab'",
            "echo ''",
            "echo '=== System Crontabs ==='",
            "cat /etc/crontab 2>/dev/null || echo 'No /etc/crontab'",
            "echo ''",
            "echo '=== Cron.d Directory ==='",
            "ls -la /etc/cron.d/ 2>/dev/null || echo 'No /etc/cron.d/'",
            "echo ''",
            "echo '=== Recent CRON Failures (last 24h) ==='",
            "journalctl -u cron --since '24 hours ago' --no-pager -q 2>/dev/null || grep CRON /var/log/syslog 2>/dev/null | tail -50",
            "echo ''",
            "echo '=== Schedule Overlap Detection ==='",
            "crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' | awk '{print $1, $2, $3, $4, $5}' | sort | uniq -d 2>/dev/null || echo 'No overlapping schedules detected'",
        ]
        .join(" && ")
    }

    /// Build a cron history command.
    ///
    /// Queries journalctl or syslog for CRON entries with optional time filtering
    /// and line limits.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if `lines` exceeds 5000.
    pub fn build_cron_history_command(lines: Option<u64>, since: Option<&str>) -> Result<String> {
        validate_cron_lines(lines)?;

        let n = lines.unwrap_or(100);
        let mut cmd = String::from("journalctl -u cron --no-pager -q");
        if let Some(s) = since {
            let _ = write!(cmd, " --since {}", shell_escape(s));
        }
        let _ = write!(cmd, " -n {n}");
        let _ = write!(
            cmd,
            " 2>/dev/null || grep CRON /var/log/syslog 2>/dev/null | tail -{n}"
        );
        Ok(cmd)
    }

    /// Build a command to list at-queue jobs.
    ///
    /// Lists pending one-time scheduled tasks from the `at` queue and shows
    /// job details.
    #[must_use]
    pub fn build_at_jobs_command() -> String {
        [
            "echo '=== Pending At Jobs ==='",
            "atq 2>/dev/null || echo 'at command not available'",
            "echo ''",
            "echo '=== At Job Details ==='",
            "for job in $(atq 2>/dev/null | awk '{print $1}'); do echo \"--- Job $job ---\"; at -c \"$job\" 2>/dev/null | tail -5; done",
        ]
        .join(" && ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== build_cron_analyze_command ==============

    #[test]
    fn test_analyze_contains_user_crontab() {
        let cmd = CronAnalysisCommandBuilder::build_cron_analyze_command();
        assert!(cmd.contains("crontab -l"));
    }

    #[test]
    fn test_analyze_contains_system_crontab() {
        let cmd = CronAnalysisCommandBuilder::build_cron_analyze_command();
        assert!(cmd.contains("/etc/crontab"));
    }

    #[test]
    fn test_analyze_contains_cron_d() {
        let cmd = CronAnalysisCommandBuilder::build_cron_analyze_command();
        assert!(cmd.contains("/etc/cron.d/"));
    }

    #[test]
    fn test_analyze_contains_journal() {
        let cmd = CronAnalysisCommandBuilder::build_cron_analyze_command();
        assert!(cmd.contains("journalctl"));
    }

    #[test]
    fn test_analyze_contains_overlap_detection() {
        let cmd = CronAnalysisCommandBuilder::build_cron_analyze_command();
        assert!(cmd.contains("uniq -d"));
    }

    #[test]
    fn test_analyze_contains_syslog_fallback() {
        let cmd = CronAnalysisCommandBuilder::build_cron_analyze_command();
        assert!(cmd.contains("/var/log/syslog"));
    }

    // ============== build_cron_history_command ==============

    #[test]
    fn test_history_defaults() {
        let cmd = CronAnalysisCommandBuilder::build_cron_history_command(None, None).unwrap();
        assert!(cmd.contains("-n 100"));
        assert!(cmd.contains("journalctl"));
    }

    #[test]
    fn test_history_custom_lines() {
        let cmd = CronAnalysisCommandBuilder::build_cron_history_command(Some(50), None).unwrap();
        assert!(cmd.contains("-n 50"));
    }

    #[test]
    fn test_history_with_since() {
        let cmd =
            CronAnalysisCommandBuilder::build_cron_history_command(None, Some("24 hours ago"))
                .unwrap();
        assert!(cmd.contains("--since '24 hours ago'"));
    }

    #[test]
    fn test_history_since_injection() {
        let cmd = CronAnalysisCommandBuilder::build_cron_history_command(
            None,
            Some("'; rm -rf /; echo '"),
        )
        .unwrap();
        // Should be shell-escaped
        assert!(cmd.contains("--since"));
        assert!(!cmd.contains("; rm -rf /; echo"));
    }

    #[test]
    fn test_history_syslog_fallback() {
        let cmd = CronAnalysisCommandBuilder::build_cron_history_command(None, None).unwrap();
        assert!(cmd.contains("/var/log/syslog"));
    }

    #[test]
    fn test_history_lines_too_large() {
        let result = CronAnalysisCommandBuilder::build_cron_history_command(Some(5001), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_history_lines_at_limit() {
        let result = CronAnalysisCommandBuilder::build_cron_history_command(Some(5000), None);
        assert!(result.is_ok());
    }

    // ============== build_at_jobs_command ==============

    #[test]
    fn test_at_jobs_contains_atq() {
        let cmd = CronAnalysisCommandBuilder::build_at_jobs_command();
        assert!(cmd.contains("atq"));
    }

    #[test]
    fn test_at_jobs_contains_at_c() {
        let cmd = CronAnalysisCommandBuilder::build_at_jobs_command();
        assert!(cmd.contains("at -c"));
    }

    #[test]
    fn test_at_jobs_contains_headers() {
        let cmd = CronAnalysisCommandBuilder::build_at_jobs_command();
        assert!(cmd.contains("Pending At Jobs"));
        assert!(cmd.contains("At Job Details"));
    }

    // ============== validate_cron_lines ==============

    #[test]
    fn test_validate_cron_lines_none() {
        assert!(validate_cron_lines(None).is_ok());
    }

    #[test]
    fn test_validate_cron_lines_valid() {
        assert!(validate_cron_lines(Some(100)).is_ok());
        assert!(validate_cron_lines(Some(5000)).is_ok());
    }

    #[test]
    fn test_validate_cron_lines_too_large() {
        assert!(validate_cron_lines(Some(5001)).is_err());
    }

    #[test]
    fn test_validate_cron_lines_error_message() {
        let result = validate_cron_lines(Some(10000));
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("5000"));
                assert!(reason.contains("10000"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }
}
