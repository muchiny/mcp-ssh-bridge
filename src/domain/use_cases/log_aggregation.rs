//! Log Aggregation Command Builder
//!
//! Builds log search, aggregation, and tail commands for multi-host
//! log analysis via SSH.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

const DEFAULT_LOG_FILES: &str = "/var/log/syslog /var/log/messages /var/log/auth.log";
const MAX_TAIL_LINES: u64 = 5000;

/// Validate a grep pattern for safety.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the pattern is empty or contains
/// newline characters.
pub fn validate_pattern(pattern: &str) -> Result<()> {
    if pattern.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Search pattern must not be empty".to_string(),
        });
    }
    if pattern.contains('\n') || pattern.contains('\r') {
        return Err(BridgeError::CommandDenied {
            reason: "Search pattern must not contain newlines".to_string(),
        });
    }
    if pattern.len() > 1000 {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Search pattern too long: {} chars (max 1000)",
                pattern.len()
            ),
        });
    }
    Ok(())
}

/// Validate the number of tail lines.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the line count exceeds the maximum.
pub fn validate_lines(lines: u64) -> Result<()> {
    if lines == 0 {
        return Err(BridgeError::CommandDenied {
            reason: "Line count must be at least 1".to_string(),
        });
    }
    if lines > MAX_TAIL_LINES {
        return Err(BridgeError::CommandDenied {
            reason: format!("Line count {lines} exceeds maximum of {MAX_TAIL_LINES}"),
        });
    }
    Ok(())
}

/// Builds log aggregation commands for remote execution.
pub struct LogAggregationCommandBuilder;

impl LogAggregationCommandBuilder {
    /// Build a command to search logs for a pattern.
    ///
    /// Uses `journalctl --grep` when available, falling back to `grep -r`.
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern is invalid.
    pub fn build_log_search_command(
        pattern: &str,
        log_files: Option<&str>,
        since: Option<&str>,
    ) -> Result<String> {
        validate_pattern(pattern)?;

        let files = log_files.unwrap_or(DEFAULT_LOG_FILES);
        let escaped_pattern = shell_escape(pattern);

        let mut journal_cmd = format!(
            "journalctl --no-pager -q --grep {escaped_pattern}"
        );
        if let Some(since_val) = since {
            journal_cmd = format!(
                "{journal_cmd} --since {}",
                shell_escape(since_val)
            );
        }

        Ok(format!(
            "{journal_cmd} 2>/dev/null || grep -r {escaped_pattern} {files} 2>/dev/null | tail -100"
        ))
    }

    /// Build a command to aggregate log statistics.
    ///
    /// Counts total lines, error lines, and warning lines across log files.
    #[must_use]
    pub fn build_log_aggregate_command(log_files: Option<&str>) -> String {
        let files = log_files.unwrap_or(DEFAULT_LOG_FILES);
        format!(
            "echo '=== Log Aggregation ===' && \
             for f in {files}; do \
               if [ -f \"$f\" ]; then \
                 total=$(wc -l < \"$f\" 2>/dev/null || echo 0); \
                 errors=$(grep -ci 'error' \"$f\" 2>/dev/null || echo 0); \
                 warnings=$(grep -ci 'warn' \"$f\" 2>/dev/null || echo 0); \
                 echo \"$f: total=$total errors=$errors warnings=$warnings\"; \
               fi; \
             done"
        )
    }

    /// Build a command to tail log files.
    ///
    /// # Errors
    ///
    /// Returns an error if the line count is invalid.
    pub fn build_log_tail_command(
        log_files: Option<&str>,
        lines: Option<u64>,
    ) -> Result<String> {
        let n = lines.unwrap_or(50);
        validate_lines(n)?;

        let files = log_files.unwrap_or(DEFAULT_LOG_FILES);
        Ok(format!("tail -n {n} {files} 2>/dev/null"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_pattern ─────────────────────────────────────

    #[test]
    fn test_validate_pattern_valid() {
        assert!(validate_pattern("error").is_ok());
        assert!(validate_pattern("ERROR|WARN").is_ok());
        assert!(validate_pattern("connection refused").is_ok());
    }

    #[test]
    fn test_validate_pattern_empty() {
        let err = validate_pattern("").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("empty"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_pattern_newline() {
        assert!(validate_pattern("line1\nline2").is_err());
        assert!(validate_pattern("line1\rline2").is_err());
    }

    #[test]
    fn test_validate_pattern_too_long() {
        let long = "x".repeat(1001);
        let err = validate_pattern(&long).unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("too long"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_pattern_max_length_ok() {
        let exact = "x".repeat(1000);
        assert!(validate_pattern(&exact).is_ok());
    }

    // ── validate_lines ───────────────────────────────────────

    #[test]
    fn test_validate_lines_valid() {
        assert!(validate_lines(1).is_ok());
        assert!(validate_lines(100).is_ok());
        assert!(validate_lines(5000).is_ok());
    }

    #[test]
    fn test_validate_lines_zero() {
        assert!(validate_lines(0).is_err());
    }

    #[test]
    fn test_validate_lines_exceeds_max() {
        let err = validate_lines(5001).unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("5001"));
                assert!(reason.contains("5000"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── build_log_search_command ─────────────────────────────

    #[test]
    fn test_search_defaults() {
        let cmd = LogAggregationCommandBuilder::build_log_search_command(
            "error", None, None,
        )
        .unwrap();
        assert!(cmd.contains("journalctl"));
        assert!(cmd.contains("--grep 'error'"));
        assert!(cmd.contains("grep -r 'error'"));
        assert!(cmd.contains(DEFAULT_LOG_FILES));
        assert!(cmd.contains("tail -100"));
    }

    #[test]
    fn test_search_with_custom_files() {
        let cmd = LogAggregationCommandBuilder::build_log_search_command(
            "warn",
            Some("/var/log/app.log"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("/var/log/app.log"));
        assert!(!cmd.contains(DEFAULT_LOG_FILES));
    }

    #[test]
    fn test_search_with_since() {
        let cmd = LogAggregationCommandBuilder::build_log_search_command(
            "error",
            None,
            Some("1 hour ago"),
        )
        .unwrap();
        assert!(cmd.contains("--since '1 hour ago'"));
    }

    #[test]
    fn test_search_invalid_pattern() {
        let result = LogAggregationCommandBuilder::build_log_search_command("", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_search_shell_injection() {
        let cmd = LogAggregationCommandBuilder::build_log_search_command(
            "'; rm -rf /; echo '",
            None,
            None,
        )
        .unwrap();
        // Pattern should be safely escaped
        assert!(cmd.contains("'\\''"));
    }

    // ── build_log_aggregate_command ──────────────────────────

    #[test]
    fn test_aggregate_defaults() {
        let cmd = LogAggregationCommandBuilder::build_log_aggregate_command(None);
        assert!(cmd.contains("Log Aggregation"));
        assert!(cmd.contains("wc -l"));
        assert!(cmd.contains("error"));
        assert!(cmd.contains("warn"));
        assert!(cmd.contains(DEFAULT_LOG_FILES));
    }

    #[test]
    fn test_aggregate_custom_files() {
        let cmd = LogAggregationCommandBuilder::build_log_aggregate_command(
            Some("/var/log/nginx/access.log"),
        );
        assert!(cmd.contains("/var/log/nginx/access.log"));
    }

    // ── build_log_tail_command ───────────────────────────────

    #[test]
    fn test_tail_defaults() {
        let cmd = LogAggregationCommandBuilder::build_log_tail_command(None, None).unwrap();
        assert!(cmd.contains("tail -n 50"));
        assert!(cmd.contains(DEFAULT_LOG_FILES));
    }

    #[test]
    fn test_tail_custom_lines() {
        let cmd =
            LogAggregationCommandBuilder::build_log_tail_command(None, Some(200)).unwrap();
        assert!(cmd.contains("tail -n 200"));
    }

    #[test]
    fn test_tail_custom_files() {
        let cmd = LogAggregationCommandBuilder::build_log_tail_command(
            Some("/var/log/app.log"),
            None,
        )
        .unwrap();
        assert!(cmd.contains("/var/log/app.log"));
    }

    #[test]
    fn test_tail_invalid_lines() {
        let result =
            LogAggregationCommandBuilder::build_log_tail_command(None, Some(6000));
        assert!(result.is_err());
    }

    #[test]
    fn test_tail_zero_lines() {
        let result = LogAggregationCommandBuilder::build_log_tail_command(None, Some(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_tail_max_lines() {
        let cmd =
            LogAggregationCommandBuilder::build_log_tail_command(None, Some(5000)).unwrap();
        assert!(cmd.contains("tail -n 5000"));
    }
}
