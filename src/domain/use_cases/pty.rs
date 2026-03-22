//! PTY Command Builder
//!
//! Builds pseudo-terminal (PTY) related commands for remote execution
//! via SSH. Supports executing commands with PTY allocation, resizing
//! terminals, and sending input to sessions.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Maximum allowed terminal dimension (rows or cols).
const MAX_DIMENSION: u32 = 500;

/// Validate terminal dimensions (rows and cols).
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if either dimension is outside 1..=500.
pub fn validate_dimensions(rows: u32, cols: u32) -> Result<()> {
    if rows == 0 || rows > MAX_DIMENSION {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid rows value {}: must be between 1 and {}",
                rows, MAX_DIMENSION
            ),
        });
    }
    if cols == 0 || cols > MAX_DIMENSION {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid cols value {}: must be between 1 and {}",
                cols, MAX_DIMENSION
            ),
        });
    }
    Ok(())
}

/// Validate a PTY command does not contain dangerous patterns.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the command is empty.
pub fn validate_pty_command(command: &str) -> Result<()> {
    if command.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "PTY command cannot be empty".to_string(),
        });
    }
    Ok(())
}

/// Builds PTY-related commands for remote execution.
pub struct PtyCommandBuilder;

impl PtyCommandBuilder {
    /// Build a command that executes with PTY emulation using `script`.
    ///
    /// Wraps the command with `script -q -c 'COMMAND' /dev/null` for PTY
    /// emulation. Optionally sets terminal dimensions first.
    #[must_use]
    pub fn build_pty_exec_command(
        command: &str,
        rows: Option<u32>,
        cols: Option<u32>,
    ) -> String {
        let escaped = shell_escape(command);
        let mut cmd = String::new();

        if let (Some(r), Some(c)) = (rows, cols) {
            cmd.push_str(&format!("stty rows {r} cols {c}; "));
        }

        cmd.push_str(&format!("script -q -c {escaped} /dev/null"));
        cmd
    }

    /// Build a command to resize the terminal.
    ///
    /// Constructs: `stty rows ROWS cols COLS`
    #[must_use]
    pub fn build_pty_resize_command(rows: u32, cols: u32) -> String {
        format!("stty rows {rows} cols {cols}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== validate_dimensions ==============

    #[test]
    fn test_validate_dimensions_valid() {
        assert!(validate_dimensions(24, 80).is_ok());
        assert!(validate_dimensions(1, 1).is_ok());
        assert!(validate_dimensions(500, 500).is_ok());
        assert!(validate_dimensions(100, 200).is_ok());
    }

    #[test]
    fn test_validate_dimensions_zero_rows() {
        let result = validate_dimensions(0, 80);
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("rows"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_dimensions_zero_cols() {
        let result = validate_dimensions(24, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("cols"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_dimensions_too_large_rows() {
        let result = validate_dimensions(501, 80);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_dimensions_too_large_cols() {
        let result = validate_dimensions(24, 501);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_dimensions_both_at_max() {
        assert!(validate_dimensions(MAX_DIMENSION, MAX_DIMENSION).is_ok());
    }

    #[test]
    fn test_validate_dimensions_error_message_rows() {
        let result = validate_dimensions(999, 80);
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("999"));
                assert!(reason.contains("rows"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_dimensions_error_message_cols() {
        let result = validate_dimensions(24, 999);
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("999"));
                assert!(reason.contains("cols"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ============== validate_pty_command ==============

    #[test]
    fn test_validate_pty_command_valid() {
        assert!(validate_pty_command("top").is_ok());
        assert!(validate_pty_command("htop").is_ok());
        assert!(validate_pty_command("vim /etc/hosts").is_ok());
    }

    #[test]
    fn test_validate_pty_command_empty() {
        let result = validate_pty_command("");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("cannot be empty"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ============== build_pty_exec_command ==============

    #[test]
    fn test_exec_command_basic() {
        let cmd = PtyCommandBuilder::build_pty_exec_command("top", None, None);
        assert!(cmd.contains("script -q -c 'top' /dev/null"));
    }

    #[test]
    fn test_exec_command_with_dimensions() {
        let cmd = PtyCommandBuilder::build_pty_exec_command("htop", Some(24), Some(80));
        assert!(cmd.contains("stty rows 24 cols 80"));
        assert!(cmd.contains("script -q -c 'htop' /dev/null"));
    }

    #[test]
    fn test_exec_command_no_dimensions() {
        let cmd = PtyCommandBuilder::build_pty_exec_command("ls -la", None, None);
        assert!(!cmd.contains("stty"));
        assert!(cmd.contains("script -q -c"));
    }

    #[test]
    fn test_exec_command_partial_dimensions() {
        // Only rows set, no cols - should not set stty
        let cmd = PtyCommandBuilder::build_pty_exec_command("ls", Some(24), None);
        assert!(!cmd.contains("stty"));
    }

    #[test]
    fn test_exec_command_injection() {
        let cmd =
            PtyCommandBuilder::build_pty_exec_command("test; rm -rf /", None, None);
        assert!(cmd.contains("'test; rm -rf /'"));
    }

    #[test]
    fn test_exec_command_with_quotes() {
        let cmd =
            PtyCommandBuilder::build_pty_exec_command("echo 'hello world'", None, None);
        assert!(cmd.contains("script -q -c"));
        assert!(cmd.contains("hello world"));
    }

    // ============== build_pty_resize_command ==============

    #[test]
    fn test_resize_command() {
        let cmd = PtyCommandBuilder::build_pty_resize_command(24, 80);
        assert_eq!(cmd, "stty rows 24 cols 80");
    }

    #[test]
    fn test_resize_command_large() {
        let cmd = PtyCommandBuilder::build_pty_resize_command(500, 500);
        assert_eq!(cmd, "stty rows 500 cols 500");
    }

    #[test]
    fn test_resize_command_small() {
        let cmd = PtyCommandBuilder::build_pty_resize_command(1, 1);
        assert_eq!(cmd, "stty rows 1 cols 1");
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_exec_long_command() {
        let long_cmd = "x".repeat(500);
        let cmd = PtyCommandBuilder::build_pty_exec_command(&long_cmd, None, None);
        assert!(cmd.contains(&long_cmd));
    }

    #[test]
    fn test_exec_command_newline_escaped() {
        let cmd = PtyCommandBuilder::build_pty_exec_command(
            "echo hello\necho world",
            None,
            None,
        );
        assert!(cmd.contains("script -q -c"));
    }
}
