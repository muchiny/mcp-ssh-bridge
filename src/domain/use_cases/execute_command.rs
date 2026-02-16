//! Execute Command Use Case
//!
//! This use case orchestrates the execution of SSH commands,
//! handling validation, execution, sanitization, and auditing.

use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

use crate::domain::CommandHistory;
use crate::error::Result;
use crate::ports::CommandOutput;
use crate::security::{AuditEvent, AuditLogger, CommandResult, CommandValidator, Sanitizer};

/// Request for executing a command
#[derive(Debug, Clone)]
pub struct ExecuteCommandRequest {
    pub host: String,
    pub command: String,
    pub timeout: Duration,
    pub working_dir: Option<String>,
}

/// Response from command execution
#[derive(Debug, Clone)]
pub struct ExecuteCommandResponse {
    pub output: String,
    pub exit_code: u32,
    pub duration_ms: u64,
}

/// Use case for executing SSH commands
///
/// This use case coordinates between the various components to:
/// 1. Validate the command against security rules
/// 2. Execute the command via SSH
/// 3. Sanitize the output
/// 4. Log the audit event
/// 5. Record in history
pub struct ExecuteCommandUseCase {
    validator: Arc<CommandValidator>,
    sanitizer: Arc<Sanitizer>,
    audit_logger: Arc<AuditLogger>,
    history: Arc<CommandHistory>,
}

impl ExecuteCommandUseCase {
    pub const fn new(
        validator: Arc<CommandValidator>,
        sanitizer: Arc<Sanitizer>,
        audit_logger: Arc<AuditLogger>,
        history: Arc<CommandHistory>,
    ) -> Self {
        Self {
            validator,
            sanitizer,
            audit_logger,
            history,
        }
    }

    /// Validate a command against security rules
    ///
    /// # Errors
    ///
    /// Returns an error if the command is denied by security rules (blacklist match or
    /// not in whitelist when in strict/standard mode).
    pub fn validate(&self, command: &str) -> Result<()> {
        self.validator.validate(command)
    }

    /// Validate a command from a trusted built-in tool handler
    ///
    /// Only checks blacklist, skips whitelist validation. Used by specialized
    /// tool handlers that construct commands via trusted domain command builders.
    ///
    /// # Errors
    ///
    /// Returns an error if the command is denied by blacklist rules.
    pub fn validate_builtin(&self, command: &str) -> Result<()> {
        self.validator.validate_builtin(command)
    }

    /// Log a denied command
    pub fn log_denied(&self, host: &str, command: &str, reason: &str) {
        self.audit_logger
            .log(AuditEvent::denied(host, command, reason));
    }

    /// Process the output from a successful command execution
    #[must_use]
    pub fn process_success(
        &self,
        host: &str,
        command: &str,
        output: &CommandOutput,
    ) -> ExecuteCommandResponse {
        // Log successful execution
        self.audit_logger.log(AuditEvent::new(
            host,
            command,
            CommandResult::Success {
                exit_code: output.exit_code,
                duration_ms: output.duration_ms,
            },
        ));

        // Record in history
        self.history
            .record_success(host, command, output.exit_code, output.duration_ms);

        // Format and sanitize the result
        let result = Self::format_output(host, command, output);
        let sanitized = self.sanitizer.sanitize(&result).into_owned();

        ExecuteCommandResponse {
            output: sanitized,
            exit_code: output.exit_code,
            duration_ms: output.duration_ms,
        }
    }

    /// Log a failed command execution
    pub fn log_failure(&self, host: &str, command: &str, error: &str) {
        self.audit_logger.log(AuditEvent::new(
            host,
            command,
            CommandResult::Error {
                message: error.to_string(),
            },
        ));

        self.history.record_failure(host, command);
    }

    /// Format command output for display
    fn format_output(host: &str, command: &str, output: &CommandOutput) -> String {
        let mut result = String::new();
        let exit_code = output.exit_code;
        let duration_ms = output.duration_ms;

        let _ = writeln!(result, "Host: {host}");
        let _ = writeln!(result, "Command: {command}");
        let _ = writeln!(result, "Exit code: {exit_code}");
        let _ = writeln!(result, "Duration: {duration_ms}ms");
        let _ = writeln!(result, "\n--- STDOUT ---");
        result.push_str(&output.stdout);

        if !output.stderr.is_empty() {
            let _ = writeln!(result, "\n--- STDERR ---");
            result.push_str(&output.stderr);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityMode;
    use crate::domain::HistoryConfig;
    use crate::security::CommandValidator;

    fn create_test_use_case() -> ExecuteCommandUseCase {
        let security_config = crate::config::SecurityConfig::default();

        ExecuteCommandUseCase::new(
            Arc::new(CommandValidator::new(&security_config)),
            Arc::new(Sanitizer::with_defaults()),
            Arc::new(AuditLogger::disabled()),
            Arc::new(CommandHistory::new(&HistoryConfig::default())),
        )
    }

    fn create_permissive_use_case() -> ExecuteCommandUseCase {
        let security_config = crate::config::SecurityConfig {
            mode: SecurityMode::Permissive,
            ..Default::default()
        };

        ExecuteCommandUseCase::new(
            Arc::new(CommandValidator::new(&security_config)),
            Arc::new(Sanitizer::with_defaults()),
            Arc::new(AuditLogger::disabled()),
            Arc::new(CommandHistory::new(&HistoryConfig::default())),
        )
    }

    #[test]
    fn test_validate_command() {
        let use_case = create_test_use_case();

        // In strict mode with empty whitelist, commands should be denied
        assert!(use_case.validate("ls -la").is_err());
    }

    #[test]
    fn test_validate_command_permissive() {
        let use_case = create_permissive_use_case();

        // In permissive mode, commands should be allowed
        assert!(use_case.validate("ls -la").is_ok());
        assert!(use_case.validate("echo hello").is_ok());
    }

    #[test]
    fn test_format_output() {
        let output = CommandOutput {
            stdout: "file1.txt\nfile2.txt\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 100,
        };

        let formatted = ExecuteCommandUseCase::format_output("test-host", "ls", &output);

        assert!(formatted.contains("Host: test-host"));
        assert!(formatted.contains("Command: ls"));
        assert!(formatted.contains("Exit code: 0"));
        assert!(formatted.contains("Duration: 100ms"));
        assert!(formatted.contains("file1.txt"));
        assert!(formatted.contains("--- STDOUT ---"));
    }

    #[test]
    fn test_format_output_with_stderr() {
        let output = CommandOutput {
            stdout: "output".to_string(),
            stderr: "warning: something".to_string(),
            exit_code: 0,
            duration_ms: 50,
        };

        let formatted = ExecuteCommandUseCase::format_output("host", "cmd", &output);

        assert!(formatted.contains("--- STDOUT ---"));
        assert!(formatted.contains("--- STDERR ---"));
        assert!(formatted.contains("warning: something"));
    }

    #[test]
    fn test_format_output_empty_stdout() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        let formatted = ExecuteCommandUseCase::format_output("host", "true", &output);

        assert!(formatted.contains("Host: host"));
        assert!(formatted.contains("Exit code: 0"));
        assert!(formatted.contains("--- STDOUT ---"));
        assert!(!formatted.contains("--- STDERR ---")); // No stderr section for empty stderr
    }

    #[test]
    fn test_format_output_nonzero_exit() {
        let output = CommandOutput {
            stdout: String::new(),
            stderr: "command not found".to_string(),
            exit_code: 127,
            duration_ms: 5,
        };

        let formatted = ExecuteCommandUseCase::format_output("host", "nonexistent", &output);

        assert!(formatted.contains("Exit code: 127"));
        assert!(formatted.contains("command not found"));
    }

    #[test]
    fn test_process_success() {
        let use_case = create_test_use_case();

        let output = CommandOutput {
            stdout: "password=secret123".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 50,
        };

        let response = use_case.process_success("host", "echo test", &output);

        // Password should be sanitized
        assert!(!response.output.contains("secret123"));
        assert!(response.output.contains("[REDACTED]"));
        assert_eq!(response.exit_code, 0);
        assert_eq!(response.duration_ms, 50);
    }

    #[test]
    fn test_process_success_with_api_key() {
        let use_case = create_test_use_case();

        // GitHub PAT pattern: ghp_ followed by exactly 36 alphanumeric chars
        let token = "ghp_1234567890abcdefGHIJKLmnopqrstuvwxyz";
        let output = CommandOutput {
            stdout: format!("GITHUB_TOKEN={token}"),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        let response = use_case.process_success("host", "env", &output);

        // GitHub token should be sanitized
        assert!(!response.output.contains(token));
    }

    #[test]
    fn test_process_success_nonzero_exit() {
        let use_case = create_test_use_case();

        let output = CommandOutput {
            stdout: String::new(),
            stderr: "Error occurred".to_string(),
            exit_code: 1,
            duration_ms: 100,
        };

        let response = use_case.process_success("host", "failing_cmd", &output);

        assert_eq!(response.exit_code, 1);
        assert!(response.output.contains("Error occurred"));
    }

    #[test]
    fn test_log_denied_does_not_panic() {
        let use_case = create_test_use_case();

        // Should not panic even with disabled logger
        use_case.log_denied("host1", "rm -rf /", "blacklisted");
        use_case.log_denied("host2", "dangerous_command", "not in whitelist");
    }

    #[test]
    fn test_log_failure_does_not_panic() {
        let use_case = create_test_use_case();

        // Should not panic even with disabled logger
        use_case.log_failure("host1", "ls", "connection timeout");
        use_case.log_failure("host2", "pwd", "network error");
    }

    #[test]
    fn test_execute_command_request_clone() {
        let req = ExecuteCommandRequest {
            host: "test".to_string(),
            command: "ls".to_string(),
            timeout: Duration::from_secs(30),
            working_dir: Some("/tmp".to_string()),
        };

        let cloned = req.clone();
        assert_eq!(req.host, cloned.host);
        assert_eq!(req.command, cloned.command);
        assert_eq!(req.timeout, cloned.timeout);
        assert_eq!(req.working_dir, cloned.working_dir);
    }

    #[test]
    fn test_execute_command_request_debug() {
        let req = ExecuteCommandRequest {
            host: "test".to_string(),
            command: "ls".to_string(),
            timeout: Duration::from_secs(30),
            working_dir: None,
        };

        let debug_str = format!("{req:?}");
        assert!(debug_str.contains("ExecuteCommandRequest"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_execute_command_response_clone() {
        let resp = ExecuteCommandResponse {
            output: "result".to_string(),
            exit_code: 0,
            duration_ms: 100,
        };

        let cloned = resp.clone();
        assert_eq!(resp.output, cloned.output);
        assert_eq!(resp.exit_code, cloned.exit_code);
        assert_eq!(resp.duration_ms, cloned.duration_ms);
    }

    #[test]
    fn test_execute_command_response_debug() {
        let resp = ExecuteCommandResponse {
            output: "result".to_string(),
            exit_code: 42,
            duration_ms: 100,
        };

        let debug_str = format!("{resp:?}");
        assert!(debug_str.contains("ExecuteCommandResponse"));
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn test_format_output_unicode() {
        let output = CommandOutput {
            stdout: "日本語テスト\n中文输出\n🎉".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        let formatted = ExecuteCommandUseCase::format_output("host", "echo", &output);

        assert!(formatted.contains("日本語テスト"));
        assert!(formatted.contains("中文输出"));
        assert!(formatted.contains("🎉"));
    }

    #[test]
    fn test_format_output_long_command() {
        let output = CommandOutput {
            stdout: "ok".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        let long_cmd = "find / -name '*.log' -exec grep -l 'error' {} \\; | head -n 100";
        let formatted = ExecuteCommandUseCase::format_output("host", long_cmd, &output);

        assert!(formatted.contains(long_cmd));
    }

    #[test]
    fn test_format_output_special_chars() {
        let output = CommandOutput {
            stdout: "line1\tline2\rline3\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 10,
        };

        let formatted = ExecuteCommandUseCase::format_output("host", "cmd", &output);

        assert!(formatted.contains("line1\t"));
        assert!(formatted.contains("\rline3"));
    }
}
