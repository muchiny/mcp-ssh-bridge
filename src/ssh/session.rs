//! SSH Session Manager
//!
//! Manages persistent interactive SSH shell sessions that maintain state
//! (working directory, environment variables) across multiple command executions.
//!
//! Each session owns a dedicated SSH connection and an interactive shell channel.
//! Commands are sent through the shell's stdin and output is read until a unique
//! marker appears, enabling reliable output delimiting.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use russh::ChannelMsg;
use serde::Serialize;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::{HostConfig, LimitsConfig, SessionConfig, ShellType};
use crate::error::{BridgeError, Result};

use super::client::SshClient;

/// Marker prefix used to delimit command output in interactive shells
const MARKER_PREFIX: &str = "---SSHB_";

/// Active shell session with a persistent channel
struct ShellSession {
    id: String,
    host: String,
    shell: ShellType,
    channel: russh::Channel<russh::client::Msg>,
    client: SshClient,
    cwd: String,
    created_at: Instant,
    last_used: Instant,
}

/// Session information returned by list operations
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub host: String,
    pub cwd: String,
    pub created_at_secs_ago: u64,
    pub last_used_secs_ago: u64,
}

/// Result of executing a command in a session
#[derive(Debug, Clone, Serialize)]
pub struct SessionExecResult {
    pub session_id: String,
    pub output: String,
    pub exit_code: u32,
    pub cwd: String,
}

/// Manages persistent SSH shell sessions
pub struct SessionManager {
    sessions: Mutex<HashMap<String, ShellSession>>,
    config: SessionConfig,
}

impl SessionManager {
    /// Create a new session manager
    #[must_use]
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Create a new interactive shell session on the specified host
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The maximum number of sessions has been reached
    /// - SSH connection to the host fails
    /// - Opening a shell channel fails
    pub async fn create(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        limits: &LimitsConfig,
        jump_host: Option<(&str, &HostConfig)>,
    ) -> Result<SessionInfo> {
        // Check session limit before connecting
        {
            let sessions = self.sessions.lock().await;
            if sessions.len() >= self.config.max_sessions {
                tracing::error!(
                    host = %host_name,
                    current = sessions.len(),
                    max = self.config.max_sessions,
                    "Session limit reached"
                );
                return Err(BridgeError::TooManySessions {
                    max: self.config.max_sessions,
                });
            }
        }

        let session_id = Uuid::new_v4().to_string();

        // Create a dedicated SSH connection (not from pool)
        let client = if let Some((jump_name, jump_config)) = jump_host {
            SshClient::connect_via_jump(host_name, host_config, jump_name, jump_config, limits)
                .await?
        } else {
            SshClient::connect(host_name, host_config, limits).await?
        };

        // Open interactive shell channel
        let mut channel = client.open_shell().await?;

        // Derive the effective shell for this host
        let shell = host_config.effective_shell();

        // Initialize: disable echo and prompts (shell-aware)
        let init_marker = format!("{MARKER_PREFIX}INIT_{session_id}---");
        let init_cmd = Self::build_init_command(shell, &init_marker);

        channel
            .data(init_cmd.as_bytes())
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Failed to initialize shell: {e}"),
            })?;

        // Wait for init marker (consumes MOTD, bashrc output, etc.)
        Self::read_until_marker(&mut channel, &init_marker, limits.command_timeout_seconds).await?;

        // Get initial working directory (shell-aware)
        let cwd_marker = format!("{MARKER_PREFIX}CWD_{session_id}---");
        let cwd_cmd = Self::build_cwd_command(shell, &cwd_marker);

        channel
            .data(cwd_cmd.as_bytes())
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Failed to get initial cwd: {e}"),
            })?;

        let cwd_output =
            Self::read_until_marker(&mut channel, &cwd_marker, limits.command_timeout_seconds)
                .await?;

        let cwd = cwd_output.lines().last().unwrap_or("/").trim().to_string();

        let now = Instant::now();
        let info = SessionInfo {
            id: session_id.clone(),
            host: host_name.to_string(),
            cwd: cwd.clone(),
            created_at_secs_ago: 0,
            last_used_secs_ago: 0,
        };

        let session = ShellSession {
            id: session_id,
            host: host_name.to_string(),
            shell,
            channel,
            client,
            cwd,
            created_at: now,
            last_used: now,
        };

        self.sessions.lock().await.insert(info.id.clone(), session);
        info!(session_id = %info.id, host = %host_name, "Session created");

        Ok(info)
    }

    /// Execute a command in an existing session
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The session ID is not found
    /// - The session has expired (max age or idle timeout exceeded)
    /// - Sending the command to the shell fails
    /// - The command times out
    #[allow(clippy::significant_drop_tightening)]
    pub async fn exec(
        &self,
        session_id: &str,
        command: &str,
        timeout_secs: u64,
    ) -> Result<SessionExecResult> {
        let mut sessions = self.sessions.lock().await;

        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| BridgeError::SessionNotFound {
                session_id: session_id.to_string(),
            })?;

        // Check expiry
        let max_age = Duration::from_secs(self.config.max_age_seconds);
        let max_idle = Duration::from_secs(self.config.idle_timeout_seconds);

        if session.created_at.elapsed() > max_age || session.last_used.elapsed() > max_idle {
            let id = session.id.clone();
            sessions.remove(session_id);
            return Err(BridgeError::SessionExpired { session_id: id });
        }

        session.last_used = Instant::now();

        let exec_id = Uuid::new_v4().to_string();
        let begin_marker = format!("{MARKER_PREFIX}B_{exec_id}---");
        let end_marker = format!("{MARKER_PREFIX}E_{exec_id}---");

        // Send command with markers (shell-aware)
        let wrapped = Self::build_exec_wrapper(session.shell, command, &begin_marker, &end_marker);

        if let Err(e) = session.channel.data(wrapped.as_bytes()).await {
            // Channel is dead - remove and close the zombie session
            if let Some(dead_session) = sessions.remove(session_id) {
                let _ = dead_session.client.close().await;
            }
            return Err(BridgeError::SshExec {
                reason: format!("Failed to send command to session: {e}"),
            });
        }

        // Read until end marker
        let raw = match Self::read_until_marker_inclusive(
            &mut session.channel,
            &end_marker,
            timeout_secs,
        )
        .await
        {
            Ok(output) => output,
            Err(e) => {
                // Shell is dead - remove and close the zombie session
                if let Some(dead_session) = sessions.remove(session_id) {
                    let _ = dead_session.client.close().await;
                }
                return Err(e);
            }
        };

        // Parse output
        let (output, exit_code, new_cwd) = Self::parse_exec_output(&raw, &begin_marker);

        session.cwd.clone_from(&new_cwd);

        debug!(
            session_id = %session_id,
            exit_code = exit_code,
            cwd = %new_cwd,
            "Session command executed"
        );

        Ok(SessionExecResult {
            session_id: session_id.to_string(),
            output,
            exit_code,
            cwd: new_cwd,
        })
    }

    /// List all active sessions
    pub async fn list(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.lock().await;
        sessions
            .values()
            .map(|s| SessionInfo {
                id: s.id.clone(),
                host: s.host.clone(),
                cwd: s.cwd.clone(),
                created_at_secs_ago: s.created_at.elapsed().as_secs(),
                last_used_secs_ago: s.last_used.elapsed().as_secs(),
            })
            .collect()
    }

    /// Get the host alias associated with a session
    pub async fn get_session_host(&self, session_id: &str) -> Option<String> {
        let sessions = self.sessions.lock().await;
        sessions.get(session_id).map(|s| s.host.clone())
    }

    /// Close a specific session
    ///
    /// # Errors
    ///
    /// Returns an error if the session ID is not found.
    pub async fn close(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().await;

        if let Some(session) = sessions.remove(session_id) {
            let _ = session.client.close().await;
            info!(session_id = %session_id, "Session closed");
            Ok(())
        } else {
            Err(BridgeError::SessionNotFound {
                session_id: session_id.to_string(),
            })
        }
    }

    /// Close all sessions
    #[allow(clippy::significant_drop_tightening)]
    pub async fn close_all(&self) {
        let mut sessions = self.sessions.lock().await;
        let count = sessions.len();
        let drained: Vec<_> = sessions.drain().collect();
        drop(sessions); // Release lock before closing connections
        for (_, session) in drained {
            let _ = session.client.close().await;
        }
        if count > 0 {
            info!(count = count, "All sessions closed");
        }
    }

    /// Clean up expired sessions
    #[allow(clippy::significant_drop_tightening)]
    pub async fn cleanup(&self) {
        let mut sessions = self.sessions.lock().await;
        let max_idle = Duration::from_secs(self.config.idle_timeout_seconds);
        let max_age = Duration::from_secs(self.config.max_age_seconds);

        let before = sessions.len();
        sessions.retain(|id, s| {
            let keep = s.last_used.elapsed() <= max_idle && s.created_at.elapsed() <= max_age;
            if !keep {
                debug!(session_id = %id, host = %s.host, "Cleaning up expired session");
            }
            keep
        });
        let after = sessions.len();

        if before != after {
            info!(
                expired = before - after,
                remaining = after,
                "Cleaned up expired sessions"
            );
        }
    }

    /// Build the shell initialization command that disables echo and prompts.
    fn build_init_command(shell: ShellType, marker: &str) -> String {
        match shell {
            ShellType::Posix => format!(
                "stty -echo 2>/dev/null; unset PROMPT_COMMAND; \
                 export PS1='' PS2='' PS3='' PS4=''; \
                 echo \"{marker}\"\n"
            ),
            ShellType::Cmd => format!("@echo off\r\nprompt $S\r\necho {marker}\r\n"),
            ShellType::PowerShell => format!(
                "function prompt {{''}}; \
                 $ProgressPreference='SilentlyContinue'; \
                 Write-Host '{marker}'\n"
            ),
        }
    }

    /// Build the command to retrieve the current working directory.
    fn build_cwd_command(shell: ShellType, marker: &str) -> String {
        match shell {
            ShellType::Posix => format!("pwd\necho \"{marker}\"\n"),
            ShellType::Cmd => format!("cd\r\necho {marker}\r\n"),
            ShellType::PowerShell => format!("(Get-Location).Path\nWrite-Host '{marker}'\n"),
        }
    }

    /// Build the exec wrapper that captures exit code and cwd after a command.
    fn build_exec_wrapper(
        shell: ShellType,
        command: &str,
        begin_marker: &str,
        end_marker: &str,
    ) -> String {
        match shell {
            ShellType::Posix => format!(
                "{command}\n\
                 __sshb_rc=$?\n\
                 echo \"{begin_marker}\"\n\
                 echo $__sshb_rc\n\
                 pwd\n\
                 echo \"{end_marker}\"\n"
            ),
            ShellType::Cmd => format!(
                "{command}\r\n\
                 echo {begin_marker}\r\n\
                 echo %ERRORLEVEL%\r\n\
                 cd\r\n\
                 echo {end_marker}\r\n"
            ),
            ShellType::PowerShell => format!(
                "{command}\n\
                 $__sshb_rc = $LASTEXITCODE; if ($null -eq $__sshb_rc) {{ $__sshb_rc = 0 }}\n\
                 Write-Host '{begin_marker}'\n\
                 Write-Host $__sshb_rc\n\
                 (Get-Location).Path\n\
                 Write-Host '{end_marker}'\n"
            ),
        }
    }

    /// Read channel output until a specific marker string appears.
    ///
    /// Returns everything before the line containing the marker.
    async fn read_until_marker(
        channel: &mut russh::Channel<russh::client::Msg>,
        marker: &str,
        timeout_secs: u64,
    ) -> Result<String> {
        let raw = Self::read_until_marker_inclusive(channel, marker, timeout_secs).await?;

        // Return everything before the marker line
        if let Some(pos) = raw.find(marker) {
            let line_start = raw[..pos].rfind('\n').map_or(0, |p| p + 1);
            Ok(raw[..line_start].to_string())
        } else {
            Ok(raw)
        }
    }

    /// Read channel output until a specific marker string appears.
    ///
    /// Returns the full output including the marker line.
    async fn read_until_marker_inclusive(
        channel: &mut russh::Channel<russh::client::Msg>,
        marker: &str,
        timeout_secs: u64,
    ) -> Result<String> {
        let mut output = String::new();
        let deadline = Duration::from_secs(timeout_secs);

        let result = timeout(deadline, async {
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => {
                        output.push_str(&String::from_utf8_lossy(&data));
                        if output.contains(marker) {
                            return Ok(());
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        // stderr - include in output
                        output.push_str(&String::from_utf8_lossy(&data));
                        if output.contains(marker) {
                            return Ok(());
                        }
                    }
                    Some(ChannelMsg::Eof) | None => {
                        return Err(BridgeError::SshExec {
                            reason: "Shell session closed unexpectedly".to_string(),
                        });
                    }
                    _ => {}
                }
            }
        })
        .await;

        match result {
            Ok(Ok(())) => Ok(output),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(BridgeError::SshTimeout {
                seconds: timeout_secs,
            }),
        }
    }

    /// Parse exec output to extract command output, exit code, and new cwd
    ///
    /// Expected format in `raw`:
    /// ```text
    /// {command output}
    /// {begin_marker}
    /// {exit_code}
    /// {cwd}
    /// {end_marker}  (may or may not be present)
    /// ```
    #[allow(clippy::option_if_let_else)]
    fn parse_exec_output(raw: &str, begin_marker: &str) -> (String, u32, String) {
        if let Some(begin_pos) = raw.find(begin_marker) {
            // Command output is everything before the begin marker line
            let line_start = raw[..begin_pos].rfind('\n').map_or(0, |p| p + 1);
            let command_output = raw[..line_start].trim_end().to_string();

            // After begin marker: exit code and cwd
            let after_begin = begin_pos + begin_marker.len();
            let metadata = raw[after_begin..].trim();
            let mut lines = metadata.lines();

            let exit_code: u32 = lines
                .next()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(1);

            let cwd = lines
                .next()
                .map_or_else(|| "/".to_string(), |s| s.trim().to_string());

            (command_output, exit_code, cwd)
        } else {
            // Fallback: couldn't find begin marker, return raw output with error
            warn!("Could not find begin marker in session output");
            (raw.to_string(), 1, "/".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_exec_output_basic() {
        let begin = "---SSHB_B_test123---";
        let raw = format!("hello world\nline 2\n{begin}\n0\n/home/user\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "hello world\nline 2");
        assert_eq!(exit_code, 0);
        assert_eq!(cwd, "/home/user");
    }

    #[test]
    fn test_parse_exec_output_nonzero_exit() {
        let begin = "---SSHB_B_test456---";
        let raw = format!("error output\n{begin}\n127\n/tmp\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "error output");
        assert_eq!(exit_code, 127);
        assert_eq!(cwd, "/tmp");
    }

    #[test]
    fn test_parse_exec_output_empty_output() {
        let begin = "---SSHB_B_test789---";
        let raw = format!("{begin}\n0\n/root\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "");
        assert_eq!(exit_code, 0);
        assert_eq!(cwd, "/root");
    }

    #[test]
    fn test_parse_exec_output_multiline() {
        let begin = "---SSHB_B_multi---";
        let raw = format!("line 1\nline 2\nline 3\n{begin}\n0\n/var/log\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "line 1\nline 2\nline 3");
        assert_eq!(exit_code, 0);
        assert_eq!(cwd, "/var/log");
    }

    #[test]
    fn test_parse_exec_output_missing_marker() {
        let (output, exit_code, cwd) =
            SessionManager::parse_exec_output("some output", "---MISSING---");
        assert_eq!(output, "some output");
        assert_eq!(exit_code, 1);
        assert_eq!(cwd, "/");
    }

    #[test]
    fn test_session_manager_creation() {
        let config = SessionConfig::default();
        let manager = SessionManager::new(config);
        drop(manager);
    }

    #[tokio::test]
    async fn test_list_empty() {
        let manager = SessionManager::new(SessionConfig::default());
        let sessions = manager.list().await;
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn test_close_nonexistent() {
        let manager = SessionManager::new(SessionConfig::default());
        let result = manager.close("nonexistent").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::SessionNotFound { session_id } => {
                assert_eq!(session_id, "nonexistent");
            }
            e => panic!("Expected SessionNotFound, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_exec_nonexistent() {
        let manager = SessionManager::new(SessionConfig::default());
        let result = manager.exec("nonexistent", "ls", 30).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::SessionNotFound { session_id } => {
                assert_eq!(session_id, "nonexistent");
            }
            e => panic!("Expected SessionNotFound, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_close_all_empty() {
        let manager = SessionManager::new(SessionConfig::default());
        manager.close_all().await;
    }

    #[tokio::test]
    async fn test_cleanup_empty() {
        let manager = SessionManager::new(SessionConfig::default());
        manager.cleanup().await;
    }

    // ============== SessionInfo Tests ==============

    #[test]
    fn test_session_info_serialization() {
        let info = SessionInfo {
            id: "test-uuid".to_string(),
            host: "server1".to_string(),
            cwd: "/home/user".to_string(),
            created_at_secs_ago: 60,
            last_used_secs_ago: 10,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test-uuid"));
        assert!(json.contains("server1"));
        assert!(json.contains("/home/user"));
    }

    #[test]
    fn test_session_info_clone() {
        let info = SessionInfo {
            id: "abc123".to_string(),
            host: "host1".to_string(),
            cwd: "/tmp".to_string(),
            created_at_secs_ago: 100,
            last_used_secs_ago: 5,
        };

        let cloned = info.clone();
        assert_eq!(cloned.id, info.id);
        assert_eq!(cloned.host, info.host);
        assert_eq!(cloned.cwd, info.cwd);
    }

    #[test]
    fn test_session_info_debug() {
        let info = SessionInfo {
            id: "debug-test".to_string(),
            host: "debug-host".to_string(),
            cwd: "/".to_string(),
            created_at_secs_ago: 0,
            last_used_secs_ago: 0,
        };

        let debug_str = format!("{info:?}");
        assert!(debug_str.contains("SessionInfo"));
        assert!(debug_str.contains("debug-test"));
    }

    // ============== SessionExecResult Tests ==============

    #[test]
    fn test_session_exec_result_serialization() {
        let result = SessionExecResult {
            session_id: "session-123".to_string(),
            output: "command output".to_string(),
            exit_code: 0,
            cwd: "/var/log".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("session-123"));
        assert!(json.contains("command output"));
        assert!(json.contains("exit_code"));
    }

    #[test]
    fn test_session_exec_result_clone() {
        let result = SessionExecResult {
            session_id: "sess1".to_string(),
            output: "hello\nworld".to_string(),
            exit_code: 127,
            cwd: "/opt".to_string(),
        };

        let cloned = result.clone();
        assert_eq!(cloned.session_id, result.session_id);
        assert_eq!(cloned.output, result.output);
        assert_eq!(cloned.exit_code, result.exit_code);
        assert_eq!(cloned.cwd, result.cwd);
    }

    #[test]
    fn test_session_exec_result_debug() {
        let result = SessionExecResult {
            session_id: "debug-session".to_string(),
            output: "test output".to_string(),
            exit_code: 1,
            cwd: "/home".to_string(),
        };

        let debug_str = format!("{result:?}");
        assert!(debug_str.contains("SessionExecResult"));
    }

    // ============== parse_exec_output Edge Cases ==============

    #[test]
    fn test_parse_exec_output_with_trailing_newlines() {
        let begin = "---SSHB_B_trail---";
        let raw = format!("output line\n\n\n{begin}\n0\n/home\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "output line");
        assert_eq!(exit_code, 0);
        assert_eq!(cwd, "/home");
    }

    #[test]
    fn test_parse_exec_output_with_windows_crlf() {
        let begin = "---SSHB_B_crlf---";
        let raw = format!("line1\r\nline2\r\n{begin}\r\n0\r\n/tmp\r\n");

        let (output, exit_code, _cwd) = SessionManager::parse_exec_output(&raw, begin);
        // Output should contain CRLF as-is
        assert!(output.contains("line1"));
        assert!(output.contains("line2"));
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_parse_exec_output_with_unicode() {
        let begin = "---SSHB_B_uni---";
        let raw = format!("日本語出力\n中文\n{begin}\n0\n/home/用户\n");

        let (output, _exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert!(output.contains("日本語出力"));
        assert!(output.contains("中文"));
        assert_eq!(cwd, "/home/用户");
    }

    #[test]
    fn test_parse_exec_output_exit_code_parse_failure() {
        let begin = "---SSHB_B_bad---";
        let raw = format!("output\n{begin}\nnot_a_number\n/tmp\n");

        let (_, exit_code, actual_cwd) = SessionManager::parse_exec_output(&raw, begin);
        // When exit code can't be parsed, default to 1
        assert_eq!(exit_code, 1);
        assert_eq!(actual_cwd, "/tmp");
    }

    #[test]
    fn test_parse_exec_output_missing_cwd() {
        let begin = "---SSHB_B_nocwd---";
        let raw = format!("output\n{begin}\n0\n");

        let (_, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(exit_code, 0);
        // When cwd is missing, default to "/"
        assert_eq!(cwd, "/");
    }

    #[test]
    fn test_parse_exec_output_empty_raw() {
        let (output, exit_code, cwd) = SessionManager::parse_exec_output("", "---MARKER---");
        assert_eq!(output, "");
        assert_eq!(exit_code, 1);
        assert_eq!(cwd, "/");
    }

    #[test]
    fn test_parse_exec_output_only_marker() {
        let begin = "---SSHB_B_only---";
        let raw = format!("{begin}\n0\n/root\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "");
        assert_eq!(exit_code, 0);
        assert_eq!(cwd, "/root");
    }

    #[test]
    fn test_parse_exec_output_special_chars_in_output() {
        let begin = "---SSHB_B_special---";
        let raw = format!("output with $VAR and `backticks` and \"quotes\"\n{begin}\n0\n/tmp\n");

        let (output, _, _) = SessionManager::parse_exec_output(&raw, begin);
        assert!(output.contains("$VAR"));
        assert!(output.contains("`backticks`"));
        assert!(output.contains("\"quotes\""));
    }

    #[test]
    fn test_parse_exec_output_very_large_exit_code() {
        let begin = "---SSHB_B_large---";
        let raw = format!("output\n{begin}\n4294967295\n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(exit_code, u32::MAX);
    }

    #[test]
    fn test_parse_exec_output_negative_exit_code() {
        let begin = "---SSHB_B_neg---";
        let raw = format!("output\n{begin}\n-1\n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        // Negative numbers should fail to parse, default to 1
        assert_eq!(exit_code, 1);
    }

    // ============== SessionManager Lifecycle Tests ==============

    #[tokio::test]
    async fn test_manager_multiple_list_calls() {
        let manager = SessionManager::new(SessionConfig::default());

        let list1 = manager.list().await;
        let list2 = manager.list().await;
        let list3 = manager.list().await;

        assert!(list1.is_empty());
        assert!(list2.is_empty());
        assert!(list3.is_empty());
    }

    #[tokio::test]
    async fn test_manager_cleanup_multiple_times() {
        let manager = SessionManager::new(SessionConfig::default());

        manager.cleanup().await;
        manager.cleanup().await;
        manager.cleanup().await;

        assert!(manager.list().await.is_empty());
    }

    #[tokio::test]
    async fn test_manager_close_all_then_list() {
        let manager = SessionManager::new(SessionConfig::default());

        manager.close_all().await;
        let list = manager.list().await;

        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn test_manager_cleanup_then_close_all() {
        let manager = SessionManager::new(SessionConfig::default());

        manager.cleanup().await;
        manager.close_all().await;

        assert!(manager.list().await.is_empty());
    }

    // ============== SessionConfig Tests ==============

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        // Verify defaults are sensible
        assert!(config.max_sessions > 0);
        assert!(config.idle_timeout_seconds > 0);
        assert!(config.max_age_seconds > 0);
    }

    // ============== Concurrent Manager Access ==============

    #[tokio::test]
    async fn test_manager_concurrent_list_calls() {
        let manager = std::sync::Arc::new(SessionManager::new(SessionConfig::default()));

        let mut handles = vec![];
        for _ in 0..10 {
            let mgr = manager.clone();
            handles.push(tokio::spawn(async move { mgr.list().await }));
        }

        for handle in handles {
            let list = handle.await.unwrap();
            assert!(list.is_empty());
        }
    }

    #[tokio::test]
    async fn test_manager_concurrent_close_nonexistent() {
        let manager = std::sync::Arc::new(SessionManager::new(SessionConfig::default()));

        let mut handles = vec![];
        for i in 0..5 {
            let mgr = manager.clone();
            let id = format!("nonexistent-{i}");
            handles.push(tokio::spawn(async move { mgr.close(&id).await }));
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_err());
        }
    }

    // ============== parse_exec_output Additional Edge Cases ==============

    #[test]
    fn test_parse_exec_output_marker_at_start() {
        let begin = "---SSHB_B_start---";
        let raw = format!("{begin}\n0\n/home\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output, "");
        assert_eq!(exit_code, 0);
        assert_eq!(cwd, "/home");
    }

    #[test]
    fn test_parse_exec_output_very_long_output() {
        let begin = "---SSHB_B_long---";
        let long_output = "x".repeat(100_000);
        let raw = format!("{long_output}\n{begin}\n0\n/tmp\n");

        let (output, exit_code, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(output.len(), 100_000);
        assert_eq!(exit_code, 0);
        assert_eq!(cwd, "/tmp");
    }

    #[test]
    fn test_parse_exec_output_binary_garbage() {
        let begin = "---SSHB_B_bin---";
        let raw = format!("\x00\x01\x02output\n{begin}\n0\n/bin\n");

        let (output, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        assert!(output.contains("output"));
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_parse_exec_output_path_with_spaces() {
        let begin = "---SSHB_B_space---";
        let raw = format!("output\n{begin}\n0\n/home/user/my folder/sub dir\n");

        let (_, _, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(cwd, "/home/user/my folder/sub dir");
    }

    #[test]
    fn test_parse_exec_output_path_with_unicode() {
        let begin = "---SSHB_B_uni---";
        let raw = format!("output\n{begin}\n0\n/home/ユーザー/ドキュメント\n");

        let (_, _, cwd) = SessionManager::parse_exec_output(&raw, begin);
        assert!(cwd.contains("ユーザー"));
    }

    #[test]
    fn test_parse_exec_output_exit_code_with_whitespace() {
        let begin = "---SSHB_B_ws---";
        let raw = format!("output\n{begin}\n  42  \n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        assert_eq!(exit_code, 42);
    }

    #[test]
    fn test_parse_exec_output_overflow_exit_code() {
        let begin = "---SSHB_B_over---";
        // u32::MAX + 1 should fail to parse
        let raw = format!("output\n{begin}\n4294967296\n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        // Should default to 1 on parse failure
        assert_eq!(exit_code, 1);
    }

    #[test]
    fn test_parse_exec_output_float_exit_code() {
        let begin = "---SSHB_B_float---";
        let raw = format!("output\n{begin}\n1.5\n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        // Float won't parse as u32
        assert_eq!(exit_code, 1);
    }

    #[test]
    fn test_parse_exec_output_hex_exit_code() {
        let begin = "---SSHB_B_hex---";
        let raw = format!("output\n{begin}\n0xFF\n/tmp\n");

        let (_, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        // Hex won't parse as decimal u32
        assert_eq!(exit_code, 1);
    }

    #[test]
    fn test_parse_exec_output_marker_in_output() {
        // What if the output contains something that looks like a marker?
        let begin = "---SSHB_B_meta---";
        let raw = format!("some output with ---SSHB--- in it\n{begin}\n0\n/tmp\n");

        let (output, exit_code, _) = SessionManager::parse_exec_output(&raw, begin);
        assert!(output.contains("---SSHB---"));
        assert_eq!(exit_code, 0);
    }

    // ============== SessionInfo Tests ==============

    #[test]
    fn test_session_info_all_fields() {
        let info = SessionInfo {
            id: "abc-123-def".to_string(),
            host: "production-server".to_string(),
            cwd: "/var/www/html".to_string(),
            created_at_secs_ago: 3600,
            last_used_secs_ago: 60,
        };

        assert_eq!(info.id, "abc-123-def");
        assert_eq!(info.host, "production-server");
        assert_eq!(info.cwd, "/var/www/html");
        assert_eq!(info.created_at_secs_ago, 3600);
        assert_eq!(info.last_used_secs_ago, 60);
    }

    #[test]
    fn test_session_info_max_values() {
        let info = SessionInfo {
            id: "max".to_string(),
            host: "host".to_string(),
            cwd: "/".to_string(),
            created_at_secs_ago: u64::MAX,
            last_used_secs_ago: u64::MAX,
        };

        assert_eq!(info.created_at_secs_ago, u64::MAX);
        assert_eq!(info.last_used_secs_ago, u64::MAX);
    }

    #[test]
    fn test_session_info_empty_strings() {
        let info = SessionInfo {
            id: String::new(),
            host: String::new(),
            cwd: String::new(),
            created_at_secs_ago: 0,
            last_used_secs_ago: 0,
        };

        assert!(info.id.is_empty());
        assert!(info.host.is_empty());
        assert!(info.cwd.is_empty());
    }

    // ============== SessionExecResult Tests ==============

    #[test]
    fn test_session_exec_result_all_fields() {
        let result = SessionExecResult {
            session_id: "session-xyz".to_string(),
            output: "Hello, World!\n".to_string(),
            exit_code: 0,
            cwd: "/home/user".to_string(),
        };

        assert_eq!(result.session_id, "session-xyz");
        assert_eq!(result.output, "Hello, World!\n");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.cwd, "/home/user");
    }

    #[test]
    fn test_session_exec_result_empty_output() {
        let result = SessionExecResult {
            session_id: "sess".to_string(),
            output: String::new(),
            exit_code: 0,
            cwd: "/".to_string(),
        };

        assert!(result.output.is_empty());
    }

    #[test]
    fn test_session_exec_result_large_output() {
        let large_output = "x".repeat(1_000_000);
        let result = SessionExecResult {
            session_id: "large".to_string(),
            output: large_output.clone(),
            exit_code: 0,
            cwd: "/".to_string(),
        };

        assert_eq!(result.output.len(), 1_000_000);
    }

    #[test]
    fn test_session_exec_result_json_serialization() {
        let result = SessionExecResult {
            session_id: "test-123".to_string(),
            output: "output\nwith\nnewlines".to_string(),
            exit_code: 42,
            cwd: "/test".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("test-123"));
        assert!(json.contains("42"));
        assert!(json.contains("/test"));

        // Verify it can be deserialized (if we had Deserialize)
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["exit_code"], 42);
    }

    // ============== SessionConfig Edge Cases ==============

    #[test]
    fn test_session_config_custom_values() {
        let config = SessionConfig {
            max_sessions: 100,
            idle_timeout_seconds: 7200,
            max_age_seconds: 86400,
        };

        assert_eq!(config.max_sessions, 100);
        assert_eq!(config.idle_timeout_seconds, 7200);
        assert_eq!(config.max_age_seconds, 86400);
    }

    #[test]
    fn test_session_config_zero_values() {
        let config = SessionConfig {
            max_sessions: 0,
            idle_timeout_seconds: 0,
            max_age_seconds: 0,
        };

        assert_eq!(config.max_sessions, 0);
        assert_eq!(config.idle_timeout_seconds, 0);
        assert_eq!(config.max_age_seconds, 0);
    }

    // ============== MARKER_PREFIX Tests ==============

    #[test]
    fn test_marker_prefix_format() {
        // MARKER_PREFIX should be unique and recognizable
        assert!(MARKER_PREFIX.starts_with("---"));
        assert!(MARKER_PREFIX.contains("SSHB"));
    }

    #[test]
    fn test_marker_not_in_common_output() {
        let common_outputs = [
            "ls -la",
            "total 42",
            "drwxr-xr-x",
            "Hello World",
            "Error: command not found",
            "#!/bin/bash",
        ];

        for output in common_outputs {
            assert!(!output.contains(MARKER_PREFIX));
        }
    }
}
