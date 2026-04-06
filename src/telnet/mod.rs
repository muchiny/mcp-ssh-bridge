//! Telnet protocol adapter — legacy network equipment
//!
//! Implements remote command execution over Telnet, primarily for
//! legacy network devices (Cisco IOS, Juniper, `MikroTik`, etc.)
//! that do not support SSH.
//!
//! Feature-gated behind `telnet`.

use std::time::{Duration, Instant};

use mini_telnet::Telnet;
use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Default Telnet port.
const DEFAULT_TELNET_PORT: u16 = 23;

/// Default prompt regex for network devices.
const DEFAULT_PROMPT: &str = r"[>#$]";

/// An active Telnet connection to a network device.
pub struct TelnetConnection {
    inner: Telnet,
    host_name: String,
    failed: bool,
}

impl TelnetConnection {
    /// Establish a Telnet connection and authenticate.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or authentication fails.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        let port = if host_config.port == 22 {
            DEFAULT_TELNET_PORT
        } else {
            host_config.port
        };

        let password = match &host_config.auth {
            crate::config::AuthConfig::Password { password } => password.to_string(),
            _ => {
                return Err(BridgeError::Config(format!(
                    "Telnet host '{host_name}' requires password authentication"
                )));
            }
        };

        let addr = format!("{}:{port}", host_config.hostname);
        info!(host = %host_name, addr = %addr, "Connecting via Telnet");

        let telnet = Telnet::builder()
            .login_prompt("ogin:", DEFAULT_PROMPT)
            .timeout(Duration::from_secs(10))
            .connect(&addr)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet connection failed: {e}"),
            })?;

        // Authenticate
        let mut conn = Self {
            inner: telnet,
            host_name: host_name.to_string(),
            failed: false,
        };

        // Send username
        conn.inner
            .execute(&host_config.user)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet login failed: {e}"),
            })?;

        // Send password
        conn.inner
            .execute(&password)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet password failed: {e}"),
            })?;

        info!(host = %host_name, "Telnet authenticated");
        Ok(conn)
    }

    /// Execute a command over the Telnet session.
    ///
    /// # Errors
    ///
    /// Returns an error if the command execution fails.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(host = %self.host_name, command = %command, "Executing Telnet command");

        let output = self
            .inner
            .execute(command)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Telnet exec failed: {e}"),
            })?;

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        // Telnet doesn't have separate stdout/stderr or exit codes.
        // The output is the raw text response from the device.
        Ok(CommandOutput {
            stdout: output,
            stderr: String::new(),
            exit_code: 0,
            duration_ms,
        })
    }

    /// Mark this connection as failed (won't be reused).
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "Telnet connection marked as failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_telnet_port() {
        assert_eq!(DEFAULT_TELNET_PORT, 23);
    }

    #[test]
    fn test_default_prompt() {
        let re = regex::Regex::new(DEFAULT_PROMPT).unwrap();
        assert!(re.is_match("#"));
        assert!(re.is_match(">"));
        assert!(re.is_match("$"));
    }

    #[test]
    fn test_default_prompt_regex_no_match() {
        let re = regex::Regex::new(DEFAULT_PROMPT).unwrap();
        assert!(!re.is_match("hello"));
        assert!(!re.is_match(""));
    }

    #[test]
    fn test_default_prompt_regex_in_context() {
        let re = regex::Regex::new(DEFAULT_PROMPT).unwrap();
        assert!(re.is_match("Router#"));
        assert!(re.is_match("Switch>"));
        assert!(re.is_match("user@host$"));
    }

    #[test]
    fn test_default_port_value() {
        assert_eq!(DEFAULT_TELNET_PORT, 23);
        // Verify it's a well-known port
        assert!(DEFAULT_TELNET_PORT < 1024);
    }

    #[test]
    fn test_port_fallback_from_ssh() {
        // When port is 22 (SSH default), telnet should use its own default
        let ssh_port: u16 = 22;
        let telnet_port = if ssh_port == 22 {
            DEFAULT_TELNET_PORT
        } else {
            ssh_port
        };
        assert_eq!(telnet_port, 23);
    }

    #[test]
    fn test_port_custom_value() {
        let custom_port: u16 = 2323;
        let telnet_port = if custom_port == 22 {
            DEFAULT_TELNET_PORT
        } else {
            custom_port
        };
        assert_eq!(telnet_port, 2323);
    }

    #[test]
    fn test_addr_format() {
        let hostname = "192.168.1.1";
        let port = DEFAULT_TELNET_PORT;
        let addr = format!("{hostname}:{port}");
        assert_eq!(addr, "192.168.1.1:23");
    }

    #[test]
    fn test_default_prompt_is_valid_regex() {
        // Ensure the constant compiles as a valid regex
        let result = regex::Regex::new(DEFAULT_PROMPT);
        assert!(result.is_ok());
    }
}
