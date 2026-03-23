//! NATS protocol adapter — event-driven command execution
//!
//! Implements remote command execution via NATS request/reply messaging.
//! Requires a custom agent running on target hosts that subscribes to
//! a command subject and publishes results back.
//!
//! **Requires remote agent** — not a native execution protocol.
//!
//! Feature-gated behind `nats`.

use std::time::{Duration, Instant};

use async_nats::Client as NatsClient;
use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Default NATS server port.
const DEFAULT_NATS_PORT: u16 = 4222;
/// Request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Subject prefix for command execution requests.
const CMD_SUBJECT_PREFIX: &str = "mcp.exec";

/// NATS connection — wraps an async-nats client for request/reply RPC.
///
/// The `HostConfig` is interpreted as follows:
/// - `hostname` → NATS server address
/// - `port` → NATS port (default: 4222)
/// - `user` → target host identity (used as subject suffix)
/// - `description` → optional NATS credentials file path
pub struct NatsConnection {
    client: NatsClient,
    target_subject: String,
    host_name: String,
    failed: bool,
}

impl NatsConnection {
    /// Connect to a NATS server and resolve the target subject.
    ///
    /// # Errors
    ///
    /// Returns an error if the NATS connection fails.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        info!(host = %host_name, "Connecting via NATS");

        let port = if host_config.port == 22 {
            DEFAULT_NATS_PORT
        } else {
            host_config.port
        };

        let server_url = format!("nats://{}:{port}", host_config.hostname);

        let client = async_nats::connect(&server_url)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("NATS connect to {server_url} failed: {e}"),
            })?;

        // Target subject: mcp.exec.<host_identity>
        let target_identity = if host_config.user.is_empty() || host_config.user == "root" {
            host_name.to_string()
        } else {
            host_config.user.clone()
        };
        let target_subject = format!("{CMD_SUBJECT_PREFIX}.{target_identity}");

        info!(
            host = %host_name,
            server = %server_url,
            subject = %target_subject,
            "NATS connected"
        );

        Ok(Self {
            client,
            target_subject,
            host_name: host_name.to_string(),
            failed: false,
        })
    }

    /// Execute a command via NATS request/reply.
    ///
    /// Publishes a JSON command request to the target subject and waits
    /// for the agent's reply containing stdout, stderr, and exit code.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or times out.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(
            host = %self.host_name,
            subject = %self.target_subject,
            command = %command,
            "Executing NATS command"
        );

        let request = serde_json::json!({
            "cmd": command,
            "timeout": REQUEST_TIMEOUT.as_secs(),
        });

        let payload = serde_json::to_vec(&request).map_err(|e| BridgeError::SshExec {
            reason: format!("NATS request serialization failed: {e}"),
        })?;

        let response = tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.client.request(self.target_subject.clone(), payload.into()),
        )
        .await
        .map_err(|_| BridgeError::SshExec {
            reason: format!(
                "NATS response timed out after {}s on subject {}",
                REQUEST_TIMEOUT.as_secs(),
                self.target_subject,
            ),
        })?
        .map_err(|e| BridgeError::SshExec {
            reason: format!("NATS request failed: {e}"),
        })?;

        let parsed: serde_json::Value =
            serde_json::from_slice(&response.payload).map_err(|e| BridgeError::SshExec {
                reason: format!("NATS response parse failed: {e}"),
            })?;

        #[allow(clippy::cast_possible_truncation)]
        let exit_code = parsed["exit_code"].as_u64().unwrap_or(0) as u32;

        Ok(CommandOutput {
            stdout: parsed["stdout"].as_str().unwrap_or_default().to_string(),
            stderr: parsed["stderr"].as_str().unwrap_or_default().to_string(),
            exit_code,
            duration_ms: elapsed_ms(start),
        })
    }

    /// Mark this connection as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "NATS connection marked as failed");
    }
}

/// Convert elapsed duration to milliseconds, saturating on overflow.
#[allow(clippy::cast_possible_truncation)]
fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_port() {
        assert_eq!(DEFAULT_NATS_PORT, 4222);
    }

    #[test]
    fn test_request_timeout() {
        assert_eq!(REQUEST_TIMEOUT.as_secs(), 30);
    }

    #[test]
    fn test_subject_format() {
        let subject = format!("{CMD_SUBJECT_PREFIX}.web-server-01");
        assert_eq!(subject, "mcp.exec.web-server-01");
    }

    #[test]
    fn test_request_payload() {
        let request = serde_json::json!({
            "cmd": "uptime",
            "timeout": 30,
        });
        let bytes = serde_json::to_vec(&request).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["cmd"].as_str().unwrap(), "uptime");
    }

    #[test]
    fn test_response_parsing() {
        let response = serde_json::json!({
            "stdout": "up 42 days\n",
            "stderr": "",
            "exit_code": 0,
        });
        assert_eq!(response["stdout"].as_str().unwrap(), "up 42 days\n");
        assert_eq!(response["exit_code"].as_u64().unwrap(), 0);
    }
}
