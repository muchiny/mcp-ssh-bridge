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
            self.client
                .request(self.target_subject.clone(), payload.into()),
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

    #[test]
    fn test_subject_construction_with_dots() {
        // NATS subjects use dots as separators
        let subject = format!("{CMD_SUBJECT_PREFIX}.db-server.primary");
        assert_eq!(subject, "mcp.exec.db-server.primary");
    }

    #[test]
    fn test_subject_prefix() {
        assert_eq!(CMD_SUBJECT_PREFIX, "mcp.exec");
        // NATS convention: dots are level separators
        assert!(CMD_SUBJECT_PREFIX.contains('.'));
    }

    #[test]
    fn test_response_parsing_with_stderr() {
        let response = serde_json::json!({
            "stdout": "",
            "stderr": "permission denied\n",
            "exit_code": 1,
        });
        assert_eq!(response["stderr"].as_str().unwrap(), "permission denied\n");
        assert_eq!(response["exit_code"].as_u64().unwrap(), 1);
    }

    #[test]
    fn test_response_parsing_missing_fields() {
        let response = serde_json::json!({});
        assert_eq!(response["stdout"].as_str().unwrap_or_default(), "");
        assert_eq!(response["stderr"].as_str().unwrap_or_default(), "");
        assert_eq!(response["exit_code"].as_u64().unwrap_or(0), 0);
    }

    #[test]
    fn test_response_parsing_wrong_types() {
        let response = serde_json::json!({
            "stdout": 42,
            "exit_code": "bad",
        });
        assert_eq!(response["stdout"].as_str().unwrap_or_default(), "");
        assert_eq!(response["exit_code"].as_u64().unwrap_or(0), 0);
    }

    #[test]
    fn test_elapsed_ms() {
        let start = Instant::now();
        let ms = elapsed_ms(start);
        assert!(ms < 100);
    }

    #[test]
    fn test_port_fallback_from_ssh() {
        let ssh_port: u16 = 22;
        let nats_port = if ssh_port == 22 {
            DEFAULT_NATS_PORT
        } else {
            ssh_port
        };
        assert_eq!(nats_port, 4222);
    }

    #[test]
    fn test_server_url_format() {
        let hostname = "nats.example.com";
        let port = DEFAULT_NATS_PORT;
        let url = format!("nats://{hostname}:{port}");
        assert_eq!(url, "nats://nats.example.com:4222");
    }

    #[test]
    fn test_target_identity_fallback() {
        let user = "";
        let host_name = "web-server-01";
        let identity = if user.is_empty() || user == "root" {
            host_name.to_string()
        } else {
            user.to_string()
        };
        assert_eq!(identity, "web-server-01");
    }

    #[test]
    fn test_target_identity_custom() {
        let user = "agent-alpha";
        let host_name = "web-server-01";
        let identity = if user.is_empty() || user == "root" {
            host_name.to_string()
        } else {
            user.to_string()
        };
        assert_eq!(identity, "agent-alpha");
    }

    #[test]
    fn test_request_serialization_roundtrip() {
        let request = serde_json::json!({
            "cmd": "cat /etc/hostname",
            "timeout": REQUEST_TIMEOUT.as_secs(),
        });
        let bytes = serde_json::to_vec(&request).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["cmd"].as_str().unwrap(), "cat /etc/hostname");
        assert_eq!(parsed["timeout"].as_u64().unwrap(), 30);
    }
}
