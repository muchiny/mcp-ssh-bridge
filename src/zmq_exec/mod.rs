//! `ZeroMQ` protocol adapter — fleet-scale command execution
//!
//! Implements remote command execution via `ZeroMQ` REQ/REP sockets,
//! following the `SaltStack` model. Requires a custom agent/daemon
//! running on target hosts that listens on a `ZeroMQ` ROUTER socket
//! and executes commands locally.
//!
//! **Requires remote agent** — not a native execution protocol.
//!
//! Feature-gated behind `zeromq`.

use std::time::{Duration, Instant};

use tracing::{debug, info, warn};
use zeromq::{ReqSocket, Socket, SocketRecv, SocketSend, ZmqMessage};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Default `ZeroMQ` agent port.
const DEFAULT_ZMQ_PORT: u16 = 4506;
/// Request timeout for `ZeroMQ` operations.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `ZeroMQ` connection — REQ socket connected to a remote agent.
///
/// The `HostConfig` is interpreted as follows:
/// - `hostname` → agent host address
/// - `port` → agent port (default: 4506, `SaltStack` convention)
/// - `user` → optional agent identity/tag
pub struct ZmqConnection {
    socket: ReqSocket,
    endpoint: String,
    host_name: String,
    failed: bool,
}

impl ZmqConnection {
    /// Connect to a `ZeroMQ` agent on the specified host.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot connect.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        info!(host = %host_name, "Connecting via ZeroMQ");

        let port = if host_config.port == 22 {
            DEFAULT_ZMQ_PORT
        } else {
            host_config.port
        };

        let endpoint = format!("tcp://{}:{port}", host_config.hostname);

        let mut socket = ReqSocket::new();
        socket
            .connect(&endpoint)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("ZeroMQ connect to {endpoint} failed: {e}"),
            })?;

        info!(host = %host_name, endpoint = %endpoint, "ZeroMQ connected");

        Ok(Self {
            socket,
            endpoint,
            host_name: host_name.to_string(),
            failed: false,
        })
    }

    /// Execute a command via `ZeroMQ` REQ/REP.
    ///
    /// Sends a JSON request to the remote agent and awaits a JSON response.
    /// The agent is expected to execute the command locally and return
    /// stdout, stderr, and exit code.
    ///
    /// # Errors
    ///
    /// Returns an error if the send/recv fails or times out.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(
            host = %self.host_name,
            endpoint = %self.endpoint,
            command = %command,
            "Executing ZeroMQ command"
        );

        // Build request payload
        let request = serde_json::json!({
            "cmd": command,
            "timeout": REQUEST_TIMEOUT.as_secs(),
        });

        let request_bytes = serde_json::to_vec(&request).map_err(|e| BridgeError::SshExec {
            reason: format!("ZeroMQ request serialization failed: {e}"),
        })?;

        // Send request
        let msg = ZmqMessage::from(request_bytes);
        self.socket
            .send(msg)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("ZeroMQ send failed: {e}"),
            })?;

        // Receive response with timeout
        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.socket.recv())
            .await
            .map_err(|_| BridgeError::SshExec {
                reason: format!(
                    "ZeroMQ response timed out after {}s",
                    REQUEST_TIMEOUT.as_secs()
                ),
            })?
            .map_err(|e| BridgeError::SshExec {
                reason: format!("ZeroMQ recv failed: {e}"),
            })?;

        // Parse response — concatenate all frames
        let response_bytes: Vec<u8> = response
            .into_vec()
            .into_iter()
            .flat_map(|frame| frame.to_vec())
            .collect();

        let parsed: serde_json::Value =
            serde_json::from_slice(&response_bytes).map_err(|e| BridgeError::SshExec {
                reason: format!("ZeroMQ response parse failed: {e}"),
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
        warn!(host = %self.host_name, "ZeroMQ connection marked as failed");
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
        assert_eq!(DEFAULT_ZMQ_PORT, 4506);
    }

    #[test]
    fn test_request_timeout() {
        assert_eq!(REQUEST_TIMEOUT.as_secs(), 30);
    }

    #[test]
    fn test_endpoint_format() {
        let endpoint = format!("tcp://192.168.1.1:{DEFAULT_ZMQ_PORT}");
        assert!(endpoint.starts_with("tcp://"));
        assert!(endpoint.ends_with("4506"));
    }

    #[test]
    fn test_request_payload() {
        let request = serde_json::json!({
            "cmd": "whoami",
            "timeout": 30,
        });
        let serialized = serde_json::to_string(&request).unwrap();
        assert!(serialized.contains("whoami"));
        assert!(serialized.contains("timeout"));
    }

    #[test]
    fn test_elapsed_ms() {
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(10));
        let ms = elapsed_ms(start);
        assert!(ms >= 10);
    }

    #[test]
    fn test_elapsed_ms_immediate() {
        let start = Instant::now();
        let ms = elapsed_ms(start);
        // Should be very small (< 1ms typically)
        assert!(ms < 100);
    }

    #[test]
    fn test_response_parsing_missing_fields() {
        let response = serde_json::json!({});
        assert_eq!(response["stdout"].as_str().unwrap_or_default(), "");
        assert_eq!(response["stderr"].as_str().unwrap_or_default(), "");
        assert_eq!(response["exit_code"].as_u64().unwrap_or(0), 0);
    }

    #[test]
    fn test_response_parsing_null_fields() {
        let response = serde_json::json!({
            "stdout": null,
            "stderr": null,
            "exit_code": null,
        });
        assert_eq!(response["stdout"].as_str().unwrap_or_default(), "");
        assert_eq!(response["exit_code"].as_u64().unwrap_or(0), 0);
    }

    #[test]
    fn test_response_parsing_wrong_types() {
        let response = serde_json::json!({
            "stdout": 123,
            "exit_code": "not_a_number",
        });
        assert_eq!(response["stdout"].as_str().unwrap_or_default(), "");
        assert_eq!(response["exit_code"].as_u64().unwrap_or(0), 0);
    }

    #[test]
    fn test_response_parsing() {
        let response = serde_json::json!({
            "stdout": "root\n",
            "stderr": "",
            "exit_code": 0,
        });
        assert_eq!(response["stdout"].as_str().unwrap(), "root\n");
        assert_eq!(response["exit_code"].as_u64().unwrap(), 0);
    }
}
