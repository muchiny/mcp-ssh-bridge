//! MQTT protocol adapter — `IoT`/Edge command execution
//!
//! Implements remote command execution via MQTT publish/subscribe.
//! Commands are published to a request topic and results are received
//! on a response topic. Requires a custom agent on target devices
//! that subscribes to command topics.
//!
//! Designed for `IoT` and edge computing environments where MQTT is
//! the primary communication protocol (lightweight, low-bandwidth).
//!
//! **Requires remote agent** — not a native execution protocol.
//!
//! Feature-gated behind `mqtt`.

use std::time::{Duration, Instant};

use rumqttc::{AsyncClient, EventLoop, MqttOptions, QoS};
use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Default MQTT broker port.
const DEFAULT_MQTT_PORT: u16 = 1883;
/// Request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Topic prefix for command requests.
const CMD_TOPIC_PREFIX: &str = "mcp/exec";
/// Topic prefix for command responses.
const RESP_TOPIC_PREFIX: &str = "mcp/resp";
/// MQTT channel capacity.
const CHANNEL_CAPACITY: usize = 16;

/// MQTT connection — wraps an MQTT client for pub/sub RPC.
///
/// The `HostConfig` is interpreted as follows:
/// - `hostname` → MQTT broker address
/// - `port` → broker port (default: 1883)
/// - `user` → target device identity (used in topic path)
/// - `description` → optional client ID prefix
pub struct MqttConnection {
    client: AsyncClient,
    eventloop: EventLoop,
    request_topic: String,
    response_topic: String,
    host_name: String,
    failed: bool,
}

impl MqttConnection {
    /// Connect to an MQTT broker and set up topics.
    ///
    /// # Errors
    ///
    /// Returns an error if the broker connection fails.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        info!(host = %host_name, "Connecting via MQTT");

        let port = if host_config.port == 22 {
            DEFAULT_MQTT_PORT
        } else {
            host_config.port
        };

        let client_id = host_config
            .description
            .as_deref()
            .unwrap_or("mcp-ssh-bridge");
        let client_id = format!("{client_id}-{}", uuid::Uuid::new_v4());

        let mut options = MqttOptions::new(&client_id, &host_config.hostname, port);
        options.set_keep_alive(Duration::from_secs(30));

        // Set credentials if password auth
        if let crate::config::AuthConfig::Password { ref password } = host_config.auth {
            options.set_credentials(&host_config.user, password.as_str());
        }

        let (client, eventloop) = AsyncClient::new(options, CHANNEL_CAPACITY);

        // Target identity for topic routing
        let target_identity = if host_config.user.is_empty() || host_config.user == "root" {
            host_name.to_string()
        } else {
            host_config.user.clone()
        };

        let request_topic = format!("{CMD_TOPIC_PREFIX}/{target_identity}");
        let response_topic = format!("{RESP_TOPIC_PREFIX}/{target_identity}");

        // Subscribe to response topic
        client
            .subscribe(&response_topic, QoS::AtLeastOnce)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("MQTT subscribe to {response_topic} failed: {e}"),
            })?;

        info!(
            host = %host_name,
            broker = format!("{}:{}", host_config.hostname, port),
            request_topic = %request_topic,
            response_topic = %response_topic,
            "MQTT connected"
        );

        Ok(Self {
            client,
            eventloop,
            request_topic,
            response_topic,
            host_name: host_name.to_string(),
            failed: false,
        })
    }

    /// Execute a command via MQTT pub/sub.
    ///
    /// Publishes a JSON command to the request topic and waits for a
    /// response on the response topic.
    ///
    /// # Errors
    ///
    /// Returns an error if publish fails or response times out.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(
            host = %self.host_name,
            topic = %self.request_topic,
            command = %command,
            "Executing MQTT command"
        );

        let request_id = uuid::Uuid::new_v4().to_string();
        let request = serde_json::json!({
            "id": request_id,
            "cmd": command,
            "timeout": REQUEST_TIMEOUT.as_secs(),
            "response_topic": self.response_topic,
        });

        let payload = serde_json::to_vec(&request).map_err(|e| BridgeError::SshExec {
            reason: format!("MQTT request serialization failed: {e}"),
        })?;

        // Publish command
        self.client
            .publish(&self.request_topic, QoS::AtLeastOnce, false, payload)
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("MQTT publish to {} failed: {e}", self.request_topic),
            })?;

        // Wait for response on response topic
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        loop {
            if Instant::now() > deadline {
                return Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: format!(
                        "MQTT response timed out after {}s",
                        REQUEST_TIMEOUT.as_secs()
                    ),
                    exit_code: 124,
                    duration_ms: elapsed_ms(start),
                });
            }

            let poll_result = tokio::time::timeout(
                Duration::from_secs(1),
                self.eventloop.poll(),
            )
            .await;

            let event = match poll_result {
                Ok(Ok(event)) => event,
                Ok(Err(e)) => {
                    return Err(BridgeError::SshExec {
                        reason: format!("MQTT eventloop error: {e}"),
                    });
                }
                Err(_) => continue, // timeout on poll, retry
            };

            // Check for incoming publish (response)
            if let rumqttc::Event::Incoming(rumqttc::Packet::Publish(publish)) = event
                && publish.topic == self.response_topic
            {
                let parsed: serde_json::Value =
                    serde_json::from_slice(&publish.payload).map_err(|e| BridgeError::SshExec {
                        reason: format!("MQTT response parse failed: {e}"),
                    })?;

                // Match response by request ID if present
                let resp_id = parsed["id"].as_str().unwrap_or_default();
                if !resp_id.is_empty() && resp_id != request_id {
                    continue; // Not our response
                }

                #[allow(clippy::cast_possible_truncation)]
                let exit_code = parsed["exit_code"].as_u64().unwrap_or(0) as u32;

                return Ok(CommandOutput {
                    stdout: parsed["stdout"].as_str().unwrap_or_default().to_string(),
                    stderr: parsed["stderr"].as_str().unwrap_or_default().to_string(),
                    exit_code,
                    duration_ms: elapsed_ms(start),
                });
            }
        }
    }

    /// Mark this connection as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "MQTT connection marked as failed");
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
        assert_eq!(DEFAULT_MQTT_PORT, 1883);
    }

    #[test]
    fn test_request_timeout() {
        assert_eq!(REQUEST_TIMEOUT.as_secs(), 30);
    }

    #[test]
    fn test_topic_format() {
        let request_topic = format!("{CMD_TOPIC_PREFIX}/sensor-gateway-01");
        let response_topic = format!("{RESP_TOPIC_PREFIX}/sensor-gateway-01");
        assert_eq!(request_topic, "mcp/exec/sensor-gateway-01");
        assert_eq!(response_topic, "mcp/resp/sensor-gateway-01");
    }

    #[test]
    fn test_request_payload() {
        let request = serde_json::json!({
            "id": "test-id",
            "cmd": "hostname",
            "timeout": 30,
            "response_topic": "mcp/resp/device-01",
        });
        let bytes = serde_json::to_vec(&request).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["cmd"].as_str().unwrap(), "hostname");
        assert_eq!(parsed["response_topic"].as_str().unwrap(), "mcp/resp/device-01");
    }

    #[test]
    fn test_response_parsing() {
        let response = serde_json::json!({
            "id": "test-id",
            "stdout": "device-01\n",
            "stderr": "",
            "exit_code": 0,
        });
        assert_eq!(response["stdout"].as_str().unwrap(), "device-01\n");
        assert_eq!(response["id"].as_str().unwrap(), "test-id");
    }
}
