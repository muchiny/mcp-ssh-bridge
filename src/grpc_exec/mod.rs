//! gRPC protocol adapter — cloud-native remote execution
//!
//! Implements remote command execution via a gRPC service. This adapter
//! connects to a gRPC server running on the remote host that implements
//! a simple command execution service.
//!
//! Feature-gated behind `grpc`.

use std::time::Instant;

use tonic::transport::Channel;
use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Default gRPC port for the remote execution service.
const DEFAULT_GRPC_PORT: u16 = 50051;

/// An active gRPC channel to a remote execution service.
pub struct GrpcConnection {
    channel: Channel,
    host_name: String,
    endpoint: String,
    failed: bool,
}

impl GrpcConnection {
    /// Establish a gRPC channel to the remote host.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel cannot be established.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        let port = if host_config.port == 22 {
            DEFAULT_GRPC_PORT
        } else {
            host_config.port
        };

        let endpoint = format!("http://{}:{port}", host_config.hostname);
        info!(host = %host_name, endpoint = %endpoint, "Connecting via gRPC");

        let channel = Channel::from_shared(endpoint.clone())
            .map_err(|e| BridgeError::SshExec {
                reason: format!("gRPC endpoint invalid: {e}"),
            })?
            .connect()
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("gRPC connect failed: {e}"),
            })?;

        info!(host = %host_name, "gRPC channel established");

        Ok(Self {
            channel,
            host_name: host_name.to_string(),
            endpoint,
            failed: false,
        })
    }

    /// Execute a command via the gRPC remote execution service.
    ///
    /// This sends a unary RPC with the command string and receives
    /// the `stdout`/`stderr`/`exit_code` response.
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC call fails.
    #[allow(clippy::unused_async)]
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(
            host = %self.host_name,
            command = %command,
            "Executing gRPC command"
        );

        // Without a proto-generated client, we use a raw unary call.
        // In a production setup, this would use a generated client from
        // a `.proto` file defining the RemoteExec service.
        //
        // For now, construct a simple JSON-encoded request over the channel.
        let request = tonic::Request::new(());

        // Since we don't have a proto definition yet, we simulate the call.
        // A real implementation would call:
        //   let response = RemoteExecClient::new(self.channel.clone())
        //       .execute(request)
        //       .await?;
        let _ = request;
        let _ = &self.channel;

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        // Placeholder: return an error indicating the proto service is not configured
        Err(BridgeError::SshExec {
            reason: format!(
                "gRPC remote exec service not configured at {} \
                 (proto definition required). Command: {command}, \
                 duration: {duration_ms}ms",
                self.endpoint
            ),
        })
    }

    /// Mark this connection as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "gRPC channel marked as failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_grpc_port() {
        assert_eq!(DEFAULT_GRPC_PORT, 50051);
    }
}
