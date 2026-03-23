//! NETCONF protocol adapter — RFC 6241 network configuration
//!
//! Implements remote network device configuration via the NETCONF protocol,
//! over SSH (RFC 6242). Used for modern network equipment
//! (Juniper, Cisco IOS XE, Nokia, etc.).
//!
//! Note: `netconf-rs` is synchronous; all calls are wrapped in
//! `tokio::task::spawn_blocking` for async compatibility.
//!
//! Feature-gated behind `netconf`.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Default NETCONF-over-SSH port (RFC 6242).
const DEFAULT_NETCONF_PORT: u16 = 830;

/// An active NETCONF session.
///
/// Wraps the synchronous `netconf-rs` `Connection` behind a `Mutex`
/// for thread-safe access from async contexts.
pub struct NetconfConnection {
    conn: Arc<Mutex<netconf_rs::Connection>>,
    host_name: String,
    failed: bool,
}

impl NetconfConnection {
    /// Establish a NETCONF-over-SSH session.
    ///
    /// # Errors
    ///
    /// Returns an error if the SSH/NETCONF handshake fails.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        let port = if host_config.port == 22 {
            DEFAULT_NETCONF_PORT
        } else {
            host_config.port
        };

        let password = match &host_config.auth {
            crate::config::AuthConfig::Password { password } => password.to_string(),
            _ => {
                return Err(BridgeError::Config(format!(
                    "NETCONF host '{host_name}' requires password authentication"
                )));
            }
        };

        let addr = format!("{}:{port}", host_config.hostname);
        let user = host_config.user.clone();
        let name = host_name.to_string();

        info!(host = %name, addr = %addr, "Connecting via NETCONF");

        // netconf-rs is synchronous, so run in blocking thread
        let conn = tokio::task::spawn_blocking(move || {
            let transport =
                netconf_rs::transport::ssh::SSHTransport::connect(&addr, &user, &password)?;
            netconf_rs::Connection::new(transport)
        })
        .await
        .map_err(|e| BridgeError::SshExec {
            reason: format!("NETCONF task join failed: {e}"),
        })?
        .map_err(|e| BridgeError::SshExec {
            reason: format!("NETCONF connect failed: {e}"),
        })?;

        info!(host = %host_name, "NETCONF session established");

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            host_name: host_name.to_string(),
            failed: false,
        })
    }

    /// Execute a NETCONF operation.
    ///
    /// If the command is `get-config`, calls the built-in method.
    /// Otherwise, sends raw XML RPC via the transport layer.
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC fails.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(host = %self.host_name, "Executing NETCONF operation");

        let conn = Arc::clone(&self.conn);
        let cmd = command.to_string();

        let response = tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().expect("NETCONF mutex poisoned");
            if cmd.trim() == "get-config" || cmd.contains("<get-config") {
                guard.get_config()
            } else {
                // netconf-rs only exposes get_config(); raw RPC requires
                // a fork with pub transport. Return the command as-is
                // wrapped in an error message for now.
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "Only 'get-config' is supported by netconf-rs. \
                         Raw RPC requires a fork with public transport. \
                         Command: {cmd}"
                    ),
                ))
            }
        })
        .await
        .map_err(|e| BridgeError::SshExec {
            reason: format!("NETCONF task join failed: {e}"),
        })?
        .map_err(|e| BridgeError::SshExec {
            reason: format!("NETCONF operation failed: {e}"),
        })?;

        let duration_ms = start.elapsed().as_millis() as u64;

        let has_error = response.contains("<rpc-error");
        let exit_code = if has_error { 1 } else { 0 };

        Ok(CommandOutput {
            stdout: response,
            stderr: String::new(),
            exit_code,
            duration_ms,
        })
    }

    /// Mark this connection as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "NETCONF session marked as failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_netconf_port() {
        assert_eq!(DEFAULT_NETCONF_PORT, 830);
    }
}
