//! `NETCONF` protocol adapter — RFC 6241 network configuration
//!
//! Implements remote network device configuration via the `NETCONF` protocol,
//! over SSH (RFC 6242). Used for modern network equipment
//! (Juniper, Cisco IOS XE, Nokia, etc.).
//!
//! Note: `netconf-rs` is synchronous; all calls are wrapped in
//! `tokio::task::spawn_blocking` for async compatibility.
//!
//! Feature-gated behind `netconf`.
//!
//! # Current Limitations
//!
//! Only `get-config` RPCs are supported. The `netconf-rs` 0.2 crate exposes
//! only `Connection::get_config()` and keeps its SSH transport private.
//! Arbitrary `<rpc>` operations (edit-config, commit, lock, get, etc.) return
//! an `Unsupported` error. A full implementation requires either upgrading to
//! a future `netconf-rs` release that exposes raw RPC, or replacing the
//! dependency with a fork/alternative crate.

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
        let host_name = self.host_name.clone();

        let response = tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().expect("NETCONF mutex poisoned");
            if cmd.trim() == "get-config" || cmd.contains("<get-config") {
                guard.get_config()
            } else {
                warn!(
                    host = %host_name,
                    command = %cmd,
                    "NETCONF: only 'get-config' is supported by netconf-rs 0.2; \
                     raw RPC requires a fork with public transport"
                );
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

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        let has_error = response.contains("<rpc-error");
        let exit_code = u32::from(has_error);

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

    #[test]
    fn test_default_port_is_iana_assigned() {
        // NETCONF over SSH is IANA-assigned port 830 (RFC 6242)
        const { assert!(DEFAULT_NETCONF_PORT > 0) };
        const { assert!(DEFAULT_NETCONF_PORT < 1024) }; // well-known port range
    }

    #[test]
    fn test_port_fallback_from_ssh() {
        let ssh_port: u16 = 22;
        let netconf_port = if ssh_port == 22 {
            DEFAULT_NETCONF_PORT
        } else {
            ssh_port
        };
        assert_eq!(netconf_port, 830);
    }

    #[test]
    fn test_port_custom_value_preserved() {
        let custom_port: u16 = 8300;
        let netconf_port = if custom_port == 22 {
            DEFAULT_NETCONF_PORT
        } else {
            custom_port
        };
        assert_eq!(netconf_port, 8300);
    }

    #[test]
    fn test_rpc_error_detection() {
        let response_ok = "<rpc-reply><data>config</data></rpc-reply>";
        let response_err =
            "<rpc-reply><rpc-error><error-message>bad</error-message></rpc-error></rpc-reply>";

        assert!(!response_ok.contains("<rpc-error"));
        assert!(response_err.contains("<rpc-error"));

        // exit_code logic: 1 if has_error, 0 otherwise
        assert_eq!(u32::from(response_ok.contains("<rpc-error")), 0);
        assert_eq!(u32::from(response_err.contains("<rpc-error")), 1);
    }

    #[test]
    fn test_get_config_command_detection() {
        // The exec method checks for "get-config" or "<get-config"
        let cmd1 = "get-config";
        let cmd2 = "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">";
        let cmd3 = "edit-config";

        assert!(cmd1.trim() == "get-config" || cmd1.contains("<get-config"));
        assert!(cmd2.trim() == "get-config" || cmd2.contains("<get-config"));
        assert!(!(cmd3.trim() == "get-config" || cmd3.contains("<get-config")));
    }

    #[test]
    fn test_addr_format() {
        let hostname = "10.0.0.1";
        let port = DEFAULT_NETCONF_PORT;
        let addr = format!("{hostname}:{port}");
        assert_eq!(addr, "10.0.0.1:830");
    }
}
