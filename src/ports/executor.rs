//! Remote Executor Port
//!
//! This module defines the protocol-agnostic trait for remote command execution.
//! Each protocol adapter (SSH, `WinRM`, Telnet, NETCONF, gRPC, etc.) implements
//! this trait, allowing the domain layer to remain protocol-agnostic.

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::Result;

use super::ssh::CommandOutput;

/// Protocol-agnostic trait for remote command execution.
///
/// This trait extends the execution model beyond SSH, allowing multiple
/// protocol adapters to be used interchangeably. Each adapter implements
/// this trait and is registered with the `ExecutorRouter`.
///
/// The existing `SshExecutor` trait is preserved for backward compatibility;
/// this trait adds protocol-awareness metadata.
#[async_trait]
pub trait RemoteExecutor: Send + Sync {
    /// Execute a command on the specified host.
    async fn execute(&self, host: &str, command: &str, timeout: Duration) -> Result<CommandOutput>;

    /// Upload a file to a remote host.
    async fn upload(&self, host: &str, local: &Path, remote: &Path) -> Result<()>;

    /// Download a file from a remote host.
    async fn download(&self, host: &str, remote: &Path, local: &Path) -> Result<()>;

    /// Check if a host is reachable via this protocol.
    async fn is_reachable(&self, host: &str) -> bool;

    /// Return the protocol name (e.g., "ssh", "winrm", "telnet").
    fn protocol_name(&self) -> &'static str;

    /// Whether this protocol supports file transfer (upload/download).
    fn supports_file_transfer(&self) -> bool;

    /// Whether this protocol supports interactive/PTY sessions.
    fn supports_interactive(&self) -> bool {
        false
    }

    /// Whether this protocol supports structured configuration (NETCONF, SNMP).
    fn supports_structured_config(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify the trait is object-safe
    #[test]
    fn test_remote_executor_is_object_safe() {
        fn _assert_object_safe(_: &dyn RemoteExecutor) {}
    }

    #[test]
    fn test_default_trait_methods() {
        struct DummyExecutor;

        #[async_trait]
        impl RemoteExecutor for DummyExecutor {
            async fn execute(
                &self,
                _host: &str,
                _command: &str,
                _timeout: Duration,
            ) -> Result<CommandOutput> {
                Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                    duration_ms: 0,
                })
            }
            async fn upload(&self, _host: &str, _local: &Path, _remote: &Path) -> Result<()> {
                Ok(())
            }
            async fn download(&self, _host: &str, _remote: &Path, _local: &Path) -> Result<()> {
                Ok(())
            }
            async fn is_reachable(&self, _host: &str) -> bool {
                true
            }
            fn protocol_name(&self) -> &'static str {
                "dummy"
            }
            fn supports_file_transfer(&self) -> bool {
                false
            }
        }

        let executor = DummyExecutor;
        assert!(!executor.supports_interactive());
        assert!(!executor.supports_structured_config());
        assert_eq!(executor.protocol_name(), "dummy");
    }
}
