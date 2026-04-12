//! PSRP (`PowerShell` Remoting Protocol) adapter.
//!
//! Wraps `psrp_rs::RunspacePool` to provide native `PowerShell` execution
//! over `WinRM` transport. Returns typed `PsValue` objects converted to
//! [`CommandOutput`] for compatibility with the standard tool pipeline.

pub mod pool;

use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::config::LimitsConfig;
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// An active PSRP connection wrapping a `psrp_rs::RunspacePool`.
///
/// Each `PsrpConnection` holds a live `PowerShell` session that persists
/// across multiple command executions, avoiding the shell creation/teardown
/// overhead of `WinRM`'s per-command model.
pub struct PsrpConnection {
    // TODO: Replace with actual `RunspacePool` once psrp-rs integration is wired
    host_name: String,
    failed: bool,
}

impl PsrpConnection {
    /// Wrap a pre-opened `RunspacePool` for a specific host.
    #[must_use]
    pub fn from_parts(host_name: &str) -> Self {
        Self {
            host_name: host_name.to_string(),
            failed: false,
        }
    }

    /// Execute a `PowerShell` script via PSRP.
    ///
    /// Uses `RunspacePool::run_script()`. Converts `Vec<PsValue>` to
    /// [`CommandOutput`] string representation.
    #[allow(clippy::unused_async)] // Will be async once psrp-rs is wired
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        debug!(
            host = %self.host_name,
            command = %command,
            "Executing PSRP command"
        );

        // TODO: Replace with actual psrp-rs `RunspacePool::run_script()` call
        let _ = command;

        Err(BridgeError::SshExec {
            reason: "PSRP adapter not yet fully wired — awaiting psrp-rs integration".to_string(),
        })
    }

    /// Execute with cancellation token propagation.
    pub async fn exec_with_cancel(
        &mut self,
        command: &str,
        limits: &LimitsConfig,
        _token: Option<CancellationToken>,
    ) -> Result<CommandOutput> {
        // TODO: Wire `CancellationToken` into psrp-rs `run_script_with_cancel`
        self.exec(command, limits).await
    }

    /// Mark connection as failed (triggers pool eviction).
    pub fn mark_failed(&mut self) {
        self.failed = true;
    }

    /// Host name for logging/eviction.
    #[must_use]
    pub fn host_name(&self) -> &str {
        &self.host_name
    }
}
