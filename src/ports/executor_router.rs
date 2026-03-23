//! Executor Router — Protocol-aware dispatcher
//!
//! `ExecutorRouter` wraps the SSH `ConnectionPool` and dispatches connections
//! based on the `protocol` field in each host's configuration. For Phase 1,
//! only SSH is supported; future protocol adapters (`WinRM`, Telnet, NETCONF,
//! gRPC, Serial) will be added as feature-gated variants.
//!
//! The router exposes the same public API as `ConnectionPool`, enabling a
//! clean cut-over in `ToolContext` without changing any of the 337 tool handlers.

use crate::config::{HostConfig, LimitsConfig, Protocol};
use crate::error::Result;
use crate::ssh::{ConnectionPool, PoolConfig, PoolStats, PooledConnectionGuard};

/// Protocol-aware connection router.
///
/// Holds one connection pool per protocol backend. For SSH hosts (the default),
/// connections are delegated to the inner `ConnectionPool`. Future protocol
/// adapters will each have their own pool/manager added here behind feature flags.
pub struct ExecutorRouter {
    ssh_pool: ConnectionPool,
}

impl ExecutorRouter {
    /// Create a router with default pool configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            ssh_pool: ConnectionPool::with_defaults(),
        }
    }

    /// Create a router with a custom SSH pool configuration.
    #[must_use]
    pub fn new(ssh_pool_config: PoolConfig) -> Self {
        Self {
            ssh_pool: ConnectionPool::new(ssh_pool_config),
        }
    }

    /// Get or create a connection to the specified host.
    ///
    /// Dispatches to the appropriate protocol backend based on
    /// `host_config.protocol`. Currently only SSH is supported.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established or if
    /// the host uses an unsupported protocol.
    pub async fn get_connection(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<PooledConnectionGuard<'_>> {
        self.get_connection_with_jump(host_name, host_config, limits, None)
            .await
    }

    /// Get or create a connection, optionally via a jump host.
    ///
    /// This is the primary entry point used by tool handlers. It dispatches
    /// to the correct protocol adapter based on `host_config.protocol`.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established.
    pub async fn get_connection_with_jump(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        limits: &LimitsConfig,
        jump_host: Option<(&str, &HostConfig)>,
    ) -> Result<PooledConnectionGuard<'_>> {
        match host_config.protocol {
            Protocol::Ssh => {
                self.ssh_pool
                    .get_connection_with_jump(host_name, host_config, limits, jump_host)
                    .await
            } // Future protocols will be dispatched here:
              // Protocol::WinRm => self.winrm_pool.get_connection(...),
              // Protocol::Telnet => self.telnet_pool.get_connection(...),
        }
    }

    /// Clean up idle and expired connections across all protocol pools.
    pub async fn cleanup(&self) {
        self.ssh_pool.cleanup().await;
        // Future: self.winrm_pool.cleanup().await;
    }

    /// Get statistics for the SSH connection pool.
    #[must_use = "pool stats should be used for monitoring or logging"]
    pub async fn stats(&self) -> PoolStats {
        self.ssh_pool.stats().await
    }

    /// Actively check all pooled connections and remove dead ones.
    pub async fn health_check(&self) {
        self.ssh_pool.health_check().await;
    }

    /// Close all connections across all protocol pools.
    pub async fn close_all(&self) {
        self.ssh_pool.close_all().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_router_with_defaults() {
        let _router = ExecutorRouter::with_defaults();
    }

    #[test]
    fn test_executor_router_new() {
        let _router = ExecutorRouter::new(PoolConfig::default());
    }

    #[tokio::test]
    async fn test_executor_router_stats_empty() {
        let router = ExecutorRouter::with_defaults();
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_executor_router_cleanup_empty() {
        let router = ExecutorRouter::with_defaults();
        router.cleanup().await;
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_executor_router_health_check_empty() {
        let router = ExecutorRouter::with_defaults();
        router.health_check().await;
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_executor_router_close_all_empty() {
        let router = ExecutorRouter::with_defaults();
        router.close_all().await;
        let stats = router.stats().await;
        assert_eq!(stats.total_connections, 0);
    }

    #[tokio::test]
    async fn test_executor_router_operations_sequence() {
        let router = ExecutorRouter::with_defaults();
        let s1 = router.stats().await;
        assert_eq!(s1.total_connections, 0);

        router.cleanup().await;
        router.health_check().await;
        router.close_all().await;

        let s2 = router.stats().await;
        assert_eq!(s2.total_connections, 0);
    }
}
