//! Executor Router — Protocol-aware dispatcher
//!
//! `ExecutorRouter` wraps the SSH `ConnectionPool` and dispatches connections
//! based on the `protocol` field in each host's configuration. Non-SSH
//! protocol adapters (`WinRM`, Telnet, NETCONF, gRPC) are feature-gated.
//!
//! The router exposes the same public API as `ConnectionPool`, enabling a
//! clean cut-over in `ToolContext` without changing any of the 337 tool handlers.

use crate::config::{HostConfig, LimitsConfig, Protocol};
use crate::error::Result;
use crate::ssh::{CommandOutput, ConnectionPool, PoolConfig, PoolStats, PooledConnectionGuard};

/// Protocol-aware connection router.
///
/// Holds one connection pool per protocol backend. For SSH hosts (the default),
/// connections are delegated to the inner `ConnectionPool`. Non-SSH adapters
/// create standalone connections behind feature flags.
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
    /// `host_config.protocol`.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established.
    pub async fn get_connection(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<ConnectionGuard<'_>> {
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
    ) -> Result<ConnectionGuard<'_>> {
        match host_config.protocol {
            Protocol::Ssh => {
                let guard = self
                    .ssh_pool
                    .get_connection_with_jump(host_name, host_config, limits, jump_host)
                    .await?;
                Ok(ConnectionGuard::Ssh(guard))
            }
            #[cfg(feature = "winrm")]
            Protocol::WinRm => {
                let conn = crate::winrm::WinRmConnection::new(host_name, host_config, limits)?;
                Ok(ConnectionGuard::WinRm(conn))
            }
            #[cfg(feature = "telnet")]
            Protocol::Telnet => {
                let conn = crate::telnet::TelnetConnection::connect(host_name, host_config, limits)
                    .await?;
                Ok(ConnectionGuard::Telnet(conn))
            }
            #[cfg(feature = "netconf")]
            Protocol::Netconf => {
                let conn =
                    crate::netconf::NetconfConnection::connect(host_name, host_config, limits)
                        .await?;
                Ok(ConnectionGuard::Netconf(conn))
            }
            #[cfg(feature = "grpc")]
            Protocol::Grpc => {
                let conn =
                    crate::grpc_exec::GrpcConnection::connect(host_name, host_config, limits)
                        .await?;
                Ok(ConnectionGuard::Grpc(conn))
            }
            #[cfg(feature = "k8s-exec")]
            Protocol::K8sExec => {
                let conn =
                    crate::k8s_exec::K8sExecConnection::connect(host_name, host_config, limits)
                        .await?;
                Ok(ConnectionGuard::K8sExec(conn))
            }
            #[cfg(feature = "serial")]
            Protocol::Serial => {
                let conn =
                    crate::serial_port::SerialConnection::connect(host_name, host_config, limits)
                        .await?;
                Ok(ConnectionGuard::Serial(conn))
            }
            #[cfg(feature = "snmp")]
            Protocol::Snmp => {
                let conn =
                    crate::snmp_client::SnmpConnection::connect(host_name, host_config, limits)
                        .await?;
                Ok(ConnectionGuard::Snmp(conn))
            }
        }
    }

    /// Clean up idle and expired connections across all protocol pools.
    pub async fn cleanup(&self) {
        self.ssh_pool.cleanup().await;
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

/// Unified connection guard for all supported protocols.
///
/// Each tool handler calls `conn.exec(command, limits)` and
/// `conn.mark_failed()` — this enum dispatches to the correct
/// protocol adapter transparently.
pub enum ConnectionGuard<'a> {
    /// SSH connection (pooled, returned to pool on drop).
    Ssh(PooledConnectionGuard<'a>),
    /// `WinRM` connection (HTTP/SOAP, stateless).
    #[cfg(feature = "winrm")]
    WinRm(crate::winrm::WinRmConnection),
    /// Telnet connection (persistent TCP session).
    #[cfg(feature = "telnet")]
    Telnet(crate::telnet::TelnetConnection),
    /// NETCONF session (RFC 6241 over SSH).
    #[cfg(feature = "netconf")]
    Netconf(crate::netconf::NetconfConnection),
    /// gRPC channel (HTTP/2).
    #[cfg(feature = "grpc")]
    Grpc(crate::grpc_exec::GrpcConnection),
    /// Kubernetes Exec (direct K8s API pod exec).
    #[cfg(feature = "k8s-exec")]
    K8sExec(crate::k8s_exec::K8sExecConnection),
    /// Serial port (RS-232/USB).
    #[cfg(feature = "serial")]
    Serial(crate::serial_port::SerialConnection),
    /// SNMP session (v1/v2c UDP).
    #[cfg(feature = "snmp")]
    Snmp(crate::snmp_client::SnmpConnection),
}

impl ConnectionGuard<'_> {
    /// Execute a command using this connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the command execution fails.
    ///
    /// # Panics
    ///
    /// Panics if the SSH connection has already been taken.
    pub async fn exec(&mut self, command: &str, limits: &LimitsConfig) -> Result<CommandOutput> {
        match self {
            Self::Ssh(guard) => guard.exec(command, limits).await,
            #[cfg(feature = "winrm")]
            Self::WinRm(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "telnet")]
            Self::Telnet(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "netconf")]
            Self::Netconf(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "grpc")]
            Self::Grpc(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "k8s-exec")]
            Self::K8sExec(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "serial")]
            Self::Serial(conn) => conn.exec(command, limits).await,
            #[cfg(feature = "snmp")]
            Self::Snmp(conn) => conn.exec(command, limits).await,
        }
    }

    /// Mark this connection as failed (won't be returned to pool).
    pub fn mark_failed(&mut self) {
        match self {
            Self::Ssh(guard) => guard.mark_failed(),
            #[cfg(feature = "winrm")]
            Self::WinRm(conn) => conn.mark_failed(),
            #[cfg(feature = "telnet")]
            Self::Telnet(conn) => conn.mark_failed(),
            #[cfg(feature = "netconf")]
            Self::Netconf(conn) => conn.mark_failed(),
            #[cfg(feature = "grpc")]
            Self::Grpc(conn) => conn.mark_failed(),
            #[cfg(feature = "k8s-exec")]
            Self::K8sExec(conn) => conn.mark_failed(),
            #[cfg(feature = "serial")]
            Self::Serial(conn) => conn.mark_failed(),
            #[cfg(feature = "snmp")]
            Self::Snmp(conn) => conn.mark_failed(),
        }
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
