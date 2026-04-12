//! PSRP connection pool — caches [`RunspacePool`] instances per host.
//!
//! Longer TTL than `WinRM` (300 s vs 120 s) because `RunspacePool` is designed
//! for session reuse and creation is expensive (TLS + auth + PSRP handshake +
//! runspace initialization).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::Result;

use super::PsrpConnection;

/// Default idle TTL for cached PSRP `RunspacePool` instances.
///
/// 300 s is longer than `WinRM`'s 120 s because `RunspacePool` is inherently
/// stateful and designed for reuse. Creation is expensive (TLS + auth +
/// PSRP handshake + runspace init), so we keep them around longer.
const DEFAULT_PSRP_IDLE_TTL: Duration = Duration::from_secs(300);

/// Configuration for the PSRP pool.
#[derive(Debug, Clone, Copy)]
pub struct PsrpPoolConfig {
    /// How long an idle `RunspacePool` stays cached before eviction.
    pub max_idle: Duration,
}

impl Default for PsrpPoolConfig {
    fn default() -> Self {
        Self {
            max_idle: DEFAULT_PSRP_IDLE_TTL,
        }
    }
}

/// Entry in the pool cache.
struct PooledRunspace {
    #[allow(dead_code)] // Will hold actual `RunspacePool` once psrp-rs is wired
    connection: PsrpConnection,
    last_used: Instant,
}

/// Cache of PSRP `RunspacePool` instances keyed by host name.
///
/// Follows the same pattern as `WinRmPool` and `K8sExecPool`:
/// `Arc<RwLock<HashMap>>` with fast/cold path lookup.
#[derive(Clone)]
pub struct PsrpPool {
    inner: Arc<RwLock<HashMap<String, PooledRunspace>>>,
    config: PsrpPoolConfig,
}

impl PsrpPool {
    /// Create a pool with default 300 s idle TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PsrpPoolConfig::default())
    }

    /// Create a pool with custom configuration.
    #[must_use]
    pub fn with_config(config: PsrpPoolConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Get or create a PSRP connection for the given host.
    ///
    /// **Fast path**: return cached `RunspacePool` if fresh.
    /// **Cold path**: build `WinrmClient` -> open `WinrmPsrpTransport` ->
    ///               open `RunspacePool` -> cache -> return.
    pub async fn get_connection(
        &self,
        host_name: &str,
        _host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<PsrpConnection> {
        // Fast path: check cache under read lock
        {
            let cache = self.inner.read().await;
            if let Some(entry) = cache.get(host_name)
                && entry.last_used.elapsed() < self.config.max_idle
            {
                debug!(host = %host_name, "PSRP pool hit (cached RunspacePool)");
                return Ok(PsrpConnection::from_parts(host_name));
            }
        }

        // Cold path: build new RunspacePool
        debug!(host = %host_name, "PSRP pool miss — creating new RunspacePool");

        // TODO: Wire actual psrp-rs RunspacePool creation:
        // 1. build_winrm_config(host_config) -> (WinrmConfig, WinrmCredentials)
        // 2. WinrmClient::new(config, creds)
        // 3. WinrmPsrpTransport::open(&client, host, creation_fragments)
        // 4. RunspacePool::open_with_transport(transport)

        let connection = PsrpConnection::from_parts(host_name);

        // Cache the new connection
        {
            let mut cache = self.inner.write().await;
            cache.insert(
                host_name.to_string(),
                PooledRunspace {
                    connection: PsrpConnection::from_parts(host_name),
                    last_used: Instant::now(),
                },
            );
        }

        Ok(connection)
    }

    /// Remove a cached entry (called on connection failure).
    pub async fn evict(&self, host_name: &str) {
        let mut cache = self.inner.write().await;
        if cache.remove(host_name).is_some() {
            debug!(host = %host_name, "Evicted PSRP RunspacePool from cache");
        }
    }

    /// Evict entries idle longer than `max_idle`.
    pub async fn cleanup(&self) {
        let max_idle = self.config.max_idle;
        let mut cache = self.inner.write().await;
        cache.retain(|host, entry| {
            let keep = entry.last_used.elapsed() < max_idle;
            if !keep {
                info!(host = %host, "Evicting idle PSRP RunspacePool");
            }
            keep
        });
    }

    /// Close all cached `RunspacePool` instances.
    pub async fn close_all(&self) {
        let mut cache = self.inner.write().await;
        cache.clear();
        info!("Closed all PSRP RunspacePool instances");
    }

    /// Number of cached entries (for tests).
    #[must_use]
    pub async fn size(&self) -> usize {
        self.inner.read().await.len()
    }
}

impl Default for PsrpPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PsrpPoolConfig::default();
        assert_eq!(config.max_idle, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_pool_new_is_empty() {
        let pool = PsrpPool::new();
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_close_all_empties_pool() {
        let pool = PsrpPool::new();
        // Insert a dummy entry
        {
            let mut cache = pool.inner.write().await;
            cache.insert(
                "test-host".to_string(),
                PooledRunspace {
                    connection: PsrpConnection::from_parts("test-host"),
                    last_used: Instant::now(),
                },
            );
        }
        assert_eq!(pool.size().await, 1);
        pool.close_all().await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_evict_removes_entry() {
        let pool = PsrpPool::new();
        {
            let mut cache = pool.inner.write().await;
            cache.insert(
                "host-a".to_string(),
                PooledRunspace {
                    connection: PsrpConnection::from_parts("host-a"),
                    last_used: Instant::now(),
                },
            );
        }
        assert_eq!(pool.size().await, 1);
        pool.evict("host-a").await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_cleanup_evicts_stale_entries() {
        let pool = PsrpPool::with_config(PsrpPoolConfig {
            max_idle: Duration::from_millis(1),
        });
        {
            let mut cache = pool.inner.write().await;
            cache.insert(
                "stale-host".to_string(),
                PooledRunspace {
                    connection: PsrpConnection::from_parts("stale-host"),
                    last_used: Instant::now() - Duration::from_secs(10),
                },
            );
        }
        assert_eq!(pool.size().await, 1);
        pool.cleanup().await;
        assert_eq!(pool.size().await, 0);
    }
}
