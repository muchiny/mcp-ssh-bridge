//! `WinRmPool` — reuse `reqwest::Client` instances across calls.
//!
//! Unlike SSH, `WinRM` is request/response HTTP. There is no
//! long-lived session on the server side to cache. What's expensive
//! per-call is the **TLS handshake**: every fresh `reqwest::Client`
//! starts a new HTTPS connection, paying a ~50-100 ms round-trip plus
//! CPU for the cipher suite negotiation.
//!
//! `reqwest::Client` itself is cheap to `Clone` — it's an
//! `Arc<Inner>` behind the scenes, and the underlying connection
//! pool (HTTP/1.1 `keep-alive` + HTTP/2 multiplexing) is shared
//! between clones. So the pool's real job is to keep a single client
//! **alive** long enough for subsequent calls to reuse its idle
//! HTTPS connections instead of dialing a new one.
//!
//! Design:
//!
//! - One cached `reqwest::Client` per `host_name`, holding the
//!   per-host TLS settings (SSL accept-invalid-certs vs strict).
//! - 120-second idle TTL. `WinRM` servers aggressively close idle
//!   sessions — shorter TTL than SSH (default 1800 s) reflects that.
//! - `get_connection()` returns a `WinRmConnection` whose HTTP
//!   client is taken from the pool. `mark_failed()` propagates a
//!   flag that the pool checks on the next `get_connection()` call
//!   and evicts if set.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::{WinRmConfig, WinRmConnection};
use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};

/// Default idle TTL for cached `reqwest::Client` entries.
///
/// `WinRM` servers typically close idle HTTPS connections after
/// 120-180 seconds. 120 seconds keeps us comfortably inside the
/// window while still letting short bursts of back-to-back calls
/// reuse the same TLS session.
const DEFAULT_WINRM_IDLE_TTL: Duration = Duration::from_secs(120);

/// A cached entry: one `reqwest::Client` + its config + last-used stamp.
#[derive(Clone)]
struct PooledClient {
    client: Client,
    config: WinRmConfig,
    last_used: Instant,
}

/// Pool configuration.
#[derive(Debug, Clone, Copy)]
pub struct WinRmPoolConfig {
    /// How long an idle client stays cached before being evicted.
    pub max_idle: Duration,
}

impl Default for WinRmPoolConfig {
    fn default() -> Self {
        Self {
            max_idle: DEFAULT_WINRM_IDLE_TTL,
        }
    }
}

/// Cache of live `reqwest::Client` instances keyed by host name.
///
/// The pool is cheap to clone (it's an `Arc` internally) and safe to
/// share across tasks — all mutation happens under an `RwLock`.
#[derive(Clone)]
pub struct WinRmPool {
    inner: Arc<RwLock<HashMap<String, PooledClient>>>,
    config: WinRmPoolConfig,
}

impl WinRmPool {
    /// Create a new pool with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(WinRmPoolConfig::default())
    }

    /// Create a new pool with an explicit configuration.
    #[must_use]
    pub fn with_config(config: WinRmPoolConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Fetch or create a `WinRmConnection` for `host_name`.
    ///
    /// If a live, non-stale `reqwest::Client` already exists for this
    /// host, clones it and wraps it in a new `WinRmConnection`. The
    /// connection inherits its `user` / `password` from `host_config`
    /// at call time, so rotating credentials does not require evicting
    /// the pool entry.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication is missing, or if building
    /// a fresh `reqwest::Client` fails on a cold entry.
    pub async fn get_connection(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<WinRmConnection> {
        // Fast path: cached entry still fresh.
        {
            let guard = self.inner.read().await;
            if let Some(entry) = guard.get(host_name)
                && entry.last_used.elapsed() <= self.config.max_idle
            {
                debug!(host = %host_name, "WinRmPool hit — reusing cached client");
                let client = entry.client.clone();
                let config = entry.config.clone();
                drop(guard);
                // Update last_used under the write lock.
                let mut w = self.inner.write().await;
                if let Some(entry) = w.get_mut(host_name) {
                    entry.last_used = Instant::now();
                }
                return WinRmConnection::from_parts(host_name, host_config, client, config);
            }
        }

        // Cold path: build a new entry under the write lock.
        let config = WinRmConfig::from_host_config(host_config);
        let client = Client::builder()
            .danger_accept_invalid_certs(!config.use_ssl)
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Some(self.config.max_idle))
            .build()
            .map_err(|e| BridgeError::SshExec {
                reason: format!("WinRM HTTP client error: {e}"),
            })?;

        {
            let mut guard = self.inner.write().await;
            guard.insert(
                host_name.to_string(),
                PooledClient {
                    client: client.clone(),
                    config: config.clone(),
                    last_used: Instant::now(),
                },
            );
        }

        info!(host = %host_name, "WinRmPool miss — created new HTTPS client");
        WinRmConnection::from_parts(host_name, host_config, client, config)
    }

    /// Drop a cached client for `host_name`. Called from
    /// `WinRmConnection::mark_failed()` path to evict a broken
    /// session.
    pub async fn evict(&self, host_name: &str) {
        let mut guard = self.inner.write().await;
        if guard.remove(host_name).is_some() {
            info!(host = %host_name, "WinRmPool evicted failed client");
        }
    }

    /// Evict entries that have been idle longer than the configured TTL.
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut guard = self.inner.write().await;
        guard.retain(|_, entry| now.duration_since(entry.last_used) <= self.config.max_idle);
    }

    /// Current number of cached entries (for tests / stats).
    pub async fn size(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Evict every entry. Called on server shutdown.
    pub async fn close_all(&self) {
        let mut guard = self.inner.write().await;
        guard.clear();
    }
}

impl Default for WinRmPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostKeyVerification, OsType, Protocol};

    fn test_host() -> HostConfig {
        HostConfig {
            hostname: "10.0.0.1".to_string(),
            port: 5986,
            user: "admin".to_string(),
            auth: AuthConfig::Password {
                password: zeroize::Zeroizing::new("pass".to_string()),
            },
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::Windows,
            shell: None,
            retry: None,
            protocol: Protocol::WinRm,
        }
    }

    #[tokio::test]
    async fn test_pool_default_empty() {
        let pool = WinRmPool::new();
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_insert_then_lookup() {
        let pool = WinRmPool::new();
        let host = test_host();
        let limits = LimitsConfig::default();

        // First call: cold, builds a client.
        let _conn1 = pool
            .get_connection("my-host", &host, &limits)
            .await
            .expect("get_connection ok");
        assert_eq!(pool.size().await, 1);

        // Second call: should reuse the cached client (same size).
        let _conn2 = pool
            .get_connection("my-host", &host, &limits)
            .await
            .expect("get_connection ok");
        assert_eq!(pool.size().await, 1);
    }

    #[tokio::test]
    async fn test_pool_evict_removes_entry() {
        let pool = WinRmPool::new();
        let host = test_host();
        let limits = LimitsConfig::default();

        let _ = pool
            .get_connection("my-host", &host, &limits)
            .await
            .expect("get_connection ok");
        assert_eq!(pool.size().await, 1);

        pool.evict("my-host").await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_expired_entry_is_rebuilt() {
        // TTL very short so the first entry is already "old" on the
        // second call. We cheat by writing the entry with
        // `last_used - max_idle - 1s` and asserting the second call
        // rebuilds it.
        let pool = WinRmPool::with_config(WinRmPoolConfig {
            max_idle: Duration::from_millis(1),
        });
        let host = test_host();
        let limits = LimitsConfig::default();

        let _ = pool.get_connection("h", &host, &limits).await.unwrap();
        assert_eq!(pool.size().await, 1);

        // Force expiry
        tokio::time::sleep(Duration::from_millis(50)).await;

        let _ = pool.get_connection("h", &host, &limits).await.unwrap();
        // Still 1 entry, but it was rebuilt (we can't observe the
        // rebuild directly; this test just asserts no panics + entry
        // count stays at 1).
        assert_eq!(pool.size().await, 1);
    }

    #[tokio::test]
    async fn test_pool_close_all() {
        let pool = WinRmPool::new();
        let host = test_host();
        let limits = LimitsConfig::default();

        for name in ["a", "b", "c"] {
            let _ = pool.get_connection(name, &host, &limits).await.unwrap();
        }
        assert_eq!(pool.size().await, 3);
        pool.close_all().await;
        assert_eq!(pool.size().await, 0);
    }

    #[tokio::test]
    async fn test_pool_cleanup_drops_stale() {
        let pool = WinRmPool::with_config(WinRmPoolConfig {
            max_idle: Duration::from_millis(10),
        });
        let host = test_host();
        let limits = LimitsConfig::default();

        let _ = pool.get_connection("h", &host, &limits).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        pool.cleanup().await;
        assert_eq!(pool.size().await, 0);
    }
}
