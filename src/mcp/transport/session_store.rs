//! Session store abstraction for the streamable HTTP transport.
//!
//! The current implementation keeps sessions in a per-process `HashMap`,
//! which prevents horizontal scaling (each replica sees its own sessions,
//! so a client that lands on replica B after initializing on replica A
//! gets 404). The 2026 MCP roadmap slates a stateless transport proposal
//! for June 2026; until then we at least want the persistence layer
//! behind a trait so a future `RedisSessionStore` or
//! `ValkeySessionStore` can be swapped in without touching the request
//! handlers.
//!
//! The trait purposefully stays narrow: the HTTP transport only needs to
//! insert on `initialize`, rotate the notification channel when a new
//! SSE connection attaches, remove on explicit `DELETE`, and expose the
//! current count for health checks. Any richer semantics (TTL eviction,
//! multi-process pub/sub for server-initiated requests) belong to the
//! concrete impl.

use std::collections::HashMap;
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::{RwLock, mpsc};

use crate::mcp::protocol::WriterMessage;

/// Per-session state required by the streamable HTTP transport.
#[derive(Debug, Clone)]
pub struct SessionData {
    /// Channel used to push notifications / server-initiated requests
    /// (elicitation, sampling, progress) back to the client SSE stream.
    pub notification_tx: mpsc::Sender<WriterMessage>,
    /// Creation timestamp, used by expiry sweeps and diagnostics.
    pub created_at: Instant,
}

/// Pluggable backing store for HTTP sessions.
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    /// Insert a new session. Overwrites any existing session with the
    /// same id (mirrors the current `HashMap::insert` semantics).
    async fn insert(&self, session_id: String, session: SessionData);

    /// Retrieve a clone of the notification sender, or `None` when the
    /// session is unknown or already closed.
    async fn get_tx(&self, session_id: &str) -> Option<mpsc::Sender<WriterMessage>>;

    /// Replace the notification sender for an existing session. Returns
    /// `true` when the session exists, `false` when it does not (the
    /// caller should answer with 404).
    async fn update_tx(&self, session_id: &str, tx: mpsc::Sender<WriterMessage>) -> bool;

    /// Remove a session. Returns `true` when a session was removed.
    async fn remove(&self, session_id: &str) -> bool;

    /// Number of active sessions. Used by `/health`.
    async fn count(&self) -> usize;
}

/// Default in-process implementation backed by a `RwLock<HashMap>`.
#[derive(Default)]
pub struct InMemorySessionStore {
    inner: RwLock<HashMap<String, SessionData>>,
}

impl InMemorySessionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn insert(&self, session_id: String, session: SessionData) {
        self.inner.write().await.insert(session_id, session);
    }

    async fn get_tx(&self, session_id: &str) -> Option<mpsc::Sender<WriterMessage>> {
        self.inner
            .read()
            .await
            .get(session_id)
            .map(|s| s.notification_tx.clone())
    }

    async fn update_tx(&self, session_id: &str, tx: mpsc::Sender<WriterMessage>) -> bool {
        if let Some(s) = self.inner.write().await.get_mut(session_id) {
            s.notification_tx = tx;
            true
        } else {
            false
        }
    }

    async fn remove(&self, session_id: &str) -> bool {
        self.inner.write().await.remove(session_id).is_some()
    }

    async fn count(&self) -> usize {
        self.inner.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_session() -> SessionData {
        let (tx, _rx) = mpsc::channel(1);
        SessionData {
            notification_tx: tx,
            created_at: Instant::now(),
        }
    }

    #[tokio::test]
    async fn insert_then_get_returns_tx() {
        let store = InMemorySessionStore::new();
        store.insert("s1".into(), sample_session()).await;
        assert!(store.get_tx("s1").await.is_some());
        assert!(store.get_tx("unknown").await.is_none());
    }

    #[tokio::test]
    async fn update_tx_replaces_existing() {
        let store = InMemorySessionStore::new();
        store.insert("s1".into(), sample_session()).await;
        let (new_tx, _new_rx) = mpsc::channel(1);
        assert!(store.update_tx("s1", new_tx).await);
        assert!(
            !store
                .update_tx("missing", sample_session().notification_tx)
                .await
        );
    }

    #[tokio::test]
    async fn remove_reports_deletion() {
        let store = InMemorySessionStore::new();
        store.insert("s1".into(), sample_session()).await;
        assert!(store.remove("s1").await);
        assert!(!store.remove("s1").await);
    }

    #[tokio::test]
    async fn count_tracks_insert_and_remove() {
        let store = InMemorySessionStore::new();
        assert_eq!(store.count().await, 0);
        store.insert("s1".into(), sample_session()).await;
        store.insert("s2".into(), sample_session()).await;
        assert_eq!(store.count().await, 2);
        store.remove("s1").await;
        assert_eq!(store.count().await, 1);
    }
}
