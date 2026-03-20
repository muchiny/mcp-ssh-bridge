//! MCP Transport Layer
//!
//! Abstracts the transport mechanism (stdio vs HTTP) behind a common trait.
//! The MCP server operates on `Transport` without knowing the underlying I/O.

pub mod stdio;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "http")]
pub mod oauth;

use async_trait::async_trait;

use super::protocol::{IncomingMessage, WriterMessage};

/// Transport abstraction for MCP JSON-RPC communication.
///
/// Implementations handle reading/writing JSON-RPC messages over
/// different transport mechanisms (stdio, HTTP/SSE).
#[async_trait]
pub trait Transport: Send + Sync {
    /// Receive the next incoming message from the client.
    /// Returns `None` on EOF / client disconnect.
    async fn recv(&mut self) -> Option<IncomingMessage>;

    /// Send a message to the client.
    async fn send(&self, msg: WriterMessage) -> crate::error::Result<()>;

    /// Gracefully shut down the transport.
    async fn shutdown(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify the trait is object-safe
    fn _assert_object_safe(_: &dyn Transport) {}
}
