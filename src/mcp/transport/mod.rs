//! MCP Transport Layer
//!
//! Abstracts the transport mechanism (stdio vs HTTP) behind a common trait.
//! The MCP server operates on `Transport` without knowing the underlying I/O.

pub mod stdio;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "http")]
pub mod oauth;

use std::future::Future;

use super::protocol::{IncomingMessage, WriterMessage};

/// Transport abstraction for MCP JSON-RPC communication.
///
/// Implementations handle reading/writing JSON-RPC messages over
/// different transport mechanisms (stdio, HTTP/SSE).
pub trait Transport: Send + Sync {
    /// Receive the next incoming message from the client.
    /// Returns `None` on EOF / client disconnect.
    fn recv(&mut self) -> impl Future<Output = Option<IncomingMessage>> + Send;

    /// Send a message to the client.
    fn send(&self, msg: WriterMessage) -> impl Future<Output = crate::error::Result<()>> + Send;

    /// Gracefully shut down the transport.
    fn shutdown(&self) -> impl Future<Output = ()> + Send;
}

#[cfg(test)]
mod tests {
    // Note: Transport uses RPITIT (native async fn in traits) and is
    // intentionally NOT dyn-compatible. It is always used via concrete types.
}
