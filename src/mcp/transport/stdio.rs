//! Stdio Transport
//!
//! Reads JSON-RPC messages line-by-line from stdin and writes to stdout.
//! This is the default transport for Claude Code subprocess spawning.

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{debug, error};

use super::Transport;
use crate::mcp::protocol::{IncomingMessage, WriterMessage};
use crate::mcp::server::McpServer;

/// Stdio-based MCP transport (JSON-RPC over stdin/stdout).
pub struct StdioTransport {
    reader: Mutex<BufReader<tokio::io::Stdin>>,
    stdout: Mutex<tokio::io::Stdout>,
}

impl StdioTransport {
    /// Create a new stdio transport.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reader: Mutex::new(BufReader::new(tokio::io::stdin())),
            stdout: Mutex::new(tokio::io::stdout()),
        }
    }
}

impl Default for StdioTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn recv(&mut self) -> Option<IncomingMessage> {
        let reader = self.reader.get_mut();
        let mut line = String::new();

        let bytes_read = reader.read_line(&mut line).await.ok()?;
        if bytes_read == 0 {
            return None; // EOF
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            // Empty line: return a dummy to keep looping
            return self.recv().await;
        }

        debug!(request = %trimmed, "Received message");

        match McpServer::parse_incoming(trimmed) {
            Ok(msg) => Some(msg),
            Err(e) => {
                error!(error = %e, "Failed to parse message");
                // Return a parse error as a single message
                None
            }
        }
    }

    async fn send(&self, msg: WriterMessage) -> crate::error::Result<()> {
        let json_str = match &msg {
            WriterMessage::Response(r) => serde_json::to_string(r),
            WriterMessage::Notification(n) => serde_json::to_string(n),
            WriterMessage::Request(r) => serde_json::to_string(&r),
            WriterMessage::BatchResponse(responses) => serde_json::to_string(responses),
        };
        let json_str = match json_str {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Failed to serialize message");
                return Ok(());
            }
        };

        debug!(message = %json_str, "Sending message");

        let mut stdout = self.stdout.lock().await;
        stdout.write_all(json_str.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
        Ok(())
    }

    async fn shutdown(&self) {
        // Stdio doesn't need explicit shutdown
    }
}
