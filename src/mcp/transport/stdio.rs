//! Stdio Transport
//!
//! Reads JSON-RPC messages line-by-line from stdin and writes to stdout.
//! This is the default transport for Claude Code subprocess spawning.

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

impl Transport for StdioTransport {
    async fn recv(&mut self) -> Option<IncomingMessage> {
        let reader = self.reader.get_mut();

        loop {
            let mut line = String::new();

            let bytes_read = reader.read_line(&mut line).await.ok()?;
            if bytes_read == 0 {
                return None; // EOF
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue; // skip empty lines
            }

            debug!(request = %trimmed, "Received message");

            return match McpServer::parse_incoming(trimmed) {
                Ok(msg) => Some(msg),
                Err(e) => {
                    error!(error = %e, "Failed to parse message");
                    None
                }
            };
        }
    }

    async fn send(&self, msg: WriterMessage) -> crate::error::Result<()> {
        let json_str = match &msg {
            WriterMessage::Response(r) => serde_json::to_string(r),
            WriterMessage::Notification(n) => serde_json::to_string(n),
            WriterMessage::Request(r) => serde_json::to_string(&r),
            WriterMessage::BatchResponse(responses) => serde_json::to_string(responses),
        };
        let Ok(json_str) = json_str else {
            error!("Failed to serialize message");
            return Ok(());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stdio_transport_default() {
        // Default trait implementation should work
        let _transport = StdioTransport::default();
    }

    #[test]
    fn test_stdio_transport_new() {
        let _transport = StdioTransport::new();
    }

    #[test]
    fn test_parse_incoming_single_request() {
        let input = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let result = McpServer::parse_incoming(input);
        assert!(result.is_ok());
        match result.unwrap() {
            IncomingMessage::Single(msg) => {
                assert_eq!(msg.method.as_deref(), Some("initialize"));
                assert_eq!(msg.id, Some(serde_json::json!(1)));
            }
            IncomingMessage::Batch(_) => panic!("Expected Single, got Batch"),
        }
    }

    #[test]
    fn test_parse_incoming_batch() {
        let input = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"resources/list"}]"#;
        let result = McpServer::parse_incoming(input);
        assert!(result.is_ok());
        match result.unwrap() {
            IncomingMessage::Batch(msgs) => {
                assert_eq!(msgs.len(), 2);
                assert_eq!(msgs[0].method.as_deref(), Some("tools/list"));
                assert_eq!(msgs[1].method.as_deref(), Some("resources/list"));
            }
            IncomingMessage::Single(_) => panic!("Expected Batch, got Single"),
        }
    }

    #[test]
    fn test_parse_incoming_notification() {
        let input = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let result = McpServer::parse_incoming(input);
        assert!(result.is_ok());
        match result.unwrap() {
            IncomingMessage::Single(msg) => {
                assert_eq!(msg.method.as_deref(), Some("notifications/initialized"));
                assert!(msg.id.is_none());
            }
            IncomingMessage::Batch(_) => panic!("Expected Single, got Batch"),
        }
    }

    #[test]
    fn test_parse_incoming_invalid_json() {
        let input = "not valid json{{{";
        let result = McpServer::parse_incoming(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_incoming_empty_string() {
        let input = "";
        let result = McpServer::parse_incoming(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_incoming_empty_batch() {
        let input = "[]";
        let result = McpServer::parse_incoming(input);
        assert!(result.is_ok());
        match result.unwrap() {
            IncomingMessage::Batch(msgs) => assert!(msgs.is_empty()),
            IncomingMessage::Single(_) => panic!("Expected Batch, got Single"),
        }
    }

    #[test]
    fn test_parse_incoming_with_leading_whitespace() {
        let input = "   {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        let result = McpServer::parse_incoming(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_incoming_response_no_method() {
        let input = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let result = McpServer::parse_incoming(input);
        assert!(result.is_ok());
        match result.unwrap() {
            IncomingMessage::Single(msg) => {
                assert!(msg.method.is_none());
                assert_eq!(msg.id, Some(serde_json::json!(1)));
            }
            IncomingMessage::Batch(_) => panic!("Expected Single, got Batch"),
        }
    }

    #[tokio::test]
    async fn test_stdio_transport_shutdown() {
        let transport = StdioTransport::new();
        // Shutdown should be a no-op and not panic
        transport.shutdown().await;
    }

    #[test]
    fn test_writer_message_serialization() {
        use crate::mcp::protocol::{JsonRpcResponse, WriterMessage};

        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            result: Some(serde_json::json!({"tools": []})),
            error: None,
        };
        let msg = WriterMessage::Response(Box::new(response));

        // Verify serialization works (used by send())
        let json_str = match &msg {
            WriterMessage::Response(r) => serde_json::to_string(r),
            _ => unreachable!(),
        };
        assert!(json_str.is_ok());
        let s = json_str.unwrap();
        assert!(s.contains("\"jsonrpc\":\"2.0\""));
        assert!(s.contains("\"id\":1"));
    }
}
