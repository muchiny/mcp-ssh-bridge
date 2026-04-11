//! Per-connection handler for the daemon Unix socket.
//!
//! Each accepted Unix socket connection is passed to [`handle`], which
//! reads newline-delimited JSON-RPC messages from the client, dispatches
//! them to the shared [`McpServer`], and writes responses back.
//!
//! This module runs *alongside* `McpServer::run()` — it does NOT go
//! through the stdio-hardcoded writer loop. It calls
//! `McpServer::handle_request()` (and `parse_incoming`) directly, which
//! is why server-initiated notifications (elicitation, sampling,
//! logging) are currently not supported in daemon mode: those require
//! per-connection notification channels not exposed by the current
//! `McpServer` API.
//!
//! See [`crate::daemon`] module-level docs for the Sprint 2 scope
//! decisions that drove this minimal design.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::error::Result;
use crate::mcp::McpServer;
use crate::mcp::protocol::{IncomingMessage, JsonRpcRequest};

/// Handle a single Unix socket connection until the client disconnects.
///
/// Reads newline-delimited JSON-RPC messages, routes each `Single`
/// incoming request to [`McpServer::handle_request`], and writes the
/// response back to the same stream. Runs until EOF (client closes the
/// write side) or a fatal I/O error.
///
/// # Errors
///
/// Returns I/O errors from the underlying `UnixStream`. Malformed JSON
/// lines are logged but not fatal — the handler continues reading.
pub async fn handle(stream: UnixStream, server: Arc<McpServer>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                tracing::debug!("Daemon client disconnected");
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(error = %e, "Daemon read failed");
                return Err(crate::error::BridgeError::Io(e));
            }
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let incoming = match McpServer::parse_incoming(trimmed) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!(error = %e, line = %trimmed, "Daemon parse failed");
                continue;
            }
        };

        match incoming {
            IncomingMessage::Single(message) => {
                // Notifications (no id) are fire-and-forget — no response
                // is sent. We ignore `notifications/cancelled` here
                // because the daemon's per-connection model doesn't have
                // the `active_requests` registration needed to correlate
                // cancels; this is a Sprint 3 enhancement.
                if message.id.is_none() {
                    tracing::debug!(
                        method = ?message.method,
                        "Daemon received notification (no response)"
                    );
                    continue;
                }

                let Some(method) = message.method.clone() else {
                    tracing::warn!("Daemon received request without method");
                    continue;
                };

                let request = JsonRpcRequest {
                    jsonrpc: message.jsonrpc,
                    id: message.id,
                    method,
                    params: message.params,
                };

                let response = server.handle_request(request).await;

                let json =
                    serde_json::to_string(&response).map_err(crate::error::BridgeError::Json)?;
                writer
                    .write_all(json.as_bytes())
                    .await
                    .map_err(crate::error::BridgeError::Io)?;
                writer
                    .write_all(b"\n")
                    .await
                    .map_err(crate::error::BridgeError::Io)?;
                writer
                    .flush()
                    .await
                    .map_err(crate::error::BridgeError::Io)?;
            }
            IncomingMessage::Batch(_) => {
                // Batch support deferred to Sprint 3 — would require
                // per-batch fanout + collection that mirrors the stdio
                // `run()` loop.
                tracing::warn!("Daemon received batch request (unsupported in Sprint 2)");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, Config, HttpTransportConfig, LimitsConfig, SecurityConfig, SessionConfig,
        SshConfigDiscovery, ToolGroupsConfig,
    };
    use std::collections::HashMap;
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    fn test_config() -> Config {
        Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
            http: HttpTransportConfig::default(),
            rbac: crate::security::rbac::RbacConfig::default(),
            awx: None,
        }
    }

    /// Smoke test: spawn a listener in a tokio task, connect a client,
    /// send a `tools/list` request over the socket, read the response.
    /// Verifies the full wiring: parse → dispatch → serialize → write.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_daemon_connection_handles_tools_list() {
        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("test.sock");

        let listener = UnixListener::bind(&socket_path).unwrap();
        let (server, _audit_task) = McpServer::new(test_config());
        let server = Arc::new(server);

        // Accept in background.
        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                handle(stream, server).await
            })
        };

        // Client side.
        let mut client = UnixStream::connect(&socket_path).await.unwrap();
        let request = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":null}\n";
        client.write_all(request).await.unwrap();
        client.flush().await.unwrap();

        // Read one line from the response.
        let (r, _w) = client.split();
        let mut reader = BufReader::new(r);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await.unwrap();

        assert!(
            response_line.contains("\"jsonrpc\":\"2.0\""),
            "response must be JSON-RPC: {response_line}"
        );
        assert!(
            response_line.contains("\"result\""),
            "response must contain a result: {response_line}"
        );
        assert!(
            response_line.contains("\"tools\""),
            "result must contain tools list: {response_line}"
        );

        drop(client);
        // Give the handler task a moment to process EOF and return.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
    }

    /// Malformed JSON must not kill the handler — it should log and wait
    /// for the next line.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_daemon_connection_tolerates_malformed_json() {
        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("test.sock");

        let listener = UnixListener::bind(&socket_path).unwrap();
        let (server, _audit_task) = McpServer::new(test_config());
        let server = Arc::new(server);

        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                handle(stream, server).await
            })
        };

        let mut client = UnixStream::connect(&socket_path).await.unwrap();
        // Garbage line — should be logged and ignored.
        client.write_all(b"not json at all\n").await.unwrap();
        // Follow with a valid request to prove the loop is still alive.
        client
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"tools/list\",\"params\":null}\n",
            )
            .await
            .unwrap();
        client.flush().await.unwrap();

        let (r, _w) = client.split();
        let mut reader = BufReader::new(r);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await.unwrap();

        assert!(response_line.contains("\"id\":42"), "got: {response_line}");

        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
    }

    /// Notifications (id == None) must NOT generate a response. After a
    /// notification, a following request must still get its response.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_daemon_connection_notifications_produce_no_response() {
        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("test.sock");

        let listener = UnixListener::bind(&socket_path).unwrap();
        let (server, _audit_task) = McpServer::new(test_config());
        let server = Arc::new(server);

        let server_task = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                handle(stream, server).await
            })
        };

        let mut client = UnixStream::connect(&socket_path).await.unwrap();
        // Notification (no id field).
        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":\"x\"}}\n")
            .await
            .unwrap();
        // Then a real request to check the loop still responds.
        client
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"tools/list\",\"params\":null}\n",
            )
            .await
            .unwrap();
        client.flush().await.unwrap();

        let (r, _w) = client.split();
        let mut reader = BufReader::new(r);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await.unwrap();

        // The FIRST line we receive must be the response to the request
        // with id=99 — the notification must not have generated any
        // output on the stream.
        assert!(response_line.contains("\"id\":99"), "got: {response_line}");

        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
    }
}
