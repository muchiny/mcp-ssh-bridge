//! Streamable HTTP Transport (MCP 2025-11-25)
//!
//! Implements the MCP Streamable HTTP transport:
//! - `POST /mcp` — Receive JSON-RPC requests, return responses
//! - `GET /mcp` — SSE stream for server-to-client notifications
//! - `DELETE /mcp` — Close a session
//!
//! Sessions are identified by the `Mcp-Session-Id` header.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::Value;
use tokio::sync::{RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;

use super::oauth::{OAuthConfig, OAuthMetadata};

use crate::mcp::protocol::{
    IncomingMessage, JsonRpcError, JsonRpcMessage, JsonRpcResponse, WriterMessage,
};
use crate::mcp::server::McpServer;

/// Configuration for the HTTP transport.
#[derive(Debug, Clone)]
pub struct HttpTransportConfig {
    /// Bind address (e.g., `"0.0.0.0:3000"`).
    pub bind: String,
    /// Maximum request body size in bytes (default: 1MB).
    pub max_body_size: usize,
    /// Session timeout (default: 30 minutes).
    pub session_timeout: Duration,
    /// Maximum concurrent sessions (default: 100).
    pub max_sessions: usize,
    /// OAuth configuration (disabled by default).
    pub oauth: OAuthConfig,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:3000".to_string(),
            max_body_size: 1_048_576,
            session_timeout: Duration::from_secs(1800),
            max_sessions: 100,
            oauth: OAuthConfig::default(),
        }
    }
}

/// A connected HTTP session.
struct HttpSession {
    /// Channel for sending notifications/responses back to the SSE stream.
    notification_tx: mpsc::Sender<WriterMessage>,
    /// Created at timestamp.
    created_at: std::time::Instant,
}

impl HttpSession {
    /// Check if this session has expired (used during session cleanup).
    #[allow(dead_code)]
    fn is_expired(&self, timeout: Duration) -> bool {
        self.created_at.elapsed() > timeout
    }
}

/// Shared state for the HTTP transport.
pub struct HttpTransportState {
    sessions: RwLock<HashMap<String, HttpSession>>,
    config: HttpTransportConfig,
    /// The MCP server processes requests from any session.
    server: Arc<McpServer>,
    /// OAuth configuration.
    oauth: Arc<OAuthConfig>,
}

/// Build the axum Router for the MCP HTTP transport.
pub fn build_router(server: Arc<McpServer>, config: HttpTransportConfig) -> Router {
    let oauth_config = Arc::new(config.oauth.clone());

    let state = Arc::new(HttpTransportState {
        sessions: RwLock::new(HashMap::new()),
        config,
        server,
        oauth: Arc::clone(&oauth_config),
    });

    let mut router = Router::new()
        .route("/mcp", post(handle_post))
        .route("/mcp", get(handle_sse))
        .route("/mcp", delete(handle_delete));

    // Add OAuth middleware if enabled
    if oauth_config.enabled {
        router = router.layer(axum::middleware::from_fn(super::oauth::oauth_middleware));
        router = router.layer(axum::Extension(Arc::clone(&oauth_config)));
    }

    // Discovery and health endpoints (not behind OAuth)
    let discovery_router = Router::new()
        .route("/.well-known/mcp.json", get(handle_mcp_discovery))
        .route(
            "/.well-known/oauth-authorization-server",
            get(handle_oauth_discovery),
        )
        .route("/health", get(handle_health))
        .with_state(Arc::clone(&state));

    router
        .layer(RequestBodyLimitLayer::new(state.config.max_body_size))
        .layer(CorsLayer::permissive())
        .with_state(state)
        .merge(discovery_router)
}

/// Start the HTTP transport server.
///
/// This binds to the configured address and serves MCP over HTTP.
pub async fn serve(
    server: Arc<McpServer>,
    config: HttpTransportConfig,
) -> crate::error::Result<()> {
    let bind = config.bind.clone();
    let router = build_router(server, config);

    info!(bind = %bind, "Starting MCP HTTP transport");

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, router)
        .await
        .map_err(|e| crate::error::BridgeError::McpProtocol(format!("HTTP server error: {e}")))?;

    Ok(())
}

/// Extract or create session ID from headers.
fn get_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Generate a new session ID.
fn new_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// POST /mcp — Handle JSON-RPC requests.
async fn handle_post(
    State(state): State<Arc<HttpTransportState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // Parse the request
    let incoming = if body.is_array() {
        match serde_json::from_value::<Vec<JsonRpcMessage>>(body) {
            Ok(msgs) => IncomingMessage::Batch(msgs),
            Err(e) => {
                let resp = JsonRpcResponse::error(
                    None,
                    JsonRpcError::parse_error(format!("Invalid batch: {e}")),
                );
                return Json(resp).into_response();
            }
        }
    } else {
        match serde_json::from_value::<JsonRpcMessage>(body) {
            Ok(msg) => IncomingMessage::Single(msg),
            Err(e) => {
                let resp = JsonRpcResponse::error(
                    None,
                    JsonRpcError::parse_error(format!("Invalid JSON-RPC: {e}")),
                );
                return Json(resp).into_response();
            }
        }
    };

    // Get or create session
    let session_id = get_session_id(&headers).unwrap_or_else(new_session_id);

    // Check if this is an initialize request — create session
    let is_initialize = match &incoming {
        IncomingMessage::Single(msg) => msg.method.as_deref() == Some("initialize"),
        IncomingMessage::Batch(_) => false,
    };

    if is_initialize {
        let sessions = state.sessions.read().await;
        if sessions.len() >= state.config.max_sessions {
            let resp = JsonRpcResponse::error(
                None,
                JsonRpcError::internal_error("Maximum sessions reached"),
            );
            return Json(resp).into_response();
        }
        drop(sessions);

        // Create session channels
        let (notif_tx, _notif_rx) = mpsc::channel::<WriterMessage>(100);

        let session = HttpSession {
            notification_tx: notif_tx,
            created_at: std::time::Instant::now(),
        };

        state
            .sessions
            .write()
            .await
            .insert(session_id.clone(), session);
    }

    // Process the request through the MCP server
    match incoming {
        IncomingMessage::Single(msg) => {
            if msg.method.is_none() {
                return StatusCode::NO_CONTENT.into_response();
            }
            let request = crate::mcp::protocol::JsonRpcRequest {
                jsonrpc: msg.jsonrpc,
                id: msg.id,
                method: msg.method.unwrap_or_default(),
                params: msg.params,
            };
            let resp = state.server.handle_request(request).await;
            let mut response = Json(resp).into_response();
            response.headers_mut().insert(
                "mcp-session-id",
                session_id
                    .parse()
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
            );
            response
        }
        IncomingMessage::Batch(msgs) => {
            let mut responses = Vec::new();
            for msg in msgs {
                if msg.method.is_none() {
                    continue;
                }
                let request = crate::mcp::protocol::JsonRpcRequest {
                    jsonrpc: msg.jsonrpc,
                    id: msg.id.clone(),
                    method: msg.method.unwrap_or_default(),
                    params: msg.params,
                };
                let is_notification = request.id.is_none();
                let resp = state.server.handle_request(request).await;
                if !is_notification {
                    responses.push(resp);
                }
            }
            let mut response = Json(responses).into_response();
            response.headers_mut().insert(
                "mcp-session-id",
                session_id
                    .parse()
                    .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
            );
            response
        }
    }
}

/// GET /mcp — SSE stream for server-to-client notifications.
async fn handle_sse(State(state): State<Arc<HttpTransportState>>, headers: HeaderMap) -> Response {
    let Some(session_id) = get_session_id(&headers) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    // Create a notification channel for this SSE connection
    let (notif_tx, notif_rx) = mpsc::channel::<WriterMessage>(100);

    // Update session with the new notification channel
    {
        let mut sessions = state.sessions.write().await;
        let Some(session) = sessions.get_mut(&session_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        session.notification_tx = notif_tx;
    }

    // Convert channel to SSE stream of Result<Event, Infallible>
    let stream = ReceiverStream::new(notif_rx);
    let sse_stream = tokio_stream::StreamExt::filter_map(stream, |msg| {
        let json_str = match &msg {
            WriterMessage::Response(r) => serde_json::to_string(&**r).ok(),
            WriterMessage::Notification(n) => serde_json::to_string(n).ok(),
            WriterMessage::Request(r) => serde_json::to_string(r).ok(),
            WriterMessage::BatchResponse(rs) => serde_json::to_string(rs).ok(),
        };
        json_str.map(|data| Ok::<_, Infallible>(Event::default().event("message").data(data)))
    });

    Sse::new(sse_stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// DELETE /mcp — Close a session.
async fn handle_delete(
    State(state): State<Arc<HttpTransportState>>,
    headers: HeaderMap,
) -> StatusCode {
    let Some(session_id) = get_session_id(&headers) else {
        return StatusCode::BAD_REQUEST;
    };

    if state.sessions.write().await.remove(&session_id).is_some() {
        info!(session = %session_id, "Session closed");
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// GET /.well-known/mcp.json — MCP server discovery metadata.
async fn handle_mcp_discovery(State(state): State<Arc<HttpTransportState>>) -> Response {
    let bind = &state.config.bind;
    let base_url = format!("http://{bind}");

    Json(serde_json::json!({
        "mcp": {
            "version": "2025-11-25",
            "transport": {
                "type": "streamable-http",
                "url": format!("{base_url}/mcp"),
            },
            "capabilities": {
                "tools": true,
                "resources": true,
                "prompts": true,
                "roots": true,
            },
            "oauth": if state.oauth.enabled {
                serde_json::json!({
                    "authorization_server": format!("{base_url}/.well-known/oauth-authorization-server"),
                })
            } else {
                serde_json::json!(null)
            },
        }
    }))
    .into_response()
}

/// GET /.well-known/oauth-authorization-server — OAuth metadata (RFC 8414).
async fn handle_oauth_discovery(State(state): State<Arc<HttpTransportState>>) -> Response {
    if !state.oauth.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let base_url = format!("http://{}", state.config.bind);
    let metadata = OAuthMetadata::from_config(&state.oauth, &base_url);
    Json(metadata).into_response()
}

/// GET /health — Simple health check endpoint.
async fn handle_health(State(state): State<Arc<HttpTransportState>>) -> Response {
    let sessions = state.sessions.read().await;
    Json(serde_json::json!({
        "status": "ok",
        "sessions": sessions.len(),
        "max_sessions": state.config.max_sessions,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HttpTransportConfig::default();
        assert_eq!(config.bind, "0.0.0.0:3000");
        assert_eq!(config.max_body_size, 1_048_576);
        assert_eq!(config.max_sessions, 100);
    }

    #[test]
    fn test_new_session_id_is_uuid() {
        let id = new_session_id();
        assert_eq!(id.len(), 36); // UUID v4 format
        assert!(id.contains('-'));
    }

    #[test]
    fn test_get_session_id_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", "test-session-123".parse().unwrap());
        assert_eq!(
            get_session_id(&headers),
            Some("test-session-123".to_string())
        );
    }

    #[test]
    fn test_get_session_id_missing() {
        let headers = HeaderMap::new();
        assert_eq!(get_session_id(&headers), None);
    }

    #[test]
    fn test_default_config_session_timeout() {
        let config = HttpTransportConfig::default();
        assert_eq!(config.session_timeout, Duration::from_secs(1800));
    }

    #[test]
    fn test_default_config_oauth_disabled() {
        let config = HttpTransportConfig::default();
        assert!(!config.oauth.enabled);
    }

    #[test]
    fn test_new_session_id_uniqueness() {
        let id1 = new_session_id();
        let id2 = new_session_id();
        assert_ne!(id1, id2, "Session IDs must be unique");
    }

    #[test]
    fn test_new_session_id_valid_uuid_v4() {
        let id = new_session_id();
        // UUID v4 has format: 8-4-4-4-12
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }

    #[test]
    fn test_get_session_id_case_sensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", "CaSe-SenSiTiVe-123".parse().unwrap());
        assert_eq!(
            get_session_id(&headers),
            Some("CaSe-SenSiTiVe-123".to_string())
        );
    }

    #[test]
    fn test_get_session_id_uuid_value() {
        let uuid = new_session_id();
        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", uuid.parse().unwrap());
        assert_eq!(get_session_id(&headers), Some(uuid));
    }

    #[test]
    fn test_session_is_expired_false() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let session = HttpSession {
            notification_tx: tx,
            created_at: std::time::Instant::now(),
        };
        assert!(!session.is_expired(Duration::from_secs(60)));
    }

    #[test]
    fn test_session_is_expired_true() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let session = HttpSession {
            notification_tx: tx,
            created_at: std::time::Instant::now() - Duration::from_secs(120),
        };
        assert!(session.is_expired(Duration::from_secs(60)));
    }

    #[test]
    fn test_custom_config() {
        let config = HttpTransportConfig {
            bind: "127.0.0.1:8080".to_string(),
            max_body_size: 2_097_152,
            session_timeout: Duration::from_secs(600),
            max_sessions: 50,
            oauth: OAuthConfig::default(),
        };
        assert_eq!(config.bind, "127.0.0.1:8080");
        assert_eq!(config.max_body_size, 2_097_152);
        assert_eq!(config.session_timeout, Duration::from_secs(600));
        assert_eq!(config.max_sessions, 50);
    }

    #[test]
    fn test_config_clone() {
        let config = HttpTransportConfig::default();
        let cloned = config.clone();
        assert_eq!(config.bind, cloned.bind);
        assert_eq!(config.max_body_size, cloned.max_body_size);
        assert_eq!(config.max_sessions, cloned.max_sessions);
    }

    #[test]
    fn test_config_debug() {
        let config = HttpTransportConfig::default();
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("HttpTransportConfig"));
        assert!(debug_str.contains("3000"));
    }
}
