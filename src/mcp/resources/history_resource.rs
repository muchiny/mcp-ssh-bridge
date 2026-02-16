//! History Resource Handler
//!
//! Exposes recent command history as an MCP resource.
//! URI format: `history://recent`
//!
//! This resource reads directly from the in-memory `CommandHistory`
//! without needing an SSH connection.

use async_trait::async_trait;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::{ResourceContent, ResourceDefinition};
use crate::ports::{ResourceHandler, ToolContext};

/// Resource handler for command history
pub struct HistoryResourceHandler;

#[async_trait]
impl ResourceHandler for HistoryResourceHandler {
    fn scheme(&self) -> &'static str {
        "history"
    }

    fn description(&self) -> &'static str {
        "Recent command execution history"
    }

    async fn list(&self, _ctx: &ToolContext) -> Result<Vec<ResourceDefinition>> {
        Ok(vec![ResourceDefinition {
            uri: "history://recent".to_string(),
            name: "Recent command history".to_string(),
            description: Some("Last 50 commands executed through the SSH bridge".to_string()),
            mime_type: Some("application/json".to_string()),
        }])
    }

    async fn read(&self, uri: &str, ctx: &ToolContext) -> Result<Vec<ResourceContent>> {
        if uri != "history://recent" {
            return Err(BridgeError::McpInvalidRequest(format!(
                "Invalid history URI: {uri}. Only 'history://recent' is supported."
            )));
        }

        let entries = ctx.history.recent(50);
        let json = serde_json::to_string_pretty(&entries)
            .unwrap_or_else(|e| format!("Error serializing history: {e}"));

        Ok(vec![ResourceContent {
            uri: uri.to_string(),
            mime_type: Some("application/json".to_string()),
            text: Some(json),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_scheme() {
        let handler = HistoryResourceHandler;
        assert_eq!(handler.scheme(), "history");
        assert!(!handler.description().is_empty());
    }

    #[tokio::test]
    async fn test_list_returns_single_resource() {
        let handler = HistoryResourceHandler;
        let ctx = create_test_context();

        let resources = handler.list(&ctx).await.unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "history://recent");
        assert_eq!(resources[0].mime_type.as_deref(), Some("application/json"));
    }

    #[tokio::test]
    async fn test_read_empty_history() {
        let handler = HistoryResourceHandler;
        let ctx = create_test_context();

        let contents = handler.read("history://recent", &ctx).await.unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].uri, "history://recent");

        // Empty history should produce valid JSON (empty array)
        let text = contents[0].text.as_deref().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_read_with_history_entries() {
        use crate::domain::CommandHistory;
        use crate::ports::mock::create_test_context_with_history;
        use std::sync::Arc;

        let history = Arc::new(CommandHistory::with_defaults());
        history.record_success("server1", "uptime", 0, 150);
        history.record_success("server2", "df -h", 0, 200);

        let ctx = create_test_context_with_history(history);
        let handler = HistoryResourceHandler;

        let contents = handler.read("history://recent", &ctx).await.unwrap();
        let text = contents[0].text.as_deref().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        let entries = parsed.as_array().unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn test_read_invalid_uri() {
        let handler = HistoryResourceHandler;
        let ctx = create_test_context();

        let result = handler.read("history://unknown", &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("history://unknown"));
            }
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
