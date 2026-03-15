//! MCP Sampling Service
//!
//! Allows the server to request LLM analysis from the client via
//! `sampling/createMessage`. Supports tool definitions (SEP-1577).
//!
//! Use cases:
//! - Analyze complex command output (dmesg, journalctl)
//! - Suggest fixes for failed commands
//! - Parse unstructured log output into structured data

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::client_requester::{ClientRequestError, ClientRequester};
use super::protocol::{
    SamplingContent, SamplingCreateMessageParams, SamplingCreateMessageResult, SamplingMessage,
    SamplingTool,
};

/// MCP Sampling service (server asks client's LLM to analyze data).
pub struct SamplingService {
    requester: Arc<ClientRequester>,
    client_supports: AtomicBool,
}

impl SamplingService {
    /// Create a new sampling service.
    #[must_use]
    pub fn new(requester: Arc<ClientRequester>) -> Self {
        Self {
            requester,
            client_supports: AtomicBool::new(false),
        }
    }

    /// Set whether the client supports sampling (called during initialize).
    pub fn set_supported(&self, supported: bool) {
        self.client_supports.store(supported, Ordering::Relaxed);
    }

    /// Whether the client supports sampling.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.client_supports.load(Ordering::Relaxed)
    }

    /// Request LLM analysis of text content.
    ///
    /// # Errors
    ///
    /// Returns `ClientRequestError::NotSupported` if the client doesn't support
    /// sampling, or other errors on communication failure.
    pub async fn analyze(
        &self,
        prompt: &str,
        content: &str,
        max_tokens: u32,
    ) -> Result<SamplingCreateMessageResult, ClientRequestError> {
        self.analyze_with_tools(prompt, content, Vec::new(), max_tokens)
            .await
    }

    /// Request LLM analysis with tool definitions (SEP-1577).
    ///
    /// # Errors
    ///
    /// Returns an error if the client doesn't support sampling or communication fails.
    pub async fn analyze_with_tools(
        &self,
        prompt: &str,
        content: &str,
        tools: Vec<SamplingTool>,
        max_tokens: u32,
    ) -> Result<SamplingCreateMessageResult, ClientRequestError> {
        if !self.is_supported() {
            return Err(ClientRequestError::NotSupported);
        }

        let params = SamplingCreateMessageParams {
            messages: vec![SamplingMessage {
                role: "user".to_string(),
                content: SamplingContent::Text {
                    text: format!("{prompt}\n\n{content}"),
                },
            }],
            model_preferences: None,
            system_prompt: None,
            include_context: Some("thisServer".to_string()),
            max_tokens,
            tools: if tools.is_empty() { None } else { Some(tools) },
        };

        let value = self
            .requester
            .send_request(
                "sampling/createMessage",
                serde_json::to_value(&params).map_err(|_| ClientRequestError::ChannelClosed)?,
            )
            .await?;

        serde_json::from_value(value).map_err(|_| ClientRequestError::RemoteError {
            code: -1,
            message: "Invalid sampling response".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::pending_requests::PendingRequests;
    use std::time::Duration;
    use tokio::sync::mpsc;

    fn create_test_service() -> (
        SamplingService,
        mpsc::Receiver<super::super::protocol::WriterMessage>,
    ) {
        let (tx, rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = Arc::new(ClientRequester::new(tx, pending, Duration::from_secs(5)));
        (SamplingService::new(requester), rx)
    }

    #[tokio::test]
    async fn test_analyze_not_supported() {
        let (service, _rx) = create_test_service();
        let result = service.analyze("test", "content", 100).await;
        assert!(matches!(result, Err(ClientRequestError::NotSupported)));
    }

    #[test]
    fn test_set_supported() {
        let (service, _rx) = create_test_service();
        assert!(!service.is_supported());
        service.set_supported(true);
        assert!(service.is_supported());
    }

    #[test]
    fn test_set_supported_toggle() {
        let (service, _rx) = create_test_service();
        service.set_supported(true);
        assert!(service.is_supported());
        service.set_supported(false);
        assert!(!service.is_supported());
    }

    #[tokio::test]
    async fn test_analyze_with_tools_not_supported() {
        let (service, _rx) = create_test_service();
        let tools = vec![SamplingTool {
            name: "test_tool".to_string(),
            description: "A test tool".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        }];
        let result = service
            .analyze_with_tools("prompt", "content", tools, 100)
            .await;
        assert!(matches!(result, Err(ClientRequestError::NotSupported)));
    }

    #[tokio::test]
    async fn test_analyze_sends_correct_method() {
        use crate::mcp::pending_requests::ClientResponse;
        use crate::mcp::protocol::WriterMessage;

        let (tx, mut rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = Arc::new(ClientRequester::new(
            tx,
            Arc::clone(&pending),
            Duration::from_secs(5),
        ));
        let service = SamplingService::new(requester);
        service.set_supported(true);

        let pending_clone = Arc::clone(&pending);
        tokio::spawn(async move {
            if let Some(WriterMessage::Request(req)) = rx.recv().await {
                assert_eq!(req.method, "sampling/createMessage");
                let params = req.params.unwrap();
                let messages = params["messages"].as_array().unwrap();
                assert_eq!(messages.len(), 1);
                let text = messages[0]["content"]["text"].as_str().unwrap();
                assert!(text.contains("Analyze this"));
                assert!(text.contains("test data"));

                let id = req.id.as_str().unwrap().to_string();
                pending_clone.resolve(
                    &id,
                    ClientResponse::Success(serde_json::json!({
                        "role": "assistant",
                        "content": {"type": "text", "text": "analysis result"},
                        "model": "test-model"
                    })),
                );
            }
        });

        let result = service
            .analyze("Analyze this", "test data", 500)
            .await
            .unwrap();
        assert_eq!(result.role, "assistant");
        assert_eq!(result.model, "test-model");
    }

    #[tokio::test]
    async fn test_analyze_with_tools_includes_tools_in_params() {
        use crate::mcp::pending_requests::ClientResponse;
        use crate::mcp::protocol::WriterMessage;

        let (tx, mut rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = Arc::new(ClientRequester::new(
            tx,
            Arc::clone(&pending),
            Duration::from_secs(5),
        ));
        let service = SamplingService::new(requester);
        service.set_supported(true);

        let pending_clone = Arc::clone(&pending);
        tokio::spawn(async move {
            if let Some(WriterMessage::Request(req)) = rx.recv().await {
                let params = req.params.unwrap();
                let tools = params["tools"].as_array().unwrap();
                assert_eq!(tools.len(), 1);
                assert_eq!(tools[0]["name"], "my_tool");

                let id = req.id.as_str().unwrap().to_string();
                pending_clone.resolve(
                    &id,
                    ClientResponse::Success(serde_json::json!({
                        "role": "assistant",
                        "content": {"type": "text", "text": "done"},
                        "model": "test"
                    })),
                );
            }
        });

        let tools = vec![SamplingTool {
            name: "my_tool".to_string(),
            description: "desc".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
        }];
        let result = service
            .analyze_with_tools("prompt", "content", tools, 200)
            .await
            .unwrap();
        assert_eq!(result.role, "assistant");
    }

    #[tokio::test]
    async fn test_analyze_empty_tools_omitted_from_params() {
        use crate::mcp::pending_requests::ClientResponse;
        use crate::mcp::protocol::WriterMessage;

        let (tx, mut rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = Arc::new(ClientRequester::new(
            tx,
            Arc::clone(&pending),
            Duration::from_secs(5),
        ));
        let service = SamplingService::new(requester);
        service.set_supported(true);

        let pending_clone = Arc::clone(&pending);
        tokio::spawn(async move {
            if let Some(WriterMessage::Request(req)) = rx.recv().await {
                let params = req.params.unwrap();
                assert!(params.get("tools").is_none() || params["tools"].is_null());

                let id = req.id.as_str().unwrap().to_string();
                pending_clone.resolve(
                    &id,
                    ClientResponse::Success(serde_json::json!({
                        "role": "assistant",
                        "content": {"type": "text", "text": "ok"},
                        "model": "m"
                    })),
                );
            }
        });

        let result = service
            .analyze_with_tools("p", "c", Vec::new(), 100)
            .await
            .unwrap();
        assert_eq!(result.role, "assistant");
    }

    #[tokio::test]
    async fn test_analyze_invalid_response_returns_remote_error() {
        use crate::mcp::pending_requests::ClientResponse;
        use crate::mcp::protocol::WriterMessage;

        let (tx, mut rx) = mpsc::channel(10);
        let pending = Arc::new(PendingRequests::new());
        let requester = Arc::new(ClientRequester::new(
            tx,
            Arc::clone(&pending),
            Duration::from_secs(5),
        ));
        let service = SamplingService::new(requester);
        service.set_supported(true);

        let pending_clone = Arc::clone(&pending);
        tokio::spawn(async move {
            if let Some(WriterMessage::Request(req)) = rx.recv().await {
                let id = req.id.as_str().unwrap().to_string();
                pending_clone.resolve(
                    &id,
                    ClientResponse::Success(serde_json::json!("not a valid response")),
                );
            }
        });

        let result = service.analyze("prompt", "content", 100).await;
        match result {
            Err(ClientRequestError::RemoteError { code, message }) => {
                assert_eq!(code, -1);
                assert!(message.contains("Invalid sampling response"));
            }
            other => panic!("Expected RemoteError, got: {other:?}"),
        }
    }
}
