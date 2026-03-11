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
}
