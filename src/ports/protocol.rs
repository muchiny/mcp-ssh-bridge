//! MCP Protocol Contract Types
//!
//! These types define the contracts used in port trait signatures
//! (`ToolHandler`, `PromptHandler`, `ResourceHandler`). They live in the
//! ports layer because they are part of the interface definition,
//! not adapter implementation details.
//!
//! The MCP adapter module re-exports these types for backward
//! compatibility via `crate::mcp::protocol`.

use serde::Serialize;
use serde_json::Value;

// ============================================================================
// Tool Annotations (MCP 2025-03-26+)
// ============================================================================

/// MCP Tool Annotations providing behavioral hints to clients.
///
/// Claude Code uses these to decide parallelization (`readOnlyHint`),
/// confirmation dialogs (`destructiveHint`), and retry safety
/// (`idempotentHint`). All fields are optional with spec-defined defaults.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    /// Human-readable title for display in UIs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// If true, the tool does not modify its environment.
    /// Clients may execute read-only tools in parallel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,

    /// If true, the tool may perform destructive operations
    /// (deletions, overwrites). Clients may show confirmation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,

    /// If true, calling the tool repeatedly with the same args
    /// has no additional effect. Clients may retry safely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,

    /// If true, the tool may interact with external entities
    /// beyond the MCP server's host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

impl ToolAnnotations {
    /// Read-only tool: safe for parallel execution, no confirmation needed.
    #[must_use]
    pub fn read_only(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(true),
        }
    }

    /// Mutating but non-destructive tool.
    #[must_use]
    pub fn mutating(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            read_only_hint: Some(false),
            destructive_hint: Some(false),
            idempotent_hint: Some(false),
            open_world_hint: Some(true),
        }
    }

    /// Destructive tool: triggers confirmation dialogs in clients.
    #[must_use]
    pub fn destructive(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            read_only_hint: Some(false),
            destructive_hint: Some(true),
            idempotent_hint: Some(false),
            open_world_hint: Some(true),
        }
    }

    /// Check if all annotation fields are `None` (empty annotations).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.read_only_hint.is_none()
            && self.destructive_hint.is_none()
            && self.idempotent_hint.is_none()
            && self.open_world_hint.is_none()
    }
}

// ============================================================================
// Tool Contract Types
// ============================================================================

/// MCP Tool Call Result
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallResult {
    pub content: Vec<ToolContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
    /// Machine-readable structured data (MCP 2025-06-18+).
    /// Must conform to the tool's `outputSchema` if defined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
}

/// Content block within a tool result.
///
/// Supports Text (used by all current handlers), plus Image, Audio,
/// and embedded Resource for future use.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ToolContent {
    Text {
        text: String,
    },
    Image {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    Audio {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    #[serde(rename = "resource")]
    Resource {
        resource: EmbeddedResource,
    },
}

/// Embedded resource content within a tool result (MCP 2025-06-18+).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddedResource {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

impl ToolCallResult {
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::Text { text: text.into() }],
            is_error: None,
            structured_content: None,
        }
    }

    #[must_use]
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::Text { text: text.into() }],
            is_error: Some(true),
            structured_content: None,
        }
    }
}

// ============================================================================
// Prompt Contract Types
// ============================================================================

/// MCP Prompt Argument definition
#[derive(Debug, Clone, Serialize)]
pub struct PromptArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
}

/// MCP Prompt Message (part of get response)
#[derive(Debug, Clone, Serialize)]
pub struct PromptMessage {
    pub role: String,
    pub content: PromptContent,
}

/// MCP Prompt Content
#[derive(Debug, Clone, Serialize)]
pub struct PromptContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

impl PromptMessage {
    /// Create a user message
    #[must_use]
    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: PromptContent {
                content_type: "text".to_string(),
                text: text.into(),
            },
        }
    }

    /// Create an assistant message
    #[must_use]
    pub fn assistant(text: impl Into<String>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: PromptContent {
                content_type: "text".to_string(),
                text: text.into(),
            },
        }
    }
}

// ============================================================================
// Resource Contract Types
// ============================================================================

/// MCP Resource Definition (returned by resources/list)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// MCP Resource Content (returned by resources/read)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContent {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ========================================================================
    // ToolAnnotations tests
    // ========================================================================

    #[test]
    fn test_read_only_annotation_fields() {
        let ann = ToolAnnotations::read_only("List files");
        assert_eq!(ann.title.as_deref(), Some("List files"));
        assert_eq!(ann.read_only_hint, Some(true));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, Some(true));
        assert_eq!(ann.open_world_hint, Some(true));
    }

    #[test]
    fn test_mutating_annotation_fields() {
        let ann = ToolAnnotations::mutating("Apply config");
        assert_eq!(ann.title.as_deref(), Some("Apply config"));
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, Some(false));
        assert_eq!(ann.open_world_hint, Some(true));
    }

    #[test]
    fn test_destructive_annotation_fields() {
        let ann = ToolAnnotations::destructive("Delete resource");
        assert_eq!(ann.title.as_deref(), Some("Delete resource"));
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(true));
        assert_eq!(ann.idempotent_hint, Some(false));
        assert_eq!(ann.open_world_hint, Some(true));
    }

    #[test]
    fn test_default_annotations_is_empty() {
        let ann = ToolAnnotations::default();
        assert!(ann.is_empty());
    }

    #[test]
    fn test_read_only_not_empty() {
        let ann = ToolAnnotations::read_only("x");
        assert!(!ann.is_empty());
    }

    #[test]
    fn test_annotations_json_serialization_camel_case() {
        let ann = ToolAnnotations::read_only("Test tool");
        let json = serde_json::to_value(&ann).unwrap();

        // Verify camelCase renaming
        assert_eq!(json["title"], "Test tool");
        assert_eq!(json["readOnlyHint"], true);
        assert_eq!(json["destructiveHint"], false);
        assert_eq!(json["idempotentHint"], true);
        assert_eq!(json["openWorldHint"], true);

        // Verify snake_case keys are NOT present
        assert!(json.get("read_only_hint").is_none());
        assert!(json.get("destructive_hint").is_none());
    }

    #[test]
    fn test_annotations_skip_serializing_none() {
        let ann = ToolAnnotations::default();
        let json = serde_json::to_value(&ann).unwrap();
        let obj = json.as_object().unwrap();

        // All fields are None, so JSON object should be empty
        assert!(
            obj.is_empty(),
            "Default annotations should serialize to {{}}"
        );
    }

    // ========================================================================
    // ToolCallResult tests
    // ========================================================================

    #[test]
    fn test_text_result_structure() {
        let result = ToolCallResult::text("ok");
        assert_eq!(result.content.len(), 1);
        match &result.content[0] {
            ToolContent::Text { text } => assert_eq!(text, "ok"),
            _ => panic!("Expected Text content"),
        }
        assert!(result.is_error.is_none());
        assert!(result.structured_content.is_none());
    }

    #[test]
    fn test_error_result_has_is_error_true() {
        let result = ToolCallResult::error("fail");
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn test_text_result_has_no_is_error() {
        let result = ToolCallResult::text("ok");
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_text_result_serialization() {
        let result = ToolCallResult::text("hello");
        let json = serde_json::to_value(&result).unwrap();

        assert_eq!(json["content"][0]["type"], "text");
        assert_eq!(json["content"][0]["text"], "hello");
        // isError should be absent (None skipped)
        assert!(json.get("isError").is_none());
        // structuredContent should be absent
        assert!(json.get("structuredContent").is_none());
    }

    #[test]
    fn test_error_result_serialization() {
        let result = ToolCallResult::error("something broke");
        let json = serde_json::to_value(&result).unwrap();

        assert_eq!(json["isError"], true);
        assert_eq!(json["content"][0]["text"], "something broke");
    }

    #[test]
    fn test_structured_content_none_skipped() {
        let result = ToolCallResult::text("ok");
        let json_str = serde_json::to_string(&result).unwrap();
        assert!(!json_str.contains("structuredContent"));
    }

    #[test]
    fn test_structured_content_present_when_set() {
        let mut result = ToolCallResult::text("ok");
        result.structured_content = Some(json!({"count": 42}));
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["structuredContent"]["count"], 42);
    }

    // ========================================================================
    // ToolContent tests
    // ========================================================================

    #[test]
    fn test_text_content_serialization() {
        let content = ToolContent::Text {
            text: "hello".to_string(),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "hello");
    }

    #[test]
    fn test_image_content_serialization() {
        let content = ToolContent::Image {
            data: "base64data".to_string(),
            mime_type: "image/png".to_string(),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "image");
        assert_eq!(json["data"], "base64data");
        assert_eq!(json["mimeType"], "image/png");
    }

    #[test]
    fn test_audio_content_serialization() {
        let content = ToolContent::Audio {
            data: "audiodata".to_string(),
            mime_type: "audio/wav".to_string(),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "audio");
        assert_eq!(json["data"], "audiodata");
        assert_eq!(json["mimeType"], "audio/wav");
    }

    #[test]
    fn test_tool_resource_content_serialization() {
        let content = ToolContent::Resource {
            resource: EmbeddedResource {
                uri: "file:///tmp/test.txt".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("file contents".to_string()),
                blob: None,
            },
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["type"], "resource");
        assert_eq!(json["resource"]["uri"], "file:///tmp/test.txt");
        assert_eq!(json["resource"]["mimeType"], "text/plain");
        assert_eq!(json["resource"]["text"], "file contents");
        // blob is None, should be absent
        assert!(json["resource"].get("blob").is_none());
    }

    #[test]
    fn test_embedded_resource_skip_none_fields() {
        let res = EmbeddedResource {
            uri: "test://x".to_string(),
            mime_type: None,
            text: None,
            blob: None,
        };
        let json = serde_json::to_value(&res).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 1); // Only uri
        assert_eq!(json["uri"], "test://x");
    }

    // ========================================================================
    // PromptMessage tests
    // ========================================================================

    #[test]
    fn test_user_message_role() {
        let msg = PromptMessage::user("hello");
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content.content_type, "text");
        assert_eq!(msg.content.text, "hello");
    }

    #[test]
    fn test_assistant_message_role() {
        let msg = PromptMessage::assistant("response");
        assert_eq!(msg.role, "assistant");
        assert_eq!(msg.content.content_type, "text");
        assert_eq!(msg.content.text, "response");
    }

    #[test]
    fn test_prompt_message_serialization() {
        let msg = PromptMessage::user("check health");
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["role"], "user");
        assert_eq!(json["content"]["type"], "text");
        assert_eq!(json["content"]["text"], "check health");
    }

    // ========================================================================
    // ResourceDefinition / ResourceContent tests
    // ========================================================================

    #[test]
    fn test_resource_definition_serialization_camel_case() {
        let def = ResourceDefinition {
            uri: "metrics://web1".to_string(),
            name: "web1 metrics".to_string(),
            description: Some("System metrics".to_string()),
            mime_type: Some("application/json".to_string()),
        };
        let json = serde_json::to_value(&def).unwrap();
        assert_eq!(json["uri"], "metrics://web1");
        assert_eq!(json["name"], "web1 metrics");
        assert_eq!(json["description"], "System metrics");
        assert_eq!(json["mimeType"], "application/json");
        // Verify camelCase, not snake_case
        assert!(json.get("mime_type").is_none());
    }

    #[test]
    fn test_resource_definition_skip_none() {
        let def = ResourceDefinition {
            uri: "test://x".to_string(),
            name: "test".to_string(),
            description: None,
            mime_type: None,
        };
        let json = serde_json::to_value(&def).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 2); // Only uri + name
        assert!(json.get("description").is_none());
        assert!(json.get("mimeType").is_none());
    }

    #[test]
    fn test_resource_content_serialization() {
        let content = ResourceContent {
            uri: "log://web1/syslog".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some("log line 1\nlog line 2".to_string()),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["uri"], "log://web1/syslog");
        assert_eq!(json["mimeType"], "text/plain");
        assert!(json["text"].as_str().unwrap().contains("log line 1"));
    }

    #[test]
    fn test_resource_content_skip_none() {
        let content = ResourceContent {
            uri: "test://x".to_string(),
            mime_type: None,
            text: None,
        };
        let json = serde_json::to_value(&content).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 1); // Only uri
    }
}
