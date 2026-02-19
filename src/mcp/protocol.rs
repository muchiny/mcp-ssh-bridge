use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 Request
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    #[must_use]
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn error(id: Option<Value>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Create a success response, falling back to an internal error if serialization fails.
    ///
    /// This is a safer alternative to `success()` that avoids panicking on serialization errors.
    #[must_use]
    pub fn success_or_serialize_error(id: Option<Value>, result: &impl Serialize) -> Self {
        match serde_json::to_value(result) {
            Ok(v) => Self::success(id, v),
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize response");
                Self::error(
                    id,
                    JsonRpcError::internal_error(format!("Serialization error: {e}")),
                )
            }
        }
    }
}

/// JSON-RPC 2.0 Error
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    #[must_use]
    pub fn parse_error(msg: impl Into<String>) -> Self {
        Self {
            code: -32700,
            message: msg.into(),
            data: None,
        }
    }

    #[must_use]
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: msg.into(),
            data: None,
        }
    }

    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("Method not found: {method}"),
            data: None,
        }
    }

    #[must_use]
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: msg.into(),
            data: None,
        }
    }

    #[must_use]
    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self {
            code: -32603,
            message: msg.into(),
            data: None,
        }
    }
}

// ============================================================================
// MCP Protocol Types
// ============================================================================

/// MCP Initialize Request Parameters
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: ClientInfo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientCapabilities {
    #[serde(default)]
    pub roots: Option<RootsCapability>,
    #[serde(default)]
    pub sampling: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootsCapability {
    pub list_changed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

/// MCP Initialize Response
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
    /// Free-form instructions for the connected LLM to understand the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerCapabilities {
    pub tools: Option<ToolsCapability>,
    pub prompts: Option<PromptsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    /// Experimental Tasks capability (MCP 2025-11-25+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks: Option<TasksCapability>,
}

/// Tasks capability declaration for MCP `initialize` response.
#[derive(Debug, Clone, Serialize)]
pub struct TasksCapability {
    pub list: Value,
    pub cancel: Value,
    pub requests: TaskRequestsCapability,
}

/// Which request types support task augmentation.
#[derive(Debug, Clone, Serialize)]
pub struct TaskRequestsCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<TaskToolsCapability>,
}

/// Task support for `tools/call`.
#[derive(Debug, Clone, Serialize)]
pub struct TaskToolsCapability {
    pub call: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptsCapability {
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website_url: Option<String>,
}

/// MCP Tool Definition
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    /// Behavioral hints for MCP clients (MCP 2025-03-26+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
    /// Execution hints for task support (MCP 2025-11-25+).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<ToolExecution>,
}

/// Tool execution hints (MCP 2025-11-25+).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolExecution {
    /// `"forbidden"` | `"optional"` | `"required"`
    pub task_support: String,
}

/// MCP Tools List Response
#[derive(Debug, Clone, Serialize)]
pub struct ToolsListResult {
    pub tools: Vec<Tool>,
}

/// MCP Tool Call Parameters
#[derive(Debug, Clone, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
    /// When present, the client requests task-augmented execution (MCP 2025-11-25+).
    #[serde(default)]
    pub task: Option<TaskRequest>,
}

/// Client-provided task parameters for task-augmented requests.
#[derive(Debug, Clone, Deserialize)]
pub struct TaskRequest {
    /// Requested TTL in milliseconds. Server may cap this.
    #[serde(default)]
    pub ttl: Option<u64>,
}

// Contract types re-exported from ports (canonical location: crate::ports::protocol)
pub use crate::ports::protocol::{EmbeddedResource, ToolAnnotations, ToolCallResult, ToolContent};

// ============================================================================
// MCP Prompts Types
// ============================================================================

pub use crate::ports::protocol::{PromptArgument, PromptContent, PromptMessage};

/// MCP Prompt Definition
#[derive(Debug, Clone, Serialize)]
pub struct PromptDefinition {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
}

/// MCP Prompts List Response
#[derive(Debug, Clone, Serialize)]
pub struct PromptsListResult {
    pub prompts: Vec<PromptDefinition>,
}

/// MCP Prompts Get Parameters
#[derive(Debug, Clone, Deserialize)]
pub struct PromptsGetParams {
    pub name: String,
    #[serde(default)]
    pub arguments: std::collections::HashMap<String, String>,
}

// PromptMessage, PromptContent, PromptArgument re-exported above

/// MCP Prompts Get Response
#[derive(Debug, Clone, Serialize)]
pub struct PromptsGetResult {
    pub messages: Vec<PromptMessage>,
}

// ============================================================================
// MCP Resources Types
// ============================================================================

pub use crate::ports::protocol::{ResourceContent, ResourceDefinition};

/// MCP Resources List Response
#[derive(Debug, Clone, Serialize)]
pub struct ResourcesListResult {
    pub resources: Vec<ResourceDefinition>,
}

/// MCP Resources Read Parameters
#[derive(Debug, Clone, Deserialize)]
pub struct ResourcesReadParams {
    pub uri: String,
}

/// MCP Resources Read Response
#[derive(Debug, Clone, Serialize)]
pub struct ResourcesReadResult {
    pub contents: Vec<ResourceContent>,
}

/// MCP Resources Capability
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    pub list_changed: bool,
}

// ============================================================================
// MCP Tasks Types (MCP 2025-11-25+, experimental)
// ============================================================================

/// Task lifecycle status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

/// Task metadata returned by task operations.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskInfo {
    pub task_id: String,
    pub status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    pub created_at: String,
    pub last_updated_at: String,
    /// Time-to-live in milliseconds before the task expires.
    pub ttl: u64,
    /// Suggested poll interval in milliseconds.
    pub poll_interval: u64,
}

/// Response for a task-augmented `tools/call` request.
#[derive(Debug, Clone, Serialize)]
pub struct CreateTaskResult {
    pub task: TaskInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "_meta")]
    pub meta: Option<Value>,
}

/// Parameters for `tasks/get`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskGetParams {
    pub task_id: String,
}

/// Parameters for `tasks/result`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskResultParams {
    pub task_id: String,
}

/// Parameters for `tasks/cancel`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskCancelParams {
    pub task_id: String,
}

/// Parameters for `tasks/list`.
#[derive(Debug, Clone, Deserialize)]
pub struct TaskListParams {
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Response for `tasks/list`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskListResult {
    pub tasks: Vec<TaskInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

// ============================================================================
// JSON-RPC Notifications
// ============================================================================

/// JSON-RPC 2.0 Notification (server → client, no id, no response expected)
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    /// Optional params payload (used by `notifications/tasks/status`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    /// Create a `notifications/tools/list_changed` notification.
    #[must_use]
    pub fn tools_list_changed() -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/tools/list_changed".to_string(),
            params: None,
        }
    }

    /// Create a `notifications/prompts/list_changed` notification.
    #[must_use]
    pub fn prompts_list_changed() -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/prompts/list_changed".to_string(),
            params: None,
        }
    }

    /// Create a `notifications/resources/list_changed` notification.
    #[must_use]
    pub fn resources_list_changed() -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/resources/list_changed".to_string(),
            params: None,
        }
    }

    /// Create a `notifications/tasks/status` notification (MCP 2025-11-25+).
    #[must_use]
    pub fn task_status(task_info: &TaskInfo) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: "notifications/tasks/status".to_string(),
            params: serde_json::to_value(task_info).ok(),
        }
    }
}

/// Messages sent through the stdout writer channel.
///
/// The writer task serializes both responses and unsolicited notifications
/// to the same stdout stream.
pub enum WriterMessage {
    /// A JSON-RPC response to a client request.
    Response(Box<JsonRpcResponse>),
    /// An unsolicited server notification (e.g., `list_changed`).
    Notification(JsonRpcNotification),
}

// ============================================================================
// MCP Protocol Version
// ============================================================================

pub const PROTOCOL_VERSION: &str = "2025-11-25";
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2024-11-05"];
pub const SERVER_NAME: &str = "mcp-ssh-bridge";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ============== JsonRpcRequest Tests ==============

    #[test]
    fn test_request_deserialization_with_id() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"test","params":{"foo":"bar"}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.id, Some(json!(1)));
        assert_eq!(req.method, "test");
        assert!(req.params.is_some());
    }

    #[test]
    fn test_request_deserialization_without_id() {
        // Notification (no id)
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(req.id.is_none());
        assert_eq!(req.method, "notifications/initialized");
        assert!(req.params.is_none());
    }

    #[test]
    fn test_request_deserialization_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc-123","method":"test"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, Some(json!("abc-123")));
    }

    #[test]
    fn test_request_deserialization_null_id() {
        // In serde_json, "id": null is deserialized as None for Option<Value>
        // This is correct for JSON-RPC: null id means the request is a notification
        let json = r#"{"jsonrpc":"2.0","id":null,"method":"test"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, None);
    }

    // ============== JsonRpcResponse Tests ==============

    #[test]
    fn test_response_success_serialization() {
        let response = JsonRpcResponse::success(Some(json!(1)), json!({"result": "ok"}));
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"id\":1"));
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_response_error_serialization() {
        let error = JsonRpcError::internal_error("Something went wrong");
        let response = JsonRpcResponse::error(Some(json!(1)), error);
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"error\""));
        assert!(json.contains("-32603"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn test_response_success_or_serialize_error_ok() {
        #[derive(Serialize)]
        struct TestResult {
            value: i32,
        }
        let result = TestResult { value: 42 };
        let response = JsonRpcResponse::success_or_serialize_error(Some(json!(1)), &result);
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    // ============== JsonRpcError Tests ==============

    #[test]
    fn test_error_parse_error_code() {
        let error = JsonRpcError::parse_error("Invalid JSON");
        assert_eq!(error.code, -32700);
        assert_eq!(error.message, "Invalid JSON");
    }

    #[test]
    fn test_error_invalid_request_code() {
        let error = JsonRpcError::invalid_request("Missing jsonrpc");
        assert_eq!(error.code, -32600);
    }

    #[test]
    fn test_error_method_not_found_code() {
        let error = JsonRpcError::method_not_found("unknown/method");
        assert_eq!(error.code, -32601);
        assert!(error.message.contains("unknown/method"));
    }

    #[test]
    fn test_error_invalid_params_code() {
        let error = JsonRpcError::invalid_params("host is required");
        assert_eq!(error.code, -32602);
    }

    #[test]
    fn test_error_internal_error_code() {
        let error = JsonRpcError::internal_error("Database connection failed");
        assert_eq!(error.code, -32603);
    }

    // ============== MCP Types Serialization Tests ==============

    #[test]
    fn test_initialize_params_deserialization() {
        let json = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "roots": {"listChanged": true}
            },
            "clientInfo": {
                "name": "TestClient",
                "version": "1.0.0"
            }
        });
        let params: InitializeParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.protocol_version, "2024-11-05");
        assert_eq!(params.client_info.name, "TestClient");
    }

    #[test]
    fn test_initialize_result_serialization() {
        let result = InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: true }),
                prompts: Some(PromptsCapability {
                    list_changed: false,
                }),
                resources: None,
                tasks: None,
            },
            server_info: ServerInfo {
                name: SERVER_NAME.to_string(),
                version: SERVER_VERSION.to_string(),
                description: None,
                website_url: None,
            },
            instructions: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("protocolVersion"));
        assert!(json.contains("serverInfo"));
        // Optional fields should be omitted when None
        assert!(!json.contains("description"));
        assert!(!json.contains("websiteUrl"));
        assert!(!json.contains("tasks"));
    }

    #[test]
    fn test_tool_call_result_text() {
        let result = ToolCallResult::text("Command output here");
        assert_eq!(result.content.len(), 1);
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_tool_call_result_error() {
        let result = ToolCallResult::error("Command failed");
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn test_prompt_message_user() {
        let msg = PromptMessage::user("Check the system health");
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content.content_type, "text");
    }

    #[test]
    fn test_prompt_message_assistant() {
        let msg = PromptMessage::assistant("Here is the result");
        assert_eq!(msg.role, "assistant");
    }

    #[test]
    fn test_tool_definition_serialization() {
        let tool = Tool {
            name: "ssh-exec".to_string(),
            description: "Execute command".to_string(),
            input_schema: json!({"type": "object"}),
            annotations: None,
            execution: None,
        };
        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("inputSchema"));
        // annotations: None should be omitted
        assert!(!json.contains("annotations"));
        // execution: None should be omitted
        assert!(!json.contains("execution"));
    }

    #[test]
    fn test_resource_definition_serialization() {
        let resource = ResourceDefinition {
            uri: "ssh://host/path".to_string(),
            name: "Remote File".to_string(),
            description: Some("A file on remote host".to_string()),
            mime_type: Some("text/plain".to_string()),
        };
        let json = serde_json::to_string(&resource).unwrap();
        assert!(json.contains("mimeType"));
    }

    #[test]
    fn test_prompts_get_params_deserialization() {
        let json = json!({
            "name": "system-health",
            "arguments": {"host": "server1"}
        });
        let params: PromptsGetParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.name, "system-health");
        assert_eq!(params.arguments.get("host"), Some(&"server1".to_string()));
    }

    // ============== Constants Tests ==============

    #[test]
    fn test_protocol_version_format() {
        // Protocol version should be a date in YYYY-MM-DD format
        assert!(PROTOCOL_VERSION.len() == 10);
        assert!(PROTOCOL_VERSION.contains('-'));
    }

    #[test]
    fn test_server_name_not_empty() {
        assert!(!SERVER_NAME.is_empty());
    }

    #[test]
    fn test_server_version_is_semver() {
        // Version should contain at least one dot (e.g., "0.1.0")
        assert!(SERVER_VERSION.contains('.'));
    }

    #[test]
    fn test_supported_protocol_versions_includes_latest() {
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS[0], PROTOCOL_VERSION);
        assert!(SUPPORTED_PROTOCOL_VERSIONS.contains(&"2025-11-25"));
        assert!(SUPPORTED_PROTOCOL_VERSIONS.contains(&"2025-06-18"));
        assert!(SUPPORTED_PROTOCOL_VERSIONS.contains(&"2024-11-05"));
        // All versions should be valid YYYY-MM-DD format
        for v in SUPPORTED_PROTOCOL_VERSIONS {
            assert_eq!(v.len(), 10, "Version {v} is not YYYY-MM-DD format");
        }
    }

    #[test]
    fn test_server_info_with_optional_fields() {
        let info = ServerInfo {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: Some("A test server".to_string()),
            website_url: Some("https://example.com".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"websiteUrl\"")); // camelCase
        assert!(!json.contains("website_url")); // NOT snake_case
    }

    #[test]
    fn test_server_info_omits_none_fields() {
        let info = ServerInfo {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            website_url: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("description"));
        assert!(!json.contains("websiteUrl"));
    }

    // ============== Tool Annotations Tests ==============

    #[test]
    fn test_tool_with_annotations_serialization() {
        let tool = Tool {
            name: "ssh_docker_ps".to_string(),
            description: "List containers".to_string(),
            input_schema: json!({"type": "object"}),
            annotations: Some(ToolAnnotations::read_only("List Docker Containers")),
            execution: None,
        };
        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("\"annotations\""));
        assert!(json.contains("\"readOnlyHint\":true"));
        assert!(json.contains("\"destructiveHint\":false"));
        assert!(json.contains("\"title\":\"List Docker Containers\""));
    }

    #[test]
    fn test_tool_without_annotations_omits_field() {
        let tool = Tool {
            name: "test".to_string(),
            description: "test".to_string(),
            input_schema: json!({"type": "object"}),
            annotations: None,
            execution: None,
        };
        let json = serde_json::to_string(&tool).unwrap();
        assert!(!json.contains("annotations"));
    }

    #[test]
    fn test_annotations_camel_case_serialization() {
        let ann = ToolAnnotations::mutating("Test Tool");
        let json = serde_json::to_string(&ann).unwrap();
        assert!(json.contains("readOnlyHint"));
        assert!(json.contains("destructiveHint"));
        assert!(json.contains("idempotentHint"));
        assert!(json.contains("openWorldHint"));
        // Should NOT contain snake_case
        assert!(!json.contains("read_only_hint"));
    }

    #[test]
    fn test_tool_call_result_structured_content_omitted_when_none() {
        let result = ToolCallResult::text("output");
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("structuredContent"));
    }

    #[test]
    fn test_tool_call_result_with_structured_content() {
        let result = ToolCallResult {
            content: vec![ToolContent::Text {
                text: "ok".to_string(),
            }],
            is_error: None,
            structured_content: Some(json!({"status": "running", "uptime": 3600})),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("structuredContent"));
        assert!(json.contains("\"status\":\"running\""));
    }

    #[test]
    fn test_tool_content_image_serialization() {
        let content = ToolContent::Image {
            data: "base64data".to_string(),
            mime_type: "image/png".to_string(),
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"image\""));
        assert!(json.contains("\"mimeType\":\"image/png\""));
        assert!(json.contains("\"data\":\"base64data\""));
    }

    #[test]
    fn test_tool_content_audio_serialization() {
        let content = ToolContent::Audio {
            data: "audiodata".to_string(),
            mime_type: "audio/wav".to_string(),
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"audio\""));
        assert!(json.contains("\"mimeType\":\"audio/wav\""));
    }

    #[test]
    fn test_tool_content_resource_serialization() {
        let content = ToolContent::Resource {
            resource: EmbeddedResource {
                uri: "data://result.json".to_string(),
                mime_type: Some("application/json".to_string()),
                text: Some("{\"key\": \"value\"}".to_string()),
                blob: None,
            },
        };
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"resource\""));
        assert!(json.contains("\"uri\":\"data://result.json\""));
        assert!(json.contains("\"mimeType\":\"application/json\""));
        // blob: None should be omitted
        assert!(!json.contains("blob"));
    }

    #[test]
    fn test_annotations_read_only_constructor() {
        let ann = ToolAnnotations::read_only("Test");
        assert_eq!(ann.read_only_hint, Some(true));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, Some(true));
        assert!(!ann.is_empty());
    }

    #[test]
    fn test_annotations_destructive_constructor() {
        let ann = ToolAnnotations::destructive("Test");
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(true));
        assert_eq!(ann.idempotent_hint, Some(false));
    }

    #[test]
    fn test_annotations_mutating_constructor() {
        let ann = ToolAnnotations::mutating("Test");
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, Some(false));
    }

    #[test]
    fn test_annotations_default_is_empty() {
        let ann = ToolAnnotations::default();
        assert!(ann.is_empty());
    }

    // ============== Notification Tests ==============

    #[test]
    fn test_notification_tools_list_changed() {
        let n = JsonRpcNotification::tools_list_changed();
        assert_eq!(n.jsonrpc, "2.0");
        assert_eq!(n.method, "notifications/tools/list_changed");
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"method\":\"notifications/tools/list_changed\""));
        // Notifications MUST NOT have an id field
        assert!(!json.contains("\"id\""));
    }

    #[test]
    fn test_notification_prompts_list_changed() {
        let n = JsonRpcNotification::prompts_list_changed();
        assert_eq!(n.method, "notifications/prompts/list_changed");
    }

    #[test]
    fn test_notification_resources_list_changed() {
        let n = JsonRpcNotification::resources_list_changed();
        assert_eq!(n.method, "notifications/resources/list_changed");
    }

    #[test]
    fn test_notification_params_omitted_when_none() {
        let n = JsonRpcNotification::tools_list_changed();
        let json = serde_json::to_string(&n).unwrap();
        assert!(!json.contains("\"params\""));
    }

    // ============== Task Types Tests (MCP 2025-11-25+) ==============

    #[test]
    fn test_task_status_serialization() {
        assert_eq!(
            serde_json::to_string(&TaskStatus::Working).unwrap(),
            "\"working\""
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Completed).unwrap(),
            "\"completed\""
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Failed).unwrap(),
            "\"failed\""
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Cancelled).unwrap(),
            "\"cancelled\""
        );
    }

    #[test]
    fn test_task_info_serialization_camel_case() {
        let info = TaskInfo {
            task_id: "abc-123".to_string(),
            status: TaskStatus::Working,
            status_message: Some("Processing...".to_string()),
            created_at: "2025-11-25T10:30:00Z".to_string(),
            last_updated_at: "2025-11-25T10:30:00Z".to_string(),
            ttl: 60000,
            poll_interval: 5000,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["taskId"], "abc-123");
        assert_eq!(json["status"], "working");
        assert_eq!(json["statusMessage"], "Processing...");
        assert_eq!(json["createdAt"], "2025-11-25T10:30:00Z");
        assert_eq!(json["lastUpdatedAt"], "2025-11-25T10:30:00Z");
        assert_eq!(json["ttl"], 60000);
        assert_eq!(json["pollInterval"], 5000);
        // Verify camelCase, not snake_case
        assert!(json.get("task_id").is_none());
    }

    #[test]
    fn test_task_info_omits_none_status_message() {
        let info = TaskInfo {
            task_id: "id".to_string(),
            status: TaskStatus::Completed,
            status_message: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            last_updated_at: "2025-01-01T00:00:00Z".to_string(),
            ttl: 1000,
            poll_interval: 500,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("statusMessage"));
    }

    #[test]
    fn test_create_task_result_serialization() {
        let result = CreateTaskResult {
            task: TaskInfo {
                task_id: "task-1".to_string(),
                status: TaskStatus::Working,
                status_message: None,
                created_at: "2025-01-01T00:00:00Z".to_string(),
                last_updated_at: "2025-01-01T00:00:00Z".to_string(),
                ttl: 30000,
                poll_interval: 2000,
            },
            meta: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["task"]["taskId"], "task-1");
        assert_eq!(json["task"]["status"], "working");
        assert!(json.get("_meta").is_none());
    }

    #[test]
    fn test_create_task_result_with_meta() {
        let result = CreateTaskResult {
            task: TaskInfo {
                task_id: "task-2".to_string(),
                status: TaskStatus::Working,
                status_message: None,
                created_at: "2025-01-01T00:00:00Z".to_string(),
                last_updated_at: "2025-01-01T00:00:00Z".to_string(),
                ttl: 30000,
                poll_interval: 2000,
            },
            meta: Some(json!({
                "io.modelcontextprotocol/model-immediate-response": "Task started"
            })),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(
            json["_meta"]["io.modelcontextprotocol/model-immediate-response"],
            "Task started"
        );
    }

    #[test]
    fn test_task_get_params_deserialization() {
        let json = json!({"taskId": "abc-123"});
        let params: TaskGetParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.task_id, "abc-123");
    }

    #[test]
    fn test_task_result_params_deserialization() {
        let json = json!({"taskId": "def-456"});
        let params: TaskResultParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.task_id, "def-456");
    }

    #[test]
    fn test_task_cancel_params_deserialization() {
        let json = json!({"taskId": "ghi-789"});
        let params: TaskCancelParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.task_id, "ghi-789");
    }

    #[test]
    fn test_task_list_params_deserialization_with_cursor() {
        let json = json!({"cursor": "page2"});
        let params: TaskListParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.cursor.as_deref(), Some("page2"));
    }

    #[test]
    fn test_task_list_params_deserialization_without_cursor() {
        let json = json!({});
        let params: TaskListParams = serde_json::from_value(json).unwrap();
        assert!(params.cursor.is_none());
    }

    #[test]
    fn test_task_list_result_serialization() {
        let result = TaskListResult {
            tasks: vec![],
            next_cursor: Some("next".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["tasks"].as_array().unwrap().is_empty());
        assert_eq!(json["nextCursor"], "next");
    }

    #[test]
    fn test_task_list_result_omits_none_cursor() {
        let result = TaskListResult {
            tasks: vec![],
            next_cursor: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("nextCursor"));
    }

    #[test]
    fn test_tool_call_params_with_task() {
        let json = json!({
            "name": "ssh_exec",
            "arguments": {"host": "web1", "command": "ls"},
            "task": {"ttl": 60000}
        });
        let params: ToolCallParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.name, "ssh_exec");
        assert!(params.task.is_some());
        assert_eq!(params.task.unwrap().ttl, Some(60000));
    }

    #[test]
    fn test_tool_call_params_without_task() {
        let json = json!({
            "name": "ssh_status",
            "arguments": {}
        });
        let params: ToolCallParams = serde_json::from_value(json).unwrap();
        assert!(params.task.is_none());
    }

    #[test]
    fn test_tool_call_params_with_empty_task() {
        let json = json!({
            "name": "ssh_exec",
            "arguments": {},
            "task": {}
        });
        let params: ToolCallParams = serde_json::from_value(json).unwrap();
        assert!(params.task.is_some());
        assert!(params.task.unwrap().ttl.is_none());
    }

    #[test]
    fn test_tool_execution_serialization() {
        let exec = ToolExecution {
            task_support: "optional".to_string(),
        };
        let json = serde_json::to_value(&exec).unwrap();
        assert_eq!(json["taskSupport"], "optional");
    }

    #[test]
    fn test_tool_with_execution_serialization() {
        let tool = Tool {
            name: "ssh_exec".to_string(),
            description: "Execute".to_string(),
            input_schema: json!({"type": "object"}),
            annotations: None,
            execution: Some(ToolExecution {
                task_support: "optional".to_string(),
            }),
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["execution"]["taskSupport"], "optional");
    }

    #[test]
    fn test_tasks_capability_serialization() {
        let cap = TasksCapability {
            list: json!({}),
            cancel: json!({}),
            requests: TaskRequestsCapability {
                tools: Some(TaskToolsCapability { call: json!({}) }),
            },
        };
        let json = serde_json::to_value(&cap).unwrap();
        assert!(json["list"].is_object());
        assert!(json["cancel"].is_object());
        assert!(json["requests"]["tools"]["call"].is_object());
    }

    #[test]
    fn test_server_capabilities_with_tasks() {
        let caps = ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: true }),
            prompts: None,
            resources: None,
            tasks: Some(TasksCapability {
                list: json!({}),
                cancel: json!({}),
                requests: TaskRequestsCapability {
                    tools: Some(TaskToolsCapability { call: json!({}) }),
                },
            }),
        };
        let json = serde_json::to_value(&caps).unwrap();
        assert!(json["tasks"].is_object());
        assert!(json["tasks"]["requests"]["tools"]["call"].is_object());
    }

    #[test]
    fn test_notification_task_status() {
        let info = TaskInfo {
            task_id: "task-99".to_string(),
            status: TaskStatus::Completed,
            status_message: Some("Done".to_string()),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            last_updated_at: "2025-01-01T00:01:00Z".to_string(),
            ttl: 60000,
            poll_interval: 5000,
        };
        let n = JsonRpcNotification::task_status(&info);
        assert_eq!(n.method, "notifications/tasks/status");
        assert!(n.params.is_some());
        let params = n.params.unwrap();
        assert_eq!(params["taskId"], "task-99");
        assert_eq!(params["status"], "completed");
    }
}
