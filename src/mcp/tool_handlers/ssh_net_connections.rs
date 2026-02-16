//! Handler for the `ssh_net_connections` tool.
//!
//! Lists active network connections on a remote host using `ss`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::network::NetworkCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshNetConnectionsArgs {
    /// Target host name.
    host: String,
    /// Filter by protocol (tcp/udp).
    protocol: Option<String>,
    /// Filter by connection state.
    state: Option<String>,
    /// Show only listening ports.
    listening: Option<bool>,
    /// Override command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters.
    max_output: Option<u64>,
    /// Path to save full output to a local file.
    save_output: Option<String>,
}

impl_common_args!(SshNetConnectionsArgs);

pub struct NetConnectionsTool;

impl StandardTool for NetConnectionsTool {
    type Args = SshNetConnectionsArgs;

    const NAME: &'static str = "ssh_net_connections";

    const DESCRIPTION: &'static str = "List active network connections on a remote host. Prefer this over ssh_exec as it \
        provides structured filtering by protocol, state, and listening mode. Returns \
        connection details including local/remote addresses and process info.";

    const SCHEMA: &'static str = r#"{
    "type": "object",
    "required": ["host"],
    "properties": {
        "host": {
            "type": "string",
            "description": "Target host name as defined in config"
        },
        "protocol": {
            "type": "string",
            "description": "Filter by protocol",
            "enum": ["tcp", "udp"]
        },
        "state": {
            "type": "string",
            "description": "Filter by connection state (e.g., established, listening, time-wait)"
        },
        "listening": {
            "type": "boolean",
            "description": "Show only listening ports"
        },
        "timeout_seconds": {
            "type": "integer",
            "description": "Override command timeout in seconds"
        },
        "max_output": {
            "type": "integer",
            "description": "Maximum output characters (truncates if exceeded)"
        },
        "save_output": {
            "type": "string",
            "description": "Path to save full output to a local file"
        }
    }
}"#;

    fn build_command(args: &SshNetConnectionsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(NetworkCommandBuilder::build_connections_command(
            args.protocol.as_deref(),
            args.state.as_deref(),
            args.listening.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_net_connections` tool.
pub type SshNetConnectionsHandler = StandardToolHandler<NetConnectionsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_schema() {
        let handler = SshNetConnectionsHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_net_connections");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::Value::String("host".to_string())));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshNetConnectionsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().expect("properties");
        assert!(props.contains_key("protocol"));
        assert!(props.contains_key("state"));
        assert!(props.contains_key("listening"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let ctx = create_test_context();
        let handler = SshNetConnectionsHandler::new();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BridgeError::McpMissingParam { ref param } if param == "arguments"));
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let ctx = create_test_context();
        let handler = SshNetConnectionsHandler::new();
        let args = serde_json::json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BridgeError::UnknownHost { ref host } if host == "nonexistent"));
    }

    #[test]
    fn test_args_deserialization() {
        let json = serde_json::json!({
            "host": "myhost",
            "protocol": "tcp",
            "state": "established",
            "listening": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshNetConnectionsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.protocol.as_deref(), Some("tcp"));
        assert_eq!(args.state.as_deref(), Some("established"));
        assert_eq!(args.listening, Some(true));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/out.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = serde_json::json!({"host": "myhost"});
        let args: SshNetConnectionsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.protocol.is_none());
        assert!(args.state.is_none());
        assert!(args.listening.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = serde_json::json!({"host": "myhost"});
        let args: SshNetConnectionsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("myhost"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = serde_json::json!({"host": 12345});
        let result = serde_json::from_value::<SshNetConnectionsArgs>(json);
        assert!(result.is_err());
    }
}
