//! Handler for the `ssh_net_routes` tool.
//!
//! Shows the routing table on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::network::NetworkCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshNetRoutesArgs {
    /// Target host name.
    host: String,
    /// Address family: 4/ipv4 (default) or 6/ipv6.
    family: Option<String>,
    /// Override command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters.
    max_output: Option<u64>,
    /// Path to save full output to a local file.
    save_output: Option<String>,
}

impl_common_args!(SshNetRoutesArgs);

pub struct NetRoutesTool;

impl StandardTool for NetRoutesTool {
    type Args = SshNetRoutesArgs;

    const NAME: &'static str = "ssh_net_routes";

    const DESCRIPTION: &'static str = "Show the routing table on a remote host. Prefer this over ssh_exec as it provides \
        structured output with destination, gateway, interface, and metrics. Supports IPv4 \
        and IPv6.";

    const SCHEMA: &'static str = r#"{
    "type": "object",
    "required": ["host"],
    "properties": {
        "host": {
            "type": "string",
            "description": "Target host name as defined in config"
        },
        "family": {
            "type": "string",
            "description": "Address family: 4/ipv4 (default) or 6/ipv6"
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

    fn build_command(args: &SshNetRoutesArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(NetworkCommandBuilder::build_routes_command(
            args.family.as_deref(),
        ))
    }
}

/// Handler for the `ssh_net_routes` tool.
pub type SshNetRoutesHandler = StandardToolHandler<NetRoutesTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_schema() {
        let handler = SshNetRoutesHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_net_routes");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&serde_json::Value::String("host".to_string())));
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshNetRoutesHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().expect("properties");
        assert!(props.contains_key("family"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let ctx = create_test_context();
        let handler = SshNetRoutesHandler::new();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BridgeError::McpMissingParam { ref param } if param == "arguments"));
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let ctx = create_test_context();
        let handler = SshNetRoutesHandler::new();
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
            "family": "6",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshNetRoutesArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.family.as_deref(), Some("6"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/out.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = serde_json::json!({"host": "myhost"});
        let args: SshNetRoutesArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.family.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_args_debug() {
        let json = serde_json::json!({"host": "myhost"});
        let args: SshNetRoutesArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("myhost"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = serde_json::json!({"host": 12345});
        let result = serde_json::from_value::<SshNetRoutesArgs>(json);
        assert!(result.is_err());
    }
}
