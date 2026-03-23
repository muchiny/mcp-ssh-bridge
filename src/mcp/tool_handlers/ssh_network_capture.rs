//! Handler for the `ssh_network_capture` tool.
//!
//! Captures network traffic on a remote host using tcpdump.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::network_security::NetworkSecurityCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshNetworkCaptureArgs {
    /// Target host name from configuration.
    host: String,
    /// Network interface to capture on (default: any).
    #[serde(default)]
    interface: Option<String>,
    /// Capture filter expression (e.g., "port 80").
    #[serde(default)]
    filter: Option<String>,
    /// Number of packets to capture (default: 100, max: 1000).
    #[serde(default)]
    count: Option<u32>,
    /// Override default command timeout in seconds.
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    #[serde(default)]
    max_output: Option<u64>,
    /// Save full output to a local file path.
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshNetworkCaptureArgs);

pub struct NetworkCaptureTool;

impl StandardTool for NetworkCaptureTool {
    type Args = SshNetworkCaptureArgs;

    const NAME: &'static str = "ssh_network_capture";

    const DESCRIPTION: &'static str = "Capture network traffic on a remote host using tcpdump. Prefer this over \
        ssh_exec for packet capture as it safely limits the number of captured packets \
        (max 1000) and formats output with -nn for numeric addresses.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "interface": {
                        "type": "string",
                        "description": "Network interface to capture on (default: any)"
                    },
                    "filter": {
                        "type": "string",
                        "description": "Capture filter expression (e.g., 'port 80')"
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of packets to capture (default: 100, max: 1000)",
                        "minimum": 1,
                        "maximum": 1000
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters before truncation",
                        "minimum": 100
                    },
                    "save_output": {
                        "type": "string",
                        "description": "Save full output to a local file path"
                    }
                },
                "required": ["host"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshNetworkCaptureArgs, _host_config: &HostConfig) -> Result<String> {
        let count = args.count.unwrap_or(100);
        NetworkSecurityCommandBuilder::build_network_capture_command(
            args.interface.as_deref(),
            args.filter.as_deref(),
            count,
        )
    }
}

/// Handler for the `ssh_network_capture` tool.
pub type SshNetworkCaptureHandler = StandardToolHandler<NetworkCaptureTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshNetworkCaptureHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshNetworkCaptureHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshNetworkCaptureHandler::new();
        assert_eq!(handler.name(), "ssh_network_capture");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_network_capture");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "interface": "eth0",
            "filter": "port 80",
            "count": 50,
            "timeout_seconds": 60,
            "max_output": 10000,
            "save_output": "/tmp/capture.txt"
        });
        let args: SshNetworkCaptureArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.interface.as_deref(), Some("eth0"));
        assert_eq!(args.filter.as_deref(), Some("port 80"));
        assert_eq!(args.count, Some(50));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/capture.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshNetworkCaptureArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.interface.is_none());
        assert!(args.filter.is_none());
        assert!(args.count.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshNetworkCaptureHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("interface"));
        assert!(props.contains_key("filter"));
        assert!(props.contains_key("count"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshNetworkCaptureArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshNetworkCaptureArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshNetworkCaptureHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
