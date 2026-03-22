//! Handler for the `ssh_latency_test` tool.
//!
//! Tests network latency from a remote host to a target.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::performance::PerformanceCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

/// Arguments for the `ssh_latency_test` tool.
#[derive(Debug, Deserialize)]
pub struct SshLatencyTestArgs {
    host: String,
    target: String,
    #[serde(default)]
    count: Option<u64>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshLatencyTestArgs);

pub struct LatencyTestTool;

impl StandardTool for LatencyTestTool {
    type Args = SshLatencyTestArgs;

    const NAME: &'static str = "ssh_latency_test";

    const DESCRIPTION: &'static str = "Test network latency from a remote host to a target. \
        Uses ping or mtr to measure round-trip time, packet loss, and routing. Count is capped \
        at 100 packets.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "target"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "target": {
                "type": "string",
                "description": "Target hostname or IP address to test latency against"
            },
            "count": {
                "type": "integer",
                "description": "Number of packets to send (default: 5, max: 100)",
                "minimum": 1,
                "maximum": 100
            },
            "method": {
                "type": "string",
                "description": "Method to use: 'ping' (default) or 'mtr'",
                "enum": ["ping", "mtr"]
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the local machine"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshLatencyTestArgs, _host_config: &HostConfig) -> Result<String> {
        PerformanceCommandBuilder::build_latency_test_command(
            &args.target,
            args.count.unwrap_or(5),
            args.method.as_deref(),
        )
    }

    fn validate(args: &SshLatencyTestArgs, _host_config: &HostConfig) -> Result<()> {
        PerformanceCommandBuilder::validate_count(args.count.unwrap_or(5))?;
        crate::domain::use_cases::performance::validate_latency_target(&args.target)?;
        Ok(())
    }
}

/// Handler for the `ssh_latency_test` tool.
pub type SshLatencyTestHandler = StandardToolHandler<LatencyTestTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshLatencyTestHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshLatencyTestHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "target": "8.8.8.8"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshLatencyTestHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_latency_test");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("target")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "myhost", "target": "8.8.8.8", "count": 10, "method": "mtr"});
        let args: SshLatencyTestArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "8.8.8.8");
        assert_eq!(args.count, Some(10));
        assert_eq!(args.method.as_deref(), Some("mtr"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "target": "example.com"});
        let args: SshLatencyTestArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "example.com");
        assert!(args.count.is_none());
        assert!(args.method.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshLatencyTestHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("target"));
        assert!(props.contains_key("count"));
        assert!(props.contains_key("method"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "target": "t"});
        let args: SshLatencyTestArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshLatencyTestArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "target": "x"});
        let result = serde_json::from_value::<SshLatencyTestArgs>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_args_full_deserialization() {
        let json = json!({
            "host": "server1",
            "target": "10.0.0.1",
            "count": 20,
            "method": "ping",
            "timeout_seconds": 120,
            "max_output": 10000,
            "save_output": "/tmp/latency.txt"
        });
        let args: SshLatencyTestArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.target, "10.0.0.1");
        assert_eq!(args.count, Some(20));
        assert_eq!(args.method.as_deref(), Some("ping"));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/latency.txt"));
    }

    #[test]
    fn test_schema_method_enum() {
        let handler = SshLatencyTestHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let method = &schema_json["properties"]["method"];
        let enum_values = method["enum"].as_array().unwrap();
        assert!(enum_values.contains(&json!("ping")));
        assert!(enum_values.contains(&json!("mtr")));
    }
}
