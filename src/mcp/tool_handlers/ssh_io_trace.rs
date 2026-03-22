//! Handler for the `ssh_io_trace` tool.
//!
//! Traces disk I/O activity on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::performance::PerformanceCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

/// Arguments for the `ssh_io_trace` tool.
#[derive(Debug, Deserialize)]
pub struct SshIoTraceArgs {
    host: String,
    #[serde(default)]
    device: Option<String>,
    #[serde(default)]
    duration: Option<u64>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshIoTraceArgs);

pub struct IoTraceTool;

impl StandardTool for IoTraceTool {
    type Args = SshIoTraceArgs;

    const NAME: &'static str = "ssh_io_trace";

    const DESCRIPTION: &'static str = "Trace disk I/O activity on a remote host. Uses iostat to \
        monitor disk throughput, IOPS, and latency per device. Optionally filter by device name. \
        Duration is capped at 60 seconds.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "device": {
                "type": "string",
                "description": "Device name to monitor (e.g. sda, nvme0n1). Omit for all devices"
            },
            "duration": {
                "type": "integer",
                "description": "Monitoring duration in seconds (default: 5, max: 60)",
                "minimum": 1,
                "maximum": 60
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

    fn build_command(args: &SshIoTraceArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PerformanceCommandBuilder::build_io_trace_command(
            args.device.as_deref(),
            args.duration.unwrap_or(5),
        ))
    }

    fn validate(args: &SshIoTraceArgs, _host_config: &HostConfig) -> Result<()> {
        PerformanceCommandBuilder::validate_duration(args.duration.unwrap_or(5))?;
        Ok(())
    }
}

/// Handler for the `ssh_io_trace` tool.
pub type SshIoTraceHandler = StandardToolHandler<IoTraceTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshIoTraceHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshIoTraceHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshIoTraceHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_io_trace");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "myhost", "device": "sda", "duration": 10});
        let args: SshIoTraceArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.device.as_deref(), Some("sda"));
        assert_eq!(args.duration, Some(10));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshIoTraceArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.device.is_none());
        assert!(args.duration.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshIoTraceHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("device"));
        assert!(props.contains_key("duration"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h"});
        let args: SshIoTraceArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshIoTraceArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123});
        let result = serde_json::from_value::<SshIoTraceArgs>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_args_full_deserialization() {
        let json = json!({
            "host": "server1",
            "device": "nvme0n1",
            "duration": 30,
            "timeout_seconds": 120,
            "max_output": 10000,
            "save_output": "/tmp/io.txt"
        });
        let args: SshIoTraceArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.device.as_deref(), Some("nvme0n1"));
        assert_eq!(args.duration, Some(30));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output, Some("/tmp/io.txt".to_string()));
    }
}
