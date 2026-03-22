//! Handler for the `ssh_perf_trace` tool.
//!
//! Profiles system or process performance on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::performance::PerformanceCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

/// Arguments for the `ssh_perf_trace` tool.
#[derive(Debug, Deserialize)]
pub struct SshPerfTraceArgs {
    host: String,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    duration: Option<u64>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshPerfTraceArgs);

pub struct PerfTraceTool;

impl StandardTool for PerfTraceTool {
    type Args = SshPerfTraceArgs;

    const NAME: &'static str = "ssh_perf_trace";

    const DESCRIPTION: &'static str = "Profile system or process performance on a remote host. \
        Uses perf stat or strace to trace syscalls and collect performance counters. Specify a \
        PID to profile a specific process, or omit for system-wide profiling. Duration is capped \
        at 60 seconds.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "pid": {
                "type": "integer",
                "description": "Process ID to profile (omit for system-wide profiling)"
            },
            "duration": {
                "type": "integer",
                "description": "Profiling duration in seconds (default: 5, max: 60)",
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

    fn build_command(args: &SshPerfTraceArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PerformanceCommandBuilder::build_perf_trace_command(
            args.pid,
            args.duration.unwrap_or(5),
        ))
    }

    fn validate(args: &SshPerfTraceArgs, _host_config: &HostConfig) -> Result<()> {
        PerformanceCommandBuilder::validate_duration(args.duration.unwrap_or(5))?;
        Ok(())
    }
}

/// Handler for the `ssh_perf_trace` tool.
pub type SshPerfTraceHandler = StandardToolHandler<PerfTraceTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPerfTraceHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshPerfTraceHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshPerfTraceHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_perf_trace");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "myhost", "pid": 1234, "duration": 10});
        let args: SshPerfTraceArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.pid, Some(1234));
        assert_eq!(args.duration, Some(10));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshPerfTraceArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.pid.is_none());
        assert!(args.duration.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshPerfTraceHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("pid"));
        assert!(props.contains_key("duration"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h"});
        let args: SshPerfTraceArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshPerfTraceArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123});
        let result = serde_json::from_value::<SshPerfTraceArgs>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_args_full_deserialization() {
        let json = json!({
            "host": "server1",
            "pid": 42,
            "duration": 30,
            "timeout_seconds": 120,
            "max_output": 10000,
            "save_output": "/tmp/perf.txt"
        });
        let args: SshPerfTraceArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pid, Some(42));
        assert_eq!(args.duration, Some(30));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output, Some("/tmp/perf.txt".to_string()));
    }
}
