//! Handler for the `ssh_timer_info` tool.
//!
//! Show detailed information about a systemd timer on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::systemd_timers::TimerCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshTimerInfoArgs {
    host: String,
    timer: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshTimerInfoArgs);

pub struct TimerInfoTool;

impl StandardTool for TimerInfoTool {
    type Args = SshTimerInfoArgs;

    const NAME: &'static str = "ssh_timer_info";

    const DESCRIPTION: &'static str = "Show detailed information about a systemd timer on a \
        remote host including calendar schedule, next/last trigger times, and configuration.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "timer"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "timer": {
                "type": "string",
                "description": "Name of the systemd timer (e.g., apt-daily.timer, logrotate.timer)"
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

    fn build_command(args: &SshTimerInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(TimerCommandBuilder::build_info_command(&args.timer))
    }
}

/// Handler for the `ssh_timer_info` tool.
pub type SshTimerInfoHandler = StandardToolHandler<TimerInfoTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTimerInfoHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshTimerInfoHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "timer": "apt-daily.timer"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshTimerInfoHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_timer_info");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("timer")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "timer": "apt-daily.timer",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshTimerInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.timer, "apt-daily.timer");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "timer": "apt-daily.timer"});
        let args: SshTimerInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.timer, "apt-daily.timer");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTimerInfoHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "timer": "t"});
        let args: SshTimerInfoArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshTimerInfoArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "timer": "apt-daily.timer"});
        let result = serde_json::from_value::<SshTimerInfoArgs>(json);
        assert!(result.is_err());
    }
}
