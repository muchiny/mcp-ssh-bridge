//! Handler for the `ssh_win_event_logs` tool.
//!
//! Retrieves recent entries from a Windows Event Log.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_event::validate_log_name;
use crate::domain::use_cases::windows_service::WindowsServiceCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshWinEventLogsArgs {
    host: String,
    log: String,
    count: Option<u32>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinEventLogsArgs);

pub struct WinEventLogsTool;

impl StandardTool for WinEventLogsTool {
    type Args = SshWinEventLogsArgs;

    const NAME: &'static str = "ssh_win_event_logs";

    const DESCRIPTION: &'static str = "Retrieve recent entries from a Windows Event Log (e.g., System, Application, \
        Security). Specify the log name and optional count (default: 50).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "log"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "log": {
                "type": "string",
                "description": "Event log name (e.g., System, Application, Security)"
            },
            "count": {
                "type": "integer",
                "description": "Number of recent entries to retrieve (default: 50)"
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

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshWinEventLogsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsServiceCommandBuilder::build_event_logs_command(
            &args.log,
            args.count.unwrap_or(50),
        ))
    }

    fn validate(args: &SshWinEventLogsArgs, _host_config: &HostConfig) -> Result<()> {
        validate_log_name(&args.log)?;
        Ok(())
    }
}

/// Handler for the `ssh_win_event_logs` tool.
pub type SshWinEventLogsHandler = StandardToolHandler<WinEventLogsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinEventLogsHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinEventLogsHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "log": "System"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinEventLogsHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_event_logs");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("log")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "log": "System",
            "count": 100,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshWinEventLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.log, "System");
        assert_eq!(args.count, Some(100));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "log": "Application"});
        let args: SshWinEventLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.log, "Application");
        assert!(args.count.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinEventLogsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("count"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "log": "System"});
        let args: SshWinEventLogsArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinEventLogsArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "log": "System"});
        let result = serde_json::from_value::<SshWinEventLogsArgs>(json);
        assert!(result.is_err());
    }
}
