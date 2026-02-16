//! Handler for the `ssh_win_process_info` tool.
//!
//! Gets detailed information about a Windows process by PID via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_process::WindowsProcessCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshWinProcessInfoArgs {
    host: String,
    pid: u32,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinProcessInfoArgs);

pub struct WinProcessInfoTool;

impl StandardTool for WinProcessInfoTool {
    type Args = SshWinProcessInfoArgs;

    const NAME: &'static str = "ssh_win_process_info";

    const DESCRIPTION: &'static str = "Get detailed information about a Windows process by PID. Shows all process properties \
        including memory, handles, threads, and module information.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "pid"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "pid": {
                "type": "integer",
                "description": "Process ID to inspect",
                "minimum": 0
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

    fn build_command(args: &SshWinProcessInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsProcessCommandBuilder::info(args.pid))
    }
}

/// Handler for the `ssh_win_process_info` tool.
pub type SshWinProcessInfoHandler = StandardToolHandler<WinProcessInfoTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinProcessInfoHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinProcessInfoHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "pid": 1234});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinProcessInfoHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_process_info");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("pid")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "pid": 1234,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshWinProcessInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.pid, 1234);
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "pid": 5678});
        let args: SshWinProcessInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.pid, 5678);
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinProcessInfoHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "pid": 1});
        let args: SshWinProcessInfoArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinProcessInfoArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "pid": "not_a_number"});
        let result = serde_json::from_value::<SshWinProcessInfoArgs>(json);
        assert!(result.is_err());
    }
}
