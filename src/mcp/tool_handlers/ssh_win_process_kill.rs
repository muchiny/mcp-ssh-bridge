//! Handler for the `ssh_win_process_kill` tool.
//!
//! Kills a process on a Windows host via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_process::WindowsProcessCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshWinProcessKillArgs {
    host: String,
    pid: u32,
    #[serde(default)]
    force: bool,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinProcessKillArgs);

pub struct WinProcessKillTool;

impl StandardTool for WinProcessKillTool {
    type Args = SshWinProcessKillArgs;

    const NAME: &'static str = "ssh_win_process_kill";

    const DESCRIPTION: &'static str = "Kill a process on a Windows host by PID. Use the force flag to forcefully terminate a \
        process that does not respond to a graceful stop.";

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
                "description": "Process ID to kill",
                "minimum": 0
            },
            "force": {
                "type": "boolean",
                "description": "Force kill the process (default: false)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshWinProcessKillArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsProcessCommandBuilder::kill(args.pid, args.force))
    }
}

/// Handler for the `ssh_win_process_kill` tool.
pub type SshWinProcessKillHandler = StandardToolHandler<WinProcessKillTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinProcessKillHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinProcessKillHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "pid": 1234});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinProcessKillHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_process_kill");
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
            "force": true,
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshWinProcessKillArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.pid, 1234);
        assert!(args.force);
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "pid": 5678});
        let args: SshWinProcessKillArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.pid, 5678);
        assert!(!args.force);
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinProcessKillHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("force"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "pid": 1});
        let args: SshWinProcessKillArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinProcessKillArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "pid": "not_a_number"});
        let result = serde_json::from_value::<SshWinProcessKillArgs>(json);
        assert!(result.is_err());
    }
}
