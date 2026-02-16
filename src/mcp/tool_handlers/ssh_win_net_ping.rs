//! Handler for the `ssh_win_net_ping` tool.
//!
//! Pings a target host from a remote Windows machine via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_network::WindowsNetworkCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshWinNetPingArgs {
    host: String,
    target: String,
    #[serde(default)]
    count: Option<u32>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinNetPingArgs);

pub struct WinNetPingTool;

impl StandardTool for WinNetPingTool {
    type Args = SshWinNetPingArgs;

    const NAME: &'static str = "ssh_win_net_ping";

    const DESCRIPTION: &'static str = "Ping a host from a Windows machine using Test-Connection. Returns round-trip time \
        statistics.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "target"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "target": {
                "type": "string",
                "description": "Hostname or IP address to ping"
            },
            "count": {
                "type": "integer",
                "description": "Number of ping packets to send (default: 4)",
                "maximum": 100
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

    fn build_command(args: &SshWinNetPingArgs, _host_config: &HostConfig) -> Result<String> {
        let count = args.count.unwrap_or(4);
        WindowsNetworkCommandBuilder::ping(&args.target, count)
    }
}

/// Handler for the `ssh_win_net_ping` tool.
pub type SshWinNetPingHandler = StandardToolHandler<WinNetPingTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinNetPingHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinNetPingHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "target": "8.8.8.8"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinNetPingHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_net_ping");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("target")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "target": "8.8.8.8",
            "count": 10,
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshWinNetPingArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "8.8.8.8");
        assert_eq!(args.count, Some(10));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "target": "8.8.8.8"});
        let args: SshWinNetPingArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "8.8.8.8");
        assert!(args.count.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinNetPingHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("count"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "target": "t"});
        let args: SshWinNetPingArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinNetPingArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "target": "8.8.8.8"});
        let result = serde_json::from_value::<SshWinNetPingArgs>(json);
        assert!(result.is_err());
    }
}
