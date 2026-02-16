//! Handler for the `ssh_process_kill` tool.
//!
//! Sends a signal to a process on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::process::ProcessCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshProcessKillArgs {
    /// Target host name from configuration.
    host: String,
    /// Process ID to signal.
    pid: u32,
    /// Signal name or number (default: TERM).
    signal: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshProcessKillArgs);

pub struct ProcessKillTool;

impl StandardTool for ProcessKillTool {
    type Args = SshProcessKillArgs;

    const NAME: &'static str = "ssh_process_kill";

    const DESCRIPTION: &'static str = "Send a signal to a process on a remote Linux host. Default signal is TERM (graceful \
        shutdown). Use signal 9 (KILL) for force kill. Protected PIDs (0, 1) are blocked. Use \
        ssh_process_list or ssh_process_top first to find target PIDs.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to signal",
                        "minimum": 2
                    },
                    "signal": {
                        "type": "string",
                        "description": "Signal name or number (default: TERM)"
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
                "required": ["host", "pid"]
            }"#;

    fn build_command(args: &SshProcessKillArgs, _host_config: &HostConfig) -> Result<String> {
        ProcessCommandBuilder::build_kill_command(args.pid, args.signal.as_deref())
    }

    fn validate(args: &SshProcessKillArgs, _host_config: &HostConfig) -> Result<()> {
        if let Some(ref sig) = args.signal {
            ProcessCommandBuilder::validate_signal(sig)?;
        }
        Ok(())
    }
}

/// Handler for the `ssh_process_kill` tool.
pub type SshProcessKillHandler = StandardToolHandler<ProcessKillTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshProcessKillHandler::new();
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
        let handler = SshProcessKillHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "pid": 1234})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshProcessKillHandler::new();
        assert_eq!(handler.name(), "ssh_process_kill");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_process_kill");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("pid")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "pid": 1234,
            "signal": "KILL",
            "timeout_seconds": 10,
            "max_output": 5000,
            "save_output": "/tmp/kill.txt"
        });
        let args: SshProcessKillArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pid, 1234);
        assert_eq!(args.signal.as_deref(), Some("KILL"));
        assert_eq!(args.timeout_seconds, Some(10));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/kill.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "pid": 5678});
        let args: SshProcessKillArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pid, 5678);
        assert!(args.signal.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshProcessKillHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("signal"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "pid": 1234});
        let args: SshProcessKillArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshProcessKillArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshProcessKillHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "pid": "not_a_number"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
