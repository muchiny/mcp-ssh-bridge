//! Handler for the `ssh_process_list` tool.
//!
//! Lists running processes on a remote host with optional filtering and sorting.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::process::ProcessCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshProcessListArgs {
    /// Target host name from configuration.
    host: String,
    /// Filter processes by user.
    user: Option<String>,
    /// Sort field: %cpu, %mem, rss, vsz.
    sort_by: Option<String>,
    /// Filter processes by name pattern.
    filter: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshProcessListArgs);

pub struct ProcessListTool;

impl StandardTool for ProcessListTool {
    type Args = SshProcessListArgs;

    const NAME: &'static str = "ssh_process_list";

    const DESCRIPTION: &'static str = "List running processes on a remote host. Prefer this over ssh_exec as it provides \
        structured filtering by user or process name with safe parameter handling. Sort by \
        CPU or memory usage. Returns PID, user, CPU%, memory%, and command. Use \
        ssh_process_kill to send signals to specific processes.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "user": {
                        "type": "string",
                        "description": "Filter processes by user"
                    },
                    "sort_by": {
                        "type": "string",
                        "description": "Sort field: %cpu, %mem, rss, vsz"
                    },
                    "filter": {
                        "type": "string",
                        "description": "Filter processes by name pattern"
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

    fn build_command(args: &SshProcessListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(ProcessCommandBuilder::build_list_command(
            args.user.as_deref(),
            args.sort_by.as_deref(),
            args.filter.as_deref(),
        ))
    }
}

/// Handler for the `ssh_process_list` tool.
pub type SshProcessListHandler = StandardToolHandler<ProcessListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshProcessListHandler::new();
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
        let handler = SshProcessListHandler::new();
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
        let handler = SshProcessListHandler::new();
        assert_eq!(handler.name(), "ssh_process_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_process_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "user": "root",
            "sort_by": "%cpu",
            "filter": "nginx",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/procs.txt"
        });
        let args: SshProcessListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.user.as_deref(), Some("root"));
        assert_eq!(args.sort_by.as_deref(), Some("%cpu"));
        assert_eq!(args.filter.as_deref(), Some("nginx"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/procs.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshProcessListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.user.is_none());
        assert!(args.sort_by.is_none());
        assert!(args.filter.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshProcessListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("user"));
        assert!(props.contains_key("sort_by"));
        assert!(props.contains_key("filter"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshProcessListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshProcessListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshProcessListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
