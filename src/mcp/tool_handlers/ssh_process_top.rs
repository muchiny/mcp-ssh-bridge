//! Handler for the `ssh_process_top` tool.
//!
//! Shows top processes by resource usage on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::process::ProcessCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshProcessTopArgs {
    /// Target host name from configuration.
    host: String,
    /// Sort field: %cpu, %mem, rss, vsz.
    sort_by: Option<String>,
    /// Filter processes by user.
    user: Option<String>,
    /// Number of top processes to show.
    count: Option<u32>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshProcessTopArgs);

pub struct ProcessTopTool;

impl StandardTool for ProcessTopTool {
    type Args = SshProcessTopArgs;

    const NAME: &'static str = "ssh_process_top";

    const DESCRIPTION: &'static str = "Show top processes by resource usage on a remote host. Prefer this over ssh_exec as \
        it provides a non-interactive snapshot sorted by CPU or memory. Use ssh_process_list \
        for filtering by user or name.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "sort_by": {
                        "type": "string",
                        "description": "Sort field (default: %cpu)",
                        "enum": ["%cpu", "%mem", "rss", "vsz"]
                    },
                    "user": {
                        "type": "string",
                        "description": "Filter processes by user"
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of top processes to show",
                        "minimum": 1
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

    fn build_command(args: &SshProcessTopArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(ProcessCommandBuilder::build_top_command(
            args.sort_by.as_deref(),
            args.user.as_deref(),
            args.count,
        ))
    }
}

/// Handler for the `ssh_process_top` tool.
pub type SshProcessTopHandler = StandardToolHandler<ProcessTopTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshProcessTopHandler::new();
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
        let handler = SshProcessTopHandler::new();
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
        let handler = SshProcessTopHandler::new();
        assert_eq!(handler.name(), "ssh_process_top");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_process_top");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "sort_by": "%mem",
            "user": "www-data",
            "count": 20,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/top.txt"
        });
        let args: SshProcessTopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.sort_by.as_deref(), Some("%mem"));
        assert_eq!(args.user.as_deref(), Some("www-data"));
        assert_eq!(args.count, Some(20));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/top.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshProcessTopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.sort_by.is_none());
        assert!(args.user.is_none());
        assert!(args.count.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshProcessTopHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("sort_by"));
        assert!(props.contains_key("user"));
        assert!(props.contains_key("count"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshProcessTopArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshProcessTopArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshProcessTopHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
