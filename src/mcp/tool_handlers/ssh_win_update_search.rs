//! Handler for the `ssh_win_update_search` tool.
//!
//! Searches for Windows updates matching a title pattern.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_update::WindowsUpdateCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshWinUpdateSearchArgs {
    host: String,
    query: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinUpdateSearchArgs);

pub struct WinUpdateSearchTool;

impl StandardTool for WinUpdateSearchTool {
    type Args = SshWinUpdateSearchArgs;

    const NAME: &'static str = "ssh_win_update_search";

    const DESCRIPTION: &'static str = "Search for Windows updates matching a title pattern.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "query"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "query": {
                "type": "string",
                "description": "Title pattern to search for (e.g., Cumulative, Security, .NET)"
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

    fn build_command(args: &SshWinUpdateSearchArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsUpdateCommandBuilder::build_search_command(
            &args.query,
        ))
    }
}

/// Handler for the `ssh_win_update_search` tool.
pub type SshWinUpdateSearchHandler = StandardToolHandler<WinUpdateSearchTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinUpdateSearchHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinUpdateSearchHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "query": "Cumulative"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinUpdateSearchHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_update_search");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("query")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "query": "Cumulative",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshWinUpdateSearchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.query, "Cumulative");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "query": "Security"});
        let args: SshWinUpdateSearchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.query, "Security");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinUpdateSearchHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "query": "test"});
        let args: SshWinUpdateSearchArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinUpdateSearchArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "query": "Cumulative"});
        let result = serde_json::from_value::<SshWinUpdateSearchArgs>(json);
        assert!(result.is_err());
    }
}
