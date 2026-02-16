//! SSH Git Log Tool Handler
//!
//! Shows commit history of a Git repository on a remote host
//! via `git -C {path} log`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::git::GitCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshGitLogArgs {
    host: String,
    path: String,
    #[serde(default)]
    max_count: Option<u32>,
    #[serde(default)]
    oneline: Option<bool>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default, rename = "format")]
    log_format: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshGitLogArgs);

pub struct GitLogTool;

impl StandardTool for GitLogTool {
    type Args = SshGitLogArgs;

    const NAME: &'static str = "ssh_git_log";

    const DESCRIPTION: &'static str = "Show commit history of a Git repository on a remote host. Supports filtering by \
        branch, author, date (--since), and custom format. Use max_count to limit results and \
        oneline for compact output.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "path": {
                "type": "string",
                "description": "Absolute path to the Git repository on the remote host"
            },
            "max_count": {
                "type": "integer",
                "description": "Limit number of commits to show (maps to --max-count)",
                "minimum": 1
            },
            "oneline": {
                "type": "boolean",
                "description": "Show each commit on a single line (default: false)"
            },
            "branch": {
                "type": "string",
                "description": "Branch name to show log for (default: current branch)"
            },
            "author": {
                "type": "string",
                "description": "Filter commits by author (maps to --author)"
            },
            "since": {
                "type": "string",
                "description": "Show commits after date (maps to --since, e.g. '2024-01-01' or '1 week ago')"
            },
            "format": {
                "type": "string",
                "description": "Pretty-print format string (maps to --format, e.g. '%H %s')"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "path"]
    }"#;

    fn build_command(args: &SshGitLogArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(GitCommandBuilder::build_log_command(
            &args.path,
            args.max_count,
            args.oneline.unwrap_or(false),
            args.branch.as_deref(),
            args.author.as_deref(),
            args.since.as_deref(),
            args.log_format.as_deref(),
        ))
    }
}

/// Handler for the `ssh_git_log` tool.
pub type SshGitLogHandler = StandardToolHandler<GitLogTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshGitLogHandler::new();
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
        let handler = SshGitLogHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "/opt/repo"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshGitLogHandler::new();
        assert_eq!(handler.name(), "ssh_git_log");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_git_log");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/opt/repo",
            "max_count": 10,
            "oneline": true,
            "branch": "main",
            "author": "alice",
            "since": "1 week ago",
            "format": "%H %s"
        });
        let args: SshGitLogArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/opt/repo");
        assert_eq!(args.max_count, Some(10));
        assert_eq!(args.oneline, Some(true));
        assert_eq!(args.branch, Some("main".to_string()));
        assert_eq!(args.log_format, Some("%H %s".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/opt/repo"});
        let args: SshGitLogArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.max_count.is_none());
        assert!(args.branch.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshGitLogHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("max_count"));
        assert!(properties.contains_key("oneline"));
        assert!(properties.contains_key("branch"));
        assert!(properties.contains_key("author"));
        assert!(properties.contains_key("since"));
        assert!(properties.contains_key("format"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/opt/repo"});
        let args: SshGitLogArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshGitLogArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshGitLogHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "path": "/opt/repo"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
