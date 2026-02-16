//! SSH Git Diff Tool Handler
//!
//! Shows changes in a Git repository on a remote host
//! via `git -C {path} diff`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::git::GitCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshGitDiffArgs {
    host: String,
    path: String,
    #[serde(default)]
    staged: Option<bool>,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    commit: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshGitDiffArgs);

pub struct GitDiffTool;

impl StandardTool for GitDiffTool {
    type Args = SshGitDiffArgs;

    const NAME: &'static str = "ssh_git_diff";

    const DESCRIPTION: &'static str = "Show changes in a Git repository on a remote host. By default shows unstaged changes; \
        use staged=true for staged changes. Can diff against a specific commit or limit to a \
        specific file.";

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
            "staged": {
                "type": "boolean",
                "description": "Show staged (cached) changes instead of unstaged (default: false)"
            },
            "file": {
                "type": "string",
                "description": "Limit diff to a specific file path"
            },
            "commit": {
                "type": "string",
                "description": "Diff against a specific commit (e.g. HEAD~3, abc123)"
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

    fn build_command(args: &SshGitDiffArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(GitCommandBuilder::build_diff_command(
            &args.path,
            args.staged.unwrap_or(false),
            args.file.as_deref(),
            args.commit.as_deref(),
        ))
    }
}

/// Handler for the `ssh_git_diff` tool.
pub type SshGitDiffHandler = StandardToolHandler<GitDiffTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshGitDiffHandler::new();
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
        let handler = SshGitDiffHandler::new();
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
        let handler = SshGitDiffHandler::new();
        assert_eq!(handler.name(), "ssh_git_diff");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_git_diff");
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
            "staged": true,
            "file": "src/main.rs",
            "commit": "HEAD~3"
        });
        let args: SshGitDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.staged, Some(true));
        assert_eq!(args.file, Some("src/main.rs".to_string()));
        assert_eq!(args.commit, Some("HEAD~3".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/opt/repo"});
        let args: SshGitDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.staged.is_none());
        assert!(args.file.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshGitDiffHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("staged"));
        assert!(properties.contains_key("file"));
        assert!(properties.contains_key("commit"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/opt/repo"});
        let args: SshGitDiffArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshGitDiffArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshGitDiffHandler::new();
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
