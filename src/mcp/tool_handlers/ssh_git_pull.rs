//! SSH Git Pull Tool Handler
//!
//! Pulls latest changes in a Git repository on a remote host
//! via `git -C {path} pull`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::git::GitCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshGitPullArgs {
    host: String,
    path: String,
    #[serde(default)]
    remote: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    rebase: Option<bool>,
    #[serde(default)]
    ff_only: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshGitPullArgs);

pub struct GitPullTool;

impl StandardTool for GitPullTool {
    type Args = SshGitPullArgs;

    const NAME: &'static str = "ssh_git_pull";

    const DESCRIPTION: &'static str = "Pull latest changes into a Git repository on a remote host. Fetches and integrates \
        remote changes. Supports --rebase and --ff-only flags, optional remote and branch \
        specification.";

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
            "remote": {
                "type": "string",
                "description": "Remote name to pull from (default: configured upstream)"
            },
            "branch": {
                "type": "string",
                "description": "Branch name to pull (default: current tracking branch)"
            },
            "rebase": {
                "type": "boolean",
                "description": "Rebase instead of merge when pulling (default: false)"
            },
            "ff_only": {
                "type": "boolean",
                "description": "Only fast-forward, abort if not possible (default: false)"
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

    fn build_command(args: &SshGitPullArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(GitCommandBuilder::build_pull_command(
            &args.path,
            args.remote.as_deref(),
            args.branch.as_deref(),
            args.rebase.unwrap_or(false),
            args.ff_only.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_git_pull` tool.
pub type SshGitPullHandler = StandardToolHandler<GitPullTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshGitPullHandler::new();
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
        let handler = SshGitPullHandler::new();
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
        let handler = SshGitPullHandler::new();
        assert_eq!(handler.name(), "ssh_git_pull");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_git_pull");
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
            "remote": "origin",
            "branch": "main",
            "rebase": true,
            "ff_only": false
        });
        let args: SshGitPullArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.remote, Some("origin".to_string()));
        assert_eq!(args.rebase, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/opt/repo"});
        let args: SshGitPullArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.remote.is_none());
        assert!(args.rebase.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshGitPullHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("remote"));
        assert!(properties.contains_key("branch"));
        assert!(properties.contains_key("rebase"));
        assert!(properties.contains_key("ff_only"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/opt/repo"});
        let args: SshGitPullArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshGitPullArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshGitPullHandler::new();
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
