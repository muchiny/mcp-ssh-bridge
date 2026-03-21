//! SSH Podman Exec Tool Handler
//!
//! Executes a command inside a running Podman container on a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::podman::PodmanCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshPodmanExecArgs {
    host: String,
    container: String,
    command: String,
    #[serde(default)]
    interactive: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshPodmanExecArgs);

pub struct PodmanExecTool;

impl StandardTool for PodmanExecTool {
    type Args = SshPodmanExecArgs;

    const NAME: &'static str = "ssh_podman_exec";

    const DESCRIPTION: &'static str = "Execute a command inside a running Podman container on \
        a remote host.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "container": {
                "type": "string",
                "description": "Container name or ID to execute in"
            },
            "command": {
                "type": "string",
                "description": "Command to execute inside the container"
            },
            "interactive": {
                "type": "boolean",
                "description": "Run in interactive mode with pseudo-TTY (default: false)"
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
        "required": ["host", "container", "command"]
    }"#;

    fn build_command(args: &SshPodmanExecArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PodmanCommandBuilder::build_exec_command(
            &args.container,
            &args.command,
            args.interactive.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_podman_exec` tool.
pub type SshPodmanExecHandler = StandardToolHandler<PodmanExecTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPodmanExecHandler::new();
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
        let handler = SshPodmanExecHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "container": "myapp", "command": "ls"})),
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
        let handler = SshPodmanExecHandler::new();
        assert_eq!(handler.name(), "ssh_podman_exec");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("container")));
        assert!(required.contains(&json!("command")));
    }
}
