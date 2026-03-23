//! SSH Podman Compose Tool Handler
//!
//! Runs podman compose commands on a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::podman::PodmanCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshPodmanComposeArgs {
    host: String,
    action: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshPodmanComposeArgs);

pub struct PodmanComposeTool;

impl StandardTool for PodmanComposeTool {
    type Args = SshPodmanComposeArgs;

    const NAME: &'static str = "ssh_podman_compose";

    const DESCRIPTION: &'static str = "Run podman compose commands on a remote host. Specify \
        action like 'up -d', 'down', 'ps'.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "action": {
                "type": "string",
                "description": "Compose action to run (e.g. 'up -d', 'down', 'ps', 'logs')"
            },
            "file": {
                "type": "string",
                "description": "Path to compose file (default: docker-compose.yml in current directory)"
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
        "required": ["host", "action"]
    }"#;

    fn build_command(args: &SshPodmanComposeArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PodmanCommandBuilder::build_compose_command(
            &args.action,
            args.file.as_deref(),
        ))
    }
}

/// Handler for the `ssh_podman_compose` tool.
pub type SshPodmanComposeHandler = StandardToolHandler<PodmanComposeTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPodmanComposeHandler::new();
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
        let handler = SshPodmanComposeHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "action": "ps"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshPodmanComposeHandler::new();
        assert_eq!(handler.name(), "ssh_podman_compose");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("action")));
    }
}
