//! SSH Podman Inspect Tool Handler
//!
//! Inspects a Podman container or image on a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::podman::PodmanCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshPodmanInspectArgs {
    host: String,
    target: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshPodmanInspectArgs);

pub struct PodmanInspectTool;

impl StandardTool for PodmanInspectTool {
    type Args = SshPodmanInspectArgs;

    const NAME: &'static str = "ssh_podman_inspect";

    const DESCRIPTION: &'static str = "Inspect a Podman container or image on a remote host. \
        Returns detailed JSON configuration.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "target": {
                "type": "string",
                "description": "Container or image name/ID to inspect"
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
        "required": ["host", "target"]
    }"#;

    fn build_command(args: &SshPodmanInspectArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PodmanCommandBuilder::build_inspect_command(&args.target))
    }
}

/// Handler for the `ssh_podman_inspect` tool.
pub type SshPodmanInspectHandler = StandardToolHandler<PodmanInspectTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPodmanInspectHandler::new();
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
        let handler = SshPodmanInspectHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "target": "myapp"})),
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
        let handler = SshPodmanInspectHandler::new();
        assert_eq!(handler.name(), "ssh_podman_inspect");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("target")));
    }
}
