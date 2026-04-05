//! SSH Podman PS Tool Handler
//!
//! Lists Podman containers on a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::podman::PodmanCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshPodmanPsArgs {
    host: String,
    #[serde(default)]
    all: Option<bool>,
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshPodmanPsArgs);

pub struct PodmanPsTool;

impl StandardTool for PodmanPsTool {
    type Args = SshPodmanPsArgs;

    const NAME: &'static str = "ssh_podman_ps";

    const DESCRIPTION: &'static str = "List Podman containers on a remote host. Set all=true \
        to include stopped containers.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "all": {
                "type": "boolean",
                "description": "Include stopped containers (default: false)"
            },
            "filter": {
                "type": "string",
                "description": "Filter containers (e.g. 'status=running', 'name=myapp')"
            },
            "format": {
                "type": "string",
                "description": "Go template format string for output"
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
        "required": ["host"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind = crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshPodmanPsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PodmanCommandBuilder::build_ps_command(
            args.all.unwrap_or(false),
            args.filter.as_deref(),
            args.format.as_deref(),
        ))
    }
}

/// Handler for the `ssh_podman_ps` tool.
pub type SshPodmanPsHandler = StandardToolHandler<PodmanPsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPodmanPsHandler::new();
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
        let handler = SshPodmanPsHandler::new();
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
        let handler = SshPodmanPsHandler::new();
        assert_eq!(handler.name(), "ssh_podman_ps");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }
}
