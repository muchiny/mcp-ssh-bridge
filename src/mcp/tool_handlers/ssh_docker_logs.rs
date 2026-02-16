//! SSH Docker Logs Tool Handler
//!
//! Fetches logs from a Docker container on a remote host via `docker logs`.
//! Auto-detects `docker` or `podman` binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::docker::DockerCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshDockerLogsArgs {
    host: String,
    container: String,
    #[serde(default)]
    tail: Option<u64>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    timestamps: Option<bool>,
    #[serde(default)]
    docker_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshDockerLogsArgs);

pub struct DockerLogsTool;

impl StandardTool for DockerLogsTool {
    type Args = SshDockerLogsArgs;

    const NAME: &'static str = "ssh_docker_logs";

    const DESCRIPTION: &'static str = "Fetch logs from a Docker container on a remote host. Use ssh_docker_ps first to find \
        container names. Supports tail (last N lines), since/until time-based filtering, and \
        timestamps. Auto-detects docker or podman binary. Returns log text.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "container": {
                "type": "string",
                "description": "Container name or ID to fetch logs from"
            },
            "tail": {
                "type": "integer",
                "description": "Number of lines from the end (--tail=N, default: all)",
                "minimum": 1
            },
            "since": {
                "type": "string",
                "description": "Show logs since timestamp or relative time (e.g., 2024-01-01, 1h, 30m)"
            },
            "until": {
                "type": "string",
                "description": "Show logs before timestamp or relative time"
            },
            "timestamps": {
                "type": "boolean",
                "description": "Include timestamps in log output (--timestamps)"
            },
            "docker_bin": {
                "type": "string",
                "description": "Custom docker binary path (default: auto-detect docker or podman)"
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
        "required": ["host", "container"]
    }"#;

    fn build_command(args: &SshDockerLogsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DockerCommandBuilder::build_logs_command(
            args.docker_bin.as_deref(),
            &args.container,
            args.tail,
            args.since.as_deref(),
            args.until.as_deref(),
            args.timestamps.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_docker_logs` tool.
pub type SshDockerLogsHandler = StandardToolHandler<DockerLogsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDockerLogsHandler::new();
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
        let handler = SshDockerLogsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "container": "nginx"})),
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
        let handler = SshDockerLogsHandler::new();
        assert_eq!(handler.name(), "ssh_docker_logs");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("container")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "container": "nginx",
            "tail": 100,
            "since": "1h",
            "until": "30m",
            "timestamps": true,
            "docker_bin": "podman",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshDockerLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "nginx");
        assert_eq!(args.tail, Some(100));
        assert_eq!(args.since, Some("1h".to_string()));
        assert_eq!(args.timestamps, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "container": "web"});
        let args: SshDockerLogsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.container, "web");
        assert!(args.tail.is_none());
        assert!(args.since.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshDockerLogsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDockerLogsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("tail"));
        assert!(properties.contains_key("since"));
        assert!(properties.contains_key("until"));
        assert!(properties.contains_key("timestamps"));
        assert!(properties.contains_key("docker_bin"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "container": "nginx"});
        let args: SshDockerLogsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDockerLogsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDockerLogsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "container": "nginx"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
