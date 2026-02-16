//! SSH Docker Stats Tool Handler
//!
//! Displays resource usage statistics of Docker containers on a remote host
//! via `docker stats`. Auto-detects `docker` or `podman` binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::docker::DockerCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshDockerStatsArgs {
    host: String,
    #[serde(default)]
    containers: Option<Vec<String>>,
    #[serde(default)]
    no_stream: Option<bool>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    docker_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshDockerStatsArgs);

pub struct DockerStatsTool;

impl StandardTool for DockerStatsTool {
    type Args = SshDockerStatsArgs;

    const NAME: &'static str = "ssh_docker_stats";

    const DESCRIPTION: &'static str = "Display CPU, memory, network, and disk I/O usage of Docker containers on a remote \
        host. Shows all running containers by default or specify specific containers. Always \
        runs in one-shot mode (--no-stream) by default. For Kubernetes pod metrics, use \
        ssh_k8s_top instead. Auto-detects docker or podman.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "containers": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Specific container names or IDs to show stats for (default: all running)"
            },
            "no_stream": {
                "type": "boolean",
                "description": "Disable streaming and show one-shot stats (default: true for MCP usage)"
            },
            "format": {
                "type": "string",
                "description": "Output format using Go template (e.g., '{{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}')"
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
            }
        },
        "required": ["host"]
    }"#;

    fn build_command(args: &SshDockerStatsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DockerCommandBuilder::build_stats_command(
            args.docker_bin.as_deref(),
            args.containers.as_deref(),
            args.no_stream.unwrap_or(true),
            args.format.as_deref(),
        ))
    }
}

/// Handler for the `ssh_docker_stats` tool.
pub type SshDockerStatsHandler = StandardToolHandler<DockerStatsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDockerStatsHandler::new();
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
        let handler = SshDockerStatsHandler::new();
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
        let handler = SshDockerStatsHandler::new();
        assert_eq!(handler.name(), "ssh_docker_stats");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_docker_stats");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "containers": ["web", "db"],
            "no_stream": true,
            "format": "{{.Name}}\t{{.CPUPerc}}",
            "docker_bin": "podman",
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshDockerStatsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(
            args.containers,
            Some(vec!["web".to_string(), "db".to_string()])
        );
        assert_eq!(args.no_stream, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshDockerStatsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.containers.is_none());
        assert!(args.no_stream.is_none());
        assert!(args.format.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDockerStatsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("containers"));
        assert!(properties.contains_key("no_stream"));
        assert!(properties.contains_key("format"));
        assert!(properties.contains_key("docker_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshDockerStatsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDockerStatsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDockerStatsHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
