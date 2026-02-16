//! SSH Docker Network Ls Tool Handler
//!
//! Lists Docker networks on a remote host via `docker network ls`.
//! Auto-detects `docker` or `podman` binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::docker::DockerCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshDockerNetworkLsArgs {
    host: String,
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    docker_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshDockerNetworkLsArgs);

pub struct DockerNetworkLsTool;

impl StandardTool for DockerNetworkLsTool {
    type Args = SshDockerNetworkLsArgs;

    const NAME: &'static str = "ssh_docker_network_ls";

    const DESCRIPTION: &'static str = "List Docker networks on a remote host. Shows network names, drivers, and scope. Use \
        filter to narrow results (e.g., driver=bridge). Auto-detects docker or podman binary.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "filter": {
                "type": "string",
                "description": "Filter by condition (e.g., driver=bridge, scope=local, name=mynetwork)"
            },
            "format": {
                "type": "string",
                "description": "Output format using Go template (e.g., '{{.Name}}\\t{{.Driver}}') or 'json'"
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
        "required": ["host"]
    }"#;

    fn build_command(args: &SshDockerNetworkLsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DockerCommandBuilder::build_network_ls_command(
            args.docker_bin.as_deref(),
            args.filter.as_deref(),
            args.format.as_deref(),
        ))
    }
}

/// Handler for the `ssh_docker_network_ls` tool.
pub type SshDockerNetworkLsHandler = StandardToolHandler<DockerNetworkLsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDockerNetworkLsHandler::new();
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
        let handler = SshDockerNetworkLsHandler::new();
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
        let handler = SshDockerNetworkLsHandler::new();
        assert_eq!(handler.name(), "ssh_docker_network_ls");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_docker_network_ls");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "filter": "driver=bridge",
            "format": "json",
            "docker_bin": "podman",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/output.txt"
        });
        let args: SshDockerNetworkLsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.filter, Some("driver=bridge".to_string()));
        assert_eq!(args.format, Some("json".to_string()));
        assert_eq!(args.docker_bin, Some("podman".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshDockerNetworkLsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.filter.is_none());
        assert!(args.format.is_none());
        assert!(args.docker_bin.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDockerNetworkLsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("filter"));
        assert!(properties.contains_key("format"));
        assert!(properties.contains_key("docker_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshDockerNetworkLsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDockerNetworkLsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDockerNetworkLsHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_rate_limit_returns_error_result() {
        use crate::ports::mock::create_test_context_with_host;
        use crate::ports::protocol::ToolContent;
        use crate::security::RateLimiter;
        use std::sync::Arc;

        let handler = SshDockerNetworkLsHandler::new();
        let mut ctx = create_test_context_with_host();
        ctx.rate_limiter = Arc::new(RateLimiter::new(1));

        // Exhaust the single token for server1
        assert!(ctx.rate_limiter.check("server1").is_ok());

        // Use explicit docker_bin to avoid auto-detect prefix with &>/dev/null
        // which triggers the blacklist pattern (?i)>\s*/dev/
        let result = handler
            .execute(
                Some(json!({"host": "server1", "docker_bin": "docker"})),
                &ctx,
            )
            .await;

        // Rate limit returns Ok with error content, not Err
        let result = result.unwrap();
        assert_eq!(result.is_error, Some(true));
        match &result.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("Rate limit exceeded"));
                assert!(text.contains("server1"));
            }
            _ => panic!("Expected Text content"),
        }
    }
}
