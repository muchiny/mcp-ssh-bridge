//! Handler for the `ssh_multicloud_list` tool.
//!
//! Lists instances from a single cloud provider via a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::multicloud::MulticloudCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshMulticloudListArgs {
    /// Target host name from configuration.
    host: String,
    /// Cloud provider: aws, gcp, or azure.
    provider: String,
    /// Override default command timeout in seconds.
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    #[serde(default)]
    max_output: Option<u64>,
    /// Save full output to a local file path.
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshMulticloudListArgs);

pub struct MulticloudListTool;

impl StandardTool for MulticloudListTool {
    type Args = SshMulticloudListArgs;

    const NAME: &'static str = "ssh_multicloud_list";

    const DESCRIPTION: &'static str = "List instances from a cloud provider via a remote host. \
        Queries AWS EC2, GCP Compute Engine, or Azure VMs to list all instances. \
        Returns JSON output for programmatic processing.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "provider": {
                        "type": "string",
                        "description": "Cloud provider: aws, gcp, or azure",
                        "enum": ["aws", "gcp", "azure"]
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters before truncation",
                        "minimum": 100
                    },
                    "save_output": {
                        "type": "string",
                        "description": "Save full output to a local file path"
                    }
                },
                "required": ["host", "provider"]
            }"#;

    fn validate(args: &SshMulticloudListArgs, _host_config: &HostConfig) -> Result<()> {
        MulticloudCommandBuilder::validate_provider(&args.provider)?;
        Ok(())
    }

    fn build_command(args: &SshMulticloudListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(MulticloudCommandBuilder::build_multicloud_list_command(
            &args.provider,
        ))
    }
}

/// Handler for the `ssh_multicloud_list` tool.
pub type SshMulticloudListHandler = StandardToolHandler<MulticloudListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshMulticloudListHandler::new();
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
        let handler = SshMulticloudListHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "provider": "aws"})),
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
        let handler = SshMulticloudListHandler::new();
        assert_eq!(handler.name(), "ssh_multicloud_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_multicloud_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("provider")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "provider": "gcp",
            "timeout_seconds": 60,
            "max_output": 50000,
            "save_output": "/tmp/instances.json"
        });
        let args: SshMulticloudListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.provider, "gcp");
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(50000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/instances.json"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "provider": "aws"});
        let args: SshMulticloudListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.provider, "aws");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshMulticloudListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "provider": "aws"});
        let args: SshMulticloudListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshMulticloudListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshMulticloudListHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "provider": "aws"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_has_type_object() {
        let handler = SshMulticloudListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_description_not_empty() {
        let handler = SshMulticloudListHandler::new();
        assert!(handler.description().len() > 10);
    }
}
