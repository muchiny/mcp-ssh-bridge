//! Handler for the `ssh_host_tags` tool.
//!
//! Manages host tags on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::inventory::InventoryCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshHostTagsArgs {
    /// Target host name from configuration.
    host: String,
    /// Tag action: list, add, or remove.
    action: String,
    /// Tags to add or remove (comma-separated).
    #[serde(default)]
    tags: Option<String>,
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

impl_common_args!(SshHostTagsArgs);

pub struct HostTagsTool;

impl StandardTool for HostTagsTool {
    type Args = SshHostTagsArgs;

    const NAME: &'static str = "ssh_host_tags";

    const DESCRIPTION: &'static str = "Manage host tags on a remote host. \
        Supports listing, adding, and removing tags stored in /etc/host-tags. \
        Tags are useful for categorizing and grouping hosts in inventory.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "action": {
                        "type": "string",
                        "description": "Tag action: list, add, or remove",
                        "enum": ["list", "add", "remove"]
                    },
                    "tags": {
                        "type": "string",
                        "description": "Tags to add or remove (comma-separated, e.g. 'web,production')"
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
                "required": ["host", "action"]
            }"#;

    fn validate(args: &SshHostTagsArgs, _host_config: &HostConfig) -> Result<()> {
        InventoryCommandBuilder::validate_tag_action(&args.action)?;
        Ok(())
    }

    fn build_command(args: &SshHostTagsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(InventoryCommandBuilder::build_host_tags_command(
            &args.action,
            args.tags.as_deref(),
        ))
    }
}

/// Handler for the `ssh_host_tags` tool.
pub type SshHostTagsHandler = StandardToolHandler<HostTagsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHostTagsHandler::new();
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
        let handler = SshHostTagsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "action": "list"})),
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
        let handler = SshHostTagsHandler::new();
        assert_eq!(handler.name(), "ssh_host_tags");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_host_tags");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("action")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "action": "add",
            "tags": "web,production",
            "timeout_seconds": 10,
            "max_output": 5000,
            "save_output": "/tmp/tags.txt"
        });
        let args: SshHostTagsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.action, "add");
        assert_eq!(args.tags.as_deref(), Some("web,production"));
        assert_eq!(args.timeout_seconds, Some(10));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/tags.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "action": "list"});
        let args: SshHostTagsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.action, "list");
        assert!(args.tags.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHostTagsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("tags"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "action": "list"});
        let args: SshHostTagsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHostTagsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHostTagsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "action": "list"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_has_type_object() {
        let handler = SshHostTagsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_description_not_empty() {
        let handler = SshHostTagsHandler::new();
        assert!(handler.description().len() > 10);
    }
}
