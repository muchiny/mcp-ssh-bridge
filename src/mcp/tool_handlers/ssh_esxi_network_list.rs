//! SSH `ESXi` Network List Tool Handler
//!
//! Lists network information on an `ESXi` host via `esxcli network`.
//! Supports components: interface, vswitch, nic, all.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::esxi::EsxiCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshEsxiNetworkListArgs {
    host: String,
    #[serde(default)]
    component: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshEsxiNetworkListArgs);

pub struct EsxiNetworkListTool;

impl StandardTool for EsxiNetworkListTool {
    type Args = SshEsxiNetworkListArgs;

    const NAME: &'static str = "ssh_esxi_network_list";

    const DESCRIPTION: &'static str = "List network information on a VMware ESXi host. Components: interface (vmk adapters), \
        vswitch (virtual switches), nic (physical NICs), or all (default, returns \
        everything). Uses esxcli network commands.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration (must be an ESXi host)"
            },
            "component": {
                "type": "string",
                "description": "Network component to query (default: all)",
                "enum": ["interface", "vswitch", "nic", "all"]
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

    fn validate(args: &SshEsxiNetworkListArgs, _host_config: &HostConfig) -> Result<()> {
        if let Some(component) = &args.component {
            EsxiCommandBuilder::validate_network_component(component)?;
        }
        Ok(())
    }

    fn build_command(args: &SshEsxiNetworkListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(EsxiCommandBuilder::build_network_list_command(
            args.component.as_deref(),
        ))
    }
}

/// Handler for the `ssh_esxi_network_list` tool.
pub type SshEsxiNetworkListHandler = StandardToolHandler<EsxiNetworkListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshEsxiNetworkListHandler::new();
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
        let handler = SshEsxiNetworkListHandler::new();
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

    #[tokio::test]
    async fn test_invalid_component() {
        let handler = SshEsxiNetworkListHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "component": "firewall"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("firewall"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshEsxiNetworkListHandler::new();
        assert_eq!(handler.name(), "ssh_esxi_network_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_esxi_network_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "esxi1",
            "component": "nic",
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshEsxiNetworkListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert_eq!(args.component, Some("nic".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "esxi1"});
        let args: SshEsxiNetworkListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert!(args.component.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshEsxiNetworkListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("component"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "esxi1"});
        let args: SshEsxiNetworkListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshEsxiNetworkListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshEsxiNetworkListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
