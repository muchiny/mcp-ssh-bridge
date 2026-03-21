//! SSH Network Equipment Config Tool Handler
//!
//! Sends configuration commands to a network device via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::network_equipment::{EquipmentType, NetworkEquipmentCommandBuilder};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshNetEquipConfigArgs {
    host: String,
    #[serde(default)]
    equipment_type: Option<String>,
    commands: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshNetEquipConfigArgs);

pub struct NetEquipConfigTool;

impl StandardTool for NetEquipConfigTool {
    type Args = SshNetEquipConfigArgs;

    const NAME: &'static str = "ssh_net_equip_config";

    const DESCRIPTION: &'static str = "Send configuration commands to a network device. \
        Automatically wraps in configure mode for the device type. Use with caution.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "equipment_type": {
                "type": "string",
                "description": "Device type: cisco, juniper, mikrotik, fortinet, or generic (default: generic)"
            },
            "commands": {
                "type": "string",
                "description": "Configuration commands to send (newline-separated for multiple commands)"
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
        "required": ["host", "commands"]
    }"#;

    fn build_command(args: &SshNetEquipConfigArgs, _host_config: &HostConfig) -> Result<String> {
        let eq_type = args
            .equipment_type
            .as_deref()
            .map_or(EquipmentType::Generic, EquipmentType::from_str_loose);
        Ok(NetworkEquipmentCommandBuilder::build_config_command(
            eq_type,
            &args.commands,
        ))
    }
}

/// Handler for the `ssh_net_equip_config` tool.
pub type SshNetEquipConfigHandler = StandardToolHandler<NetEquipConfigTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshNetEquipConfigHandler::new();
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
        let handler = SshNetEquipConfigHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "commands": "interface Gi0/1"})),
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
        let handler = SshNetEquipConfigHandler::new();
        assert_eq!(handler.name(), "ssh_net_equip_config");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("commands")));
    }
}
