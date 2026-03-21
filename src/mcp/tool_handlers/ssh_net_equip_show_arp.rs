//! SSH Network Equipment Show ARP Tool Handler
//!
//! Shows ARP table on a network device via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::network_equipment::{EquipmentType, NetworkEquipmentCommandBuilder};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshNetEquipShowArpArgs {
    host: String,
    #[serde(default)]
    equipment_type: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshNetEquipShowArpArgs);

pub struct NetEquipShowArpTool;

impl StandardTool for NetEquipShowArpTool {
    type Args = SshNetEquipShowArpArgs;

    const NAME: &'static str = "ssh_net_equip_show_arp";

    const DESCRIPTION: &'static str = "Show ARP table on a network device.";

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

    fn build_command(args: &SshNetEquipShowArpArgs, _host_config: &HostConfig) -> Result<String> {
        let eq_type = args
            .equipment_type
            .as_deref()
            .map_or(EquipmentType::Generic, EquipmentType::from_str_loose);
        Ok(NetworkEquipmentCommandBuilder::build_show_arp_command(eq_type))
    }
}

/// Handler for the `ssh_net_equip_show_arp` tool.
pub type SshNetEquipShowArpHandler = StandardToolHandler<NetEquipShowArpTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshNetEquipShowArpHandler::new();
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
        let handler = SshNetEquipShowArpHandler::new();
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
        let handler = SshNetEquipShowArpHandler::new();
        assert_eq!(handler.name(), "ssh_net_equip_show_arp");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }
}
