//! Handler for the `ssh_firewall_list` tool.
//!
//! Lists firewall rules on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::firewall::FirewallCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshFirewallListArgs {
    /// Target host name from configuration.
    host: String,
    /// Override auto-detected firewall tool (ufw/firewall-cmd/iptables).
    firewall_tool: Option<String>,
    /// Filter by iptables chain (INPUT/OUTPUT/FORWARD).
    chain: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshFirewallListArgs);

pub struct FirewallListTool;

impl StandardTool for FirewallListTool {
    type Args = SshFirewallListArgs;

    const NAME: &'static str = "ssh_firewall_list";

    const DESCRIPTION: &'static str = "List firewall rules on a remote host. Prefer this over ssh_exec as it auto-detects \
        the firewall tool (ufw/firewall-cmd/iptables). Returns numbered rules with protocol, \
        port, and action details. Use ssh_firewall_allow or ssh_firewall_deny to modify \
        rules.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "firewall_tool": {
                        "type": "string",
                        "description": "Override auto-detected firewall tool (ufw/firewall-cmd/iptables)"
                    },
                    "chain": {
                        "type": "string",
                        "description": "Filter by iptables chain (INPUT/OUTPUT/FORWARD)"
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
                "required": ["host"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshFirewallListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(FirewallCommandBuilder::build_list_command(
            args.firewall_tool.as_deref(),
            args.chain.as_deref(),
        ))
    }
}

/// Handler for the `ssh_firewall_list` tool.
pub type SshFirewallListHandler = StandardToolHandler<FirewallListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFirewallListHandler::new();
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
        let handler = SshFirewallListHandler::new();
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
        let handler = SshFirewallListHandler::new();
        assert_eq!(handler.name(), "ssh_firewall_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_firewall_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "firewall_tool": "iptables",
            "chain": "INPUT",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/fw_rules.txt"
        });
        let args: SshFirewallListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.firewall_tool.as_deref(), Some("iptables"));
        assert_eq!(args.chain.as_deref(), Some("INPUT"));
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/fw_rules.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshFirewallListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.firewall_tool.is_none());
        assert!(args.chain.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshFirewallListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("firewall_tool"));
        assert!(props.contains_key("chain"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshFirewallListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshFirewallListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshFirewallListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
