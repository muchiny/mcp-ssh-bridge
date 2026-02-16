//! Handler for the `ssh_firewall_allow` tool.
//!
//! Adds a firewall allow rule on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::firewall::{FirewallCommandBuilder, validate_port};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshFirewallAllowArgs {
    /// Target host name from configuration.
    host: String,
    /// Port number or range to allow (e.g., "80", "8080:8090").
    port: String,
    /// Protocol (tcp/udp). Defaults to tcp.
    protocol: Option<String>,
    /// Source IP or CIDR to restrict the rule to.
    source: Option<String>,
    /// Override auto-detected firewall tool (ufw/firewall-cmd/iptables).
    firewall_tool: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshFirewallAllowArgs);

pub struct FirewallAllowTool;

impl StandardTool for FirewallAllowTool {
    type Args = SshFirewallAllowArgs;

    const NAME: &'static str = "ssh_firewall_allow";

    const DESCRIPTION: &'static str = "Add a firewall allow rule on a remote host. Prefer this over ssh_exec as it \
        auto-detects the firewall tool (ufw/firewall-cmd/iptables) and validates parameters. \
        Opens a port for incoming traffic, optionally restricted to a source IP/CIDR. Verify \
        with ssh_firewall_list afterward.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "port": {
                        "type": "string",
                        "description": "Port number or range to allow (e.g., '80', '8080:8090')"
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Protocol to allow. Defaults to tcp",
                        "enum": ["tcp", "udp"],
                        "default": "tcp"
                    },
                    "source": {
                        "type": "string",
                        "description": "Source IP or CIDR to restrict the rule to"
                    },
                    "firewall_tool": {
                        "type": "string",
                        "description": "Override auto-detected firewall tool",
                        "enum": ["ufw", "firewall-cmd", "iptables"]
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1,
                        "maximum": 3600
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
                "required": ["host", "port"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshFirewallAllowArgs, _host_config: &HostConfig) -> Result<String> {
        FirewallCommandBuilder::build_allow_command(
            args.firewall_tool.as_deref(),
            &args.port,
            args.protocol.as_deref(),
            args.source.as_deref(),
        )
    }

    fn validate(args: &SshFirewallAllowArgs, _host_config: &HostConfig) -> Result<()> {
        validate_port(&args.port)?;
        Ok(())
    }
}

/// Handler for the `ssh_firewall_allow` tool.
pub type SshFirewallAllowHandler = StandardToolHandler<FirewallAllowTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFirewallAllowHandler::new();
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
        let handler = SshFirewallAllowHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "port": "80"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshFirewallAllowHandler::new();
        assert_eq!(handler.name(), "ssh_firewall_allow");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_firewall_allow");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("port")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "port": "443",
            "protocol": "tcp",
            "source": "10.0.0.0/8",
            "firewall_tool": "ufw",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/fw_allow.txt"
        });
        let args: SshFirewallAllowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.port, "443");
        assert_eq!(args.protocol.as_deref(), Some("tcp"));
        assert_eq!(args.source.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(args.firewall_tool.as_deref(), Some("ufw"));
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/fw_allow.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "port": "80"});
        let args: SshFirewallAllowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.port, "80");
        assert!(args.protocol.is_none());
        assert!(args.source.is_none());
        assert!(args.firewall_tool.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshFirewallAllowHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("protocol"));
        assert!(props.contains_key("source"));
        assert!(props.contains_key("firewall_tool"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "port": "80"});
        let args: SshFirewallAllowArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshFirewallAllowArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshFirewallAllowHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "port": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
