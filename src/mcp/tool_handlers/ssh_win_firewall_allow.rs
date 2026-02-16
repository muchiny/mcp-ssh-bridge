//! Handler for the `ssh_win_firewall_allow` tool.
//!
//! Creates a Windows Firewall allow rule for inbound traffic on a specific port.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_firewall::{
    WindowsFirewallCommandBuilder, validate_firewall_rule_name,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshWinFirewallAllowArgs {
    host: String,
    name: String,
    port: u16,
    protocol: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinFirewallAllowArgs);

pub struct WinFirewallAllowTool;

impl StandardTool for WinFirewallAllowTool {
    type Args = SshWinFirewallAllowArgs;

    const NAME: &'static str = "ssh_win_firewall_allow";

    const DESCRIPTION: &'static str = "Create a Windows Firewall allow rule for inbound traffic on a specific port. Use \
        ssh_win_firewall_list to check existing rules first. Verify with \
        ssh_win_firewall_list afterward.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "name", "port"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "name": {
                "type": "string",
                "description": "Display name for the firewall rule"
            },
            "port": {
                "type": "integer",
                "description": "Port number to allow (1-65535)"
            },
            "protocol": {
                "type": "string",
                "description": "Protocol to allow. Defaults to TCP",
                "enum": ["TCP", "UDP"],
                "default": "TCP"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the local machine"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshWinFirewallAllowArgs, _host_config: &HostConfig) -> Result<String> {
        let protocol = args.protocol.as_deref().unwrap_or("TCP");
        Ok(WindowsFirewallCommandBuilder::build_allow_command(
            &args.name, args.port, protocol,
        ))
    }

    fn validate(args: &SshWinFirewallAllowArgs, _host_config: &HostConfig) -> Result<()> {
        validate_firewall_rule_name(&args.name)?;
        Ok(())
    }
}

/// Handler for the `ssh_win_firewall_allow` tool.
pub type SshWinFirewallAllowHandler = StandardToolHandler<WinFirewallAllowTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinFirewallAllowHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinFirewallAllowHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "name": "AllowHTTP", "port": 80});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinFirewallAllowHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_firewall_allow");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("name")));
        assert!(required.iter().any(|v| v.as_str() == Some("port")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "name": "AllowHTTPS",
            "port": 443,
            "protocol": "TCP",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshWinFirewallAllowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "AllowHTTPS");
        assert_eq!(args.port, 443);
        assert_eq!(args.protocol, Some("TCP".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "name": "AllowHTTP", "port": 80});
        let args: SshWinFirewallAllowArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "AllowHTTP");
        assert_eq!(args.port, 80);
        assert!(args.protocol.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinFirewallAllowHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("protocol"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "name": "r", "port": 80});
        let args: SshWinFirewallAllowArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinFirewallAllowArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "name": "AllowHTTP", "port": 80});
        let result = serde_json::from_value::<SshWinFirewallAllowArgs>(json);
        assert!(result.is_err());
    }
}
