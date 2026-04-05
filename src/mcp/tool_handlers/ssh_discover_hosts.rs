//! Handler for the `ssh_discover_hosts` tool.
//!
//! Discovers hosts on a network via a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::inventory::InventoryCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshDiscoverHostsArgs {
    /// Target host name from configuration.
    host: String,
    /// Network address/CIDR to scan (e.g. "192.168.1.0/24").
    network: String,
    /// Discovery method: nmap, arp, or ip. Auto-detects if not specified.
    #[serde(default)]
    method: Option<String>,
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

impl_common_args!(SshDiscoverHostsArgs);

pub struct DiscoverHostsTool;

impl StandardTool for DiscoverHostsTool {
    type Args = SshDiscoverHostsArgs;

    const NAME: &'static str = "ssh_discover_hosts";

    const DESCRIPTION: &'static str = "Discover hosts on a network from a remote host. \
        Scans the specified network using nmap, arp-scan, or ip neigh to find active hosts. \
        Auto-detects the best available scanning method if not specified.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "network": {
                        "type": "string",
                        "description": "Network address/CIDR to scan (e.g. '192.168.1.0/24')"
                    },
                    "method": {
                        "type": "string",
                        "description": "Discovery method: nmap, arp, or ip. Auto-detects if not specified.",
                        "enum": ["nmap", "arp", "ip"]
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
                "required": ["host", "network"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind = crate::domain::output_kind::OutputKind::Tabular;

    fn validate(args: &SshDiscoverHostsArgs, _host_config: &HostConfig) -> Result<()> {
        InventoryCommandBuilder::validate_network(&args.network)?;
        Ok(())
    }

    fn build_command(args: &SshDiscoverHostsArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(InventoryCommandBuilder::build_discover_hosts_command(
            &args.network,
            args.method.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        _args: &SshDiscoverHostsArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        // ip neigh / arp-scan produce columnar output — convert to TSV
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_select_columns(parsed, dr);
        ToolCallResult::text(parsed.to_tsv())
    }
}

/// Handler for the `ssh_discover_hosts` tool.
pub type SshDiscoverHostsHandler = StandardToolHandler<DiscoverHostsTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDiscoverHostsHandler::new();
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
        let handler = SshDiscoverHostsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "network": "192.168.1.0/24"})),
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
        let handler = SshDiscoverHostsHandler::new();
        assert_eq!(handler.name(), "ssh_discover_hosts");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_discover_hosts");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("network")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "network": "10.0.0.0/24",
            "method": "nmap",
            "timeout_seconds": 120,
            "max_output": 50000,
            "save_output": "/tmp/hosts.txt"
        });
        let args: SshDiscoverHostsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.network, "10.0.0.0/24");
        assert_eq!(args.method.as_deref(), Some("nmap"));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(50000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/hosts.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "network": "192.168.1.0/24"});
        let args: SshDiscoverHostsArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.network, "192.168.1.0/24");
        assert!(args.method.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDiscoverHostsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("method"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "network": "10.0.0.0/8"});
        let args: SshDiscoverHostsArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDiscoverHostsArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDiscoverHostsHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "network": "10.0.0.0/24"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_has_type_object() {
        let handler = SshDiscoverHostsHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_description_not_empty() {
        let handler = SshDiscoverHostsHandler::new();
        assert!(handler.description().len() > 10);
    }
}
