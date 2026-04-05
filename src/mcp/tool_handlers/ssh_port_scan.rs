//! Handler for the `ssh_port_scan` tool.
//!
//! Scans for open ports on a remote host or target.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::network_security::{NetworkSecurityCommandBuilder, validate_target};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshPortScanArgs {
    /// Target host name from configuration.
    host: String,
    /// Target address to scan (default: local).
    #[serde(default)]
    target: Option<String>,
    /// Comma-separated list of ports to scan.
    #[serde(default)]
    ports: Option<String>,
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

impl_common_args!(SshPortScanArgs);

pub struct PortScanTool;

impl StandardTool for PortScanTool {
    type Args = SshPortScanArgs;

    const NAME: &'static str = "ssh_port_scan";

    const DESCRIPTION: &'static str = "Scan for open ports on a remote host. Prefer this over ssh_exec for port \
        scanning as it uses ss/netstat for local scanning or nmap/bash fallback for remote targets. \
        Supports custom port lists.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target address to scan (default: local host)"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Comma-separated list of ports to scan (e.g., '22,80,443')"
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
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind = crate::domain::output_kind::OutputKind::Tabular;

    fn validate(args: &SshPortScanArgs, _host_config: &HostConfig) -> Result<()> {
        if let Some(ref target) = args.target {
            validate_target(target)?;
        }
        Ok(())
    }

    fn build_command(args: &SshPortScanArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(NetworkSecurityCommandBuilder::build_port_scan_command(
            args.target.as_deref(),
            args.ports.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        _args: &SshPortScanArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        // ss/netstat output is columnar — convert to TSV for token efficiency
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        ToolCallResult::text(parsed.to_tsv())
    }
}

/// Handler for the `ssh_port_scan` tool.
pub type SshPortScanHandler = StandardToolHandler<PortScanTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPortScanHandler::new();
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
        let handler = SshPortScanHandler::new();
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
        let handler = SshPortScanHandler::new();
        assert_eq!(handler.name(), "ssh_port_scan");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_port_scan");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "target": "192.168.1.1",
            "ports": "22,80,443",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/port_scan.txt"
        });
        let args: SshPortScanArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.target.as_deref(), Some("192.168.1.1"));
        assert_eq!(args.ports.as_deref(), Some("22,80,443"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/port_scan.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshPortScanArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.target.is_none());
        assert!(args.ports.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshPortScanHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("target"));
        assert!(props.contains_key("ports"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshPortScanArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshPortScanArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshPortScanHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
