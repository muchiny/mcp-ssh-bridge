//! Handler for the `ssh_service_list` tool.
//!
//! Lists systemd services on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::systemd::SystemdCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshServiceListArgs {
    host: String,
    state: Option<String>,
    all: Option<bool>,
    unit_type: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshServiceListArgs);

pub struct ServiceListTool;

impl StandardTool for ServiceListTool {
    type Args = SshServiceListArgs;

    const NAME: &'static str = "ssh_service_list";

    const DESCRIPTION: &'static str = "List systemd services on a remote host. Start here to discover service names before \
        using ssh_service_status, ssh_service_start, ssh_service_stop, or \
        ssh_service_restart. Filter by state (running, failed, inactive) and unit type. \
        Returns service name, load state, active state, and description.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "state": {
                "type": "string",
                "description": "Filter by state: running, failed, inactive, active, etc."
            },
            "all": {
                "type": "boolean",
                "description": "Show all loaded units including inactive ones (default: false)"
            },
            "unit_type": {
                "type": "string",
                "description": "Filter by unit type: service, socket, timer, mount, etc."
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

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshServiceListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(SystemdCommandBuilder::build_list_command(
            args.state.as_deref(),
            args.all.unwrap_or(false),
            args.unit_type.as_deref(),
        ))
    }
}

/// Handler for the `ssh_service_list` tool.
pub type SshServiceListHandler = StandardToolHandler<ServiceListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshServiceListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshServiceListHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshServiceListHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_service_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "state": "running",
            "all": true,
            "unit_type": "service",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshServiceListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.state, Some("running".to_string()));
        assert_eq!(args.all, Some(true));
        assert_eq!(args.unit_type, Some("service".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshServiceListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.state.is_none());
        assert!(args.all.is_none());
        assert!(args.unit_type.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshServiceListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("state"));
        assert!(props.contains_key("all"));
        assert!(props.contains_key("unit_type"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h"});
        let args: SshServiceListArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshServiceListArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123});
        let result = serde_json::from_value::<SshServiceListArgs>(json);
        assert!(result.is_err());
    }
}
