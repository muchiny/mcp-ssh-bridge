//! Handler for the `ssh_hyperv_vm_start` tool.
//!
//! Starts a Hyper-V virtual machine on a Windows host via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::hyperv::{HyperVCommandBuilder, validate_vm_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshHypervVmStartArgs {
    host: String,
    name: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshHypervVmStartArgs);

pub struct HypervVmStartTool;

impl StandardTool for HypervVmStartTool {
    type Args = SshHypervVmStartArgs;

    const NAME: &'static str = "ssh_hyperv_vm_start";

    const DESCRIPTION: &'static str = "Start a Hyper-V virtual machine on a Windows host. Shows VM state after starting. \
        Requires appropriate permissions on the Hyper-V host.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "name"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target Windows host alias (must match a configured host)"
            },
            "name": {
                "type": "string",
                "description": "Name of the Hyper-V virtual machine to start"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshHypervVmStartArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(HyperVCommandBuilder::vm_start(&args.name))
    }

    fn validate(args: &SshHypervVmStartArgs, _host_config: &HostConfig) -> Result<()> {
        validate_vm_name(&args.name)?;
        Ok(())
    }
}

/// Handler for the `ssh_hyperv_vm_start` tool.
pub type SshHypervVmStartHandler = StandardToolHandler<HypervVmStartTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHypervVmStartHandler::new();
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
        let handler = SshHypervVmStartHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "name": "MyVM"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshHypervVmStartHandler::new();
        assert_eq!(handler.name(), "ssh_hyperv_vm_start");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "winhost",
            "name": "MyVM",
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshHypervVmStartArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "winhost");
        assert_eq!(args.name, "MyVM");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "winhost", "name": "MyVM"});
        let args: SshHypervVmStartArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "winhost");
        assert_eq!(args.name, "MyVM");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHypervVmStartHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "winhost"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "name": "vm"});
        let args: SshHypervVmStartArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshHypervVmStartArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "name": "MyVM"});
        let result = serde_json::from_value::<SshHypervVmStartArgs>(json);
        assert!(result.is_err());
    }
}
