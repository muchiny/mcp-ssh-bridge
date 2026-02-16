//! Handler for the `ssh_hyperv_snapshot_list` tool.
//!
//! Lists Hyper-V VM snapshots (checkpoints) via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::hyperv::{HyperVCommandBuilder, validate_vm_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshHypervSnapshotListArgs {
    host: String,
    vm_name: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshHypervSnapshotListArgs);

pub struct HypervSnapshotListTool;

impl StandardTool for HypervSnapshotListTool {
    type Args = SshHypervSnapshotListArgs;

    const NAME: &'static str = "ssh_hyperv_snapshot_list";

    const DESCRIPTION: &'static str = "List snapshots (checkpoints) of a Hyper-V virtual machine. Returns name, creation \
        time, snapshot type, and parent snapshot for each checkpoint. Use \
        `ssh_hyperv_vm_list` first to find VM names.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "vm_name"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target Windows host alias (must match a configured host)"
            },
            "vm_name": {
                "type": "string",
                "description": "Name of the Hyper-V virtual machine"
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
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(
        args: &SshHypervSnapshotListArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        Ok(HyperVCommandBuilder::snapshot_list(&args.vm_name))
    }

    fn validate(args: &SshHypervSnapshotListArgs, _host_config: &HostConfig) -> Result<()> {
        validate_vm_name(&args.vm_name)?;
        Ok(())
    }
}

/// Handler for the `ssh_hyperv_snapshot_list` tool.
pub type SshHypervSnapshotListHandler = StandardToolHandler<HypervSnapshotListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHypervSnapshotListHandler::new();
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
        let handler = SshHypervSnapshotListHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "vm_name": "MyVM"})),
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
        let handler = SshHypervSnapshotListHandler::new();
        assert_eq!(handler.name(), "ssh_hyperv_snapshot_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("vm_name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "winhost",
            "vm_name": "MyVM",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshHypervSnapshotListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "winhost");
        assert_eq!(args.vm_name, "MyVM");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "winhost", "vm_name": "MyVM"});
        let args: SshHypervSnapshotListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "winhost");
        assert_eq!(args.vm_name, "MyVM");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHypervSnapshotListHandler::new();
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
    fn test_schema_optional_fields() {
        let handler = SshHypervSnapshotListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "vm_name": "vm"});
        let args: SshHypervSnapshotListArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshHypervSnapshotListArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "vm_name": "MyVM"});
        let result = serde_json::from_value::<SshHypervSnapshotListArgs>(json);
        assert!(result.is_err());
    }
}
