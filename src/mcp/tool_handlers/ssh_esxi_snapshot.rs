//! SSH `ESXi` Snapshot Tool Handler
//!
//! Manages VM snapshots on an `ESXi` host via `vim-cmd vmsvc/snapshot.*`.
//! Supports list, create, revert, and `remove_all` actions.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::esxi::EsxiCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshEsxiSnapshotArgs {
    host: String,
    vm_id: String,
    action: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    include_memory: Option<bool>,
    #[serde(default)]
    quiesce: Option<bool>,
    #[serde(default)]
    snapshot_id: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshEsxiSnapshotArgs);

pub struct EsxiSnapshotTool;

impl StandardTool for EsxiSnapshotTool {
    type Args = SshEsxiSnapshotArgs;

    const NAME: &'static str = "ssh_esxi_snapshot";

    const DESCRIPTION: &'static str = "Manage VM snapshots on a VMware ESXi host. Actions: list (show snapshot tree), create \
        (new snapshot with optional memory/quiesce), revert (restore to snapshot_id), \
        remove_all (delete all snapshots). Use ssh_esxi_vm_list first to find VM IDs.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration (must be an ESXi host)"
            },
            "vm_id": {
                "type": "string",
                "description": "VM ID from vim-cmd vmsvc/getallvms (use ssh_esxi_vm_list to find IDs)"
            },
            "action": {
                "type": "string",
                "description": "Snapshot action to perform",
                "enum": ["list", "create", "revert", "remove_all"]
            },
            "name": {
                "type": "string",
                "description": "Snapshot name (required for create, default: 'snapshot')"
            },
            "description": {
                "type": "string",
                "description": "Snapshot description (optional, for create)"
            },
            "include_memory": {
                "type": "boolean",
                "description": "Include VM memory in snapshot (for create, default: false)"
            },
            "quiesce": {
                "type": "boolean",
                "description": "Quiesce guest filesystem via VMware Tools (for create, default: false)"
            },
            "snapshot_id": {
                "type": "string",
                "description": "Snapshot ID to revert to (required for revert)"
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
        "required": ["host", "vm_id", "action"]
    }"#;

    fn validate(args: &SshEsxiSnapshotArgs, _host_config: &HostConfig) -> Result<()> {
        EsxiCommandBuilder::validate_snapshot_action(&args.action)
    }

    fn build_command(args: &SshEsxiSnapshotArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(EsxiCommandBuilder::build_snapshot_command(
            &args.vm_id,
            &args.action,
            args.name.as_deref(),
            args.description.as_deref(),
            args.include_memory.unwrap_or(false),
            args.quiesce.unwrap_or(false),
            args.snapshot_id.as_deref(),
        ))
    }
}

/// Handler for the `ssh_esxi_snapshot` tool.
pub type SshEsxiSnapshotHandler = StandardToolHandler<EsxiSnapshotTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshEsxiSnapshotHandler::new();
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
        let handler = SshEsxiSnapshotHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "vm_id": "1", "action": "list"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_action() {
        let handler = SshEsxiSnapshotHandler::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "vm_id": "1", "action": "delete"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("delete"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshEsxiSnapshotHandler::new();
        assert_eq!(handler.name(), "ssh_esxi_snapshot");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("vm_id")));
        assert!(required.contains(&json!("action")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "esxi1",
            "vm_id": "42",
            "action": "create",
            "name": "before-upgrade",
            "description": "Pre-upgrade snapshot",
            "include_memory": true,
            "quiesce": false
        });
        let args: SshEsxiSnapshotArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert_eq!(args.vm_id, "42");
        assert_eq!(args.action, "create");
        assert_eq!(args.name, Some("before-upgrade".to_string()));
        assert_eq!(args.include_memory, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "esxi1", "vm_id": "1", "action": "list"});
        let args: SshEsxiSnapshotArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "esxi1");
        assert_eq!(args.action, "list");
        assert!(args.name.is_none());
        assert!(args.snapshot_id.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshEsxiSnapshotHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "esxi1", "vm_id": "1"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshEsxiSnapshotHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("name"));
        assert!(properties.contains_key("description"));
        assert!(properties.contains_key("include_memory"));
        assert!(properties.contains_key("quiesce"));
        assert!(properties.contains_key("snapshot_id"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "esxi1", "vm_id": "1", "action": "list"});
        let args: SshEsxiSnapshotArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshEsxiSnapshotArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshEsxiSnapshotHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "vm_id": "1", "action": "list"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
