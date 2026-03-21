//! Handler for the `ssh_storage_mount` tool.
//!
//! Mounts a filesystem on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::storage::StorageCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshStorageMountArgs {
    /// Target host name from configuration.
    host: String,
    /// Device to mount (e.g., /dev/sdb1).
    device: String,
    /// Mount point path (e.g., /mnt/data).
    mount_point: String,
    /// Filesystem type (e.g., ext4, xfs, nfs).
    #[serde(default)]
    fs_type: Option<String>,
    /// Mount options (e.g., ro,noexec).
    #[serde(default)]
    options: Option<String>,
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

impl_common_args!(SshStorageMountArgs);

pub struct StorageMountTool;

impl StandardTool for StorageMountTool {
    type Args = SshStorageMountArgs;

    const NAME: &'static str = "ssh_storage_mount";

    const DESCRIPTION: &'static str = "Mount a filesystem on a remote host. Specify device, \
        mount point, and optionally filesystem type and mount options.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "device": {
                        "type": "string",
                        "description": "Device to mount (e.g., /dev/sdb1, //server/share)"
                    },
                    "mount_point": {
                        "type": "string",
                        "description": "Mount point path (e.g., /mnt/data)"
                    },
                    "fs_type": {
                        "type": "string",
                        "description": "Filesystem type (e.g., ext4, xfs, nfs, cifs)"
                    },
                    "options": {
                        "type": "string",
                        "description": "Mount options (e.g., ro,noexec,nosuid)"
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
                "required": ["host", "device", "mount_point"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshStorageMountArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(StorageCommandBuilder::build_mount_command(
            &args.device,
            &args.mount_point,
            args.fs_type.as_deref(),
            args.options.as_deref(),
        ))
    }
}

/// Handler for the `ssh_storage_mount` tool.
pub type SshStorageMountHandler = StandardToolHandler<StorageMountTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshStorageMountHandler::new();
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
        let handler = SshStorageMountHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "device": "/dev/sdb1", "mount_point": "/mnt/data"})),
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
        let handler = SshStorageMountHandler::new();
        assert_eq!(handler.name(), "ssh_storage_mount");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_storage_mount");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("device")));
        assert!(required.contains(&json!("mount_point")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "device": "/dev/sdb1",
            "mount_point": "/mnt/data",
            "fs_type": "ext4",
            "options": "ro,noexec",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/mount.txt"
        });
        let args: SshStorageMountArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.device, "/dev/sdb1");
        assert_eq!(args.mount_point, "/mnt/data");
        assert_eq!(args.fs_type.as_deref(), Some("ext4"));
        assert_eq!(args.options.as_deref(), Some("ro,noexec"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/mount.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "device": "/dev/sdb1", "mount_point": "/mnt/data"});
        let args: SshStorageMountArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.device, "/dev/sdb1");
        assert_eq!(args.mount_point, "/mnt/data");
        assert!(args.fs_type.is_none());
        assert!(args.options.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshStorageMountHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "server1", "device": "/dev/sdb1"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshStorageMountHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("fs_type"));
        assert!(props.contains_key("options"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "device": "/dev/sdb1", "mount_point": "/mnt/data"});
        let args: SshStorageMountArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshStorageMountArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshStorageMountHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "device": "/dev/sdb1", "mount_point": "/mnt/data"})),
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
