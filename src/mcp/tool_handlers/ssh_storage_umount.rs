//! Handler for the `ssh_storage_umount` tool.
//!
//! Unmounts a filesystem on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::storage::StorageCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshStorageUmountArgs {
    /// Target host name from configuration.
    host: String,
    /// Path or device to unmount.
    path: String,
    /// Use lazy unmount when the filesystem is busy.
    #[serde(default)]
    lazy: Option<bool>,
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

impl_common_args!(SshStorageUmountArgs);

pub struct StorageUmountTool;

impl StandardTool for StorageUmountTool {
    type Args = SshStorageUmountArgs;

    const NAME: &'static str = "ssh_storage_umount";

    const DESCRIPTION: &'static str = "Unmount a filesystem on a remote host. Use lazy=true for \
        lazy unmount when the filesystem is busy.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "path": {
                        "type": "string",
                        "description": "Mount point or device to unmount (e.g., /mnt/data)"
                    },
                    "lazy": {
                        "type": "boolean",
                        "description": "Use lazy unmount (-l) when the filesystem is busy"
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
                "required": ["host", "path"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshStorageUmountArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(StorageCommandBuilder::build_umount_command(
            &args.path,
            args.lazy.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_storage_umount` tool.
pub type SshStorageUmountHandler = StandardToolHandler<StorageUmountTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshStorageUmountHandler::new();
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
        let handler = SshStorageUmountHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "/mnt/data"})),
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
        let handler = SshStorageUmountHandler::new();
        assert_eq!(handler.name(), "ssh_storage_umount");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_storage_umount");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/mnt/data",
            "lazy": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/umount.txt"
        });
        let args: SshStorageUmountArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/mnt/data");
        assert_eq!(args.lazy, Some(true));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/umount.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/mnt/data"});
        let args: SshStorageUmountArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/mnt/data");
        assert!(args.lazy.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshStorageUmountHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshStorageUmountHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("lazy"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/mnt/data"});
        let args: SshStorageUmountArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshStorageUmountArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshStorageUmountHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "path": "/mnt/data"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
