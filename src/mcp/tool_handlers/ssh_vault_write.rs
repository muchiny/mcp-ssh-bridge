use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::vault::VaultCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshVaultWriteArgs {
    host: String,
    path: String,
    data: Vec<String>,
    vault_addr: Option<String>,
    mount: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshVaultWriteArgs);

pub struct VaultWriteTool;

impl StandardTool for VaultWriteTool {
    type Args = SshVaultWriteArgs;

    const NAME: &'static str = "ssh_vault_write";

    const DESCRIPTION: &'static str = "Write a secret to HashiCorp Vault on a remote host. Creates or updates secret data at \
        the given path. Use ssh_vault_list to browse existing paths and ssh_vault_read to \
        verify after writing.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "SSH host to connect through"
                    },
                    "path": {
                        "type": "string",
                        "description": "Secret path in Vault"
                    },
                    "data": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Key-value pairs as 'key=value' strings"
                    },
                    "vault_addr": {
                        "type": "string",
                        "description": "Vault server address (default: from VAULT_ADDR env)"
                    },
                    "mount": {
                        "type": "string",
                        "description": "Secrets engine mount path"
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Command timeout in seconds"
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters"
                    },
                    "save_output": {
                        "type": "string",
                        "description": "File path to save full output"
                    }
                },
                "required": ["host", "path", "data"]
            }"#;

    fn build_command(args: &SshVaultWriteArgs, _host_config: &HostConfig) -> Result<String> {
        VaultCommandBuilder::build_write_command(
            &args.path,
            &args.data,
            args.vault_addr.as_deref(),
            args.mount.as_deref(),
        )
    }
}

/// Handler for the `ssh_vault_write` tool.
pub type SshVaultWriteHandler = StandardToolHandler<VaultWriteTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshVaultWriteHandler::new();
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
        let handler = SshVaultWriteHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "secret/data/myapp", "data": ["key=value"]})),
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
        let handler = SshVaultWriteHandler::new();
        assert_eq!(handler.name(), "ssh_vault_write");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_vault_write");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
        assert!(required.contains(&json!("data")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "path": "secret/data/myapp",
            "data": ["username=admin", "password=secret123"],
            "vault_addr": "https://vault.example.com:8200",
            "mount": "secret",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/vault_write.txt"
        });
        let args: SshVaultWriteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.path, "secret/data/myapp");
        assert_eq!(args.data, vec!["username=admin", "password=secret123"]);
        assert_eq!(
            args.vault_addr.as_deref(),
            Some("https://vault.example.com:8200")
        );
        assert_eq!(args.mount.as_deref(), Some("secret"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/vault_write.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "path": "secret/data/myapp", "data": ["key=value"]});
        let args: SshVaultWriteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.path, "secret/data/myapp");
        assert_eq!(args.data, vec!["key=value"]);
        assert!(args.vault_addr.is_none());
        assert!(args.mount.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshVaultWriteHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("vault_addr"));
        assert!(properties.contains_key("mount"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "path": "secret/data/myapp", "data": ["key=value"]});
        let args: SshVaultWriteArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshVaultWriteArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshVaultWriteHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "path": 456, "data": "not_an_array"})),
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
