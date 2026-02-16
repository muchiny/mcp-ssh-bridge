use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::vault::VaultCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshVaultStatusArgs {
    host: String,
    vault_addr: Option<String>,
    #[serde(rename = "format")]
    output_format: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshVaultStatusArgs);

pub struct VaultStatusTool;

impl StandardTool for VaultStatusTool {
    type Args = SshVaultStatusArgs;

    const NAME: &'static str = "ssh_vault_status";

    const DESCRIPTION: &'static str = "Check HashiCorp Vault server status on a remote host. Returns seal status, cluster \
        info, and server version. Use this first to verify Vault is unsealed and healthy \
        before reading or writing secrets.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "SSH host to connect through"
                    },
                    "vault_addr": {
                        "type": "string",
                        "description": "Vault server address (default: from VAULT_ADDR env)"
                    },
                    "format": {
                        "type": "string",
                        "description": "Output format: table, json, yaml"
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
                "required": ["host"]
            }"#;

    fn build_command(args: &SshVaultStatusArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(VaultCommandBuilder::build_status_command(
            args.vault_addr.as_deref(),
            args.output_format.as_deref(),
        ))
    }
}

/// Handler for the `ssh_vault_status` tool.
pub type SshVaultStatusHandler = StandardToolHandler<VaultStatusTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshVaultStatusHandler::new();
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
        let handler = SshVaultStatusHandler::new();
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
        let handler = SshVaultStatusHandler::new();
        assert_eq!(handler.name(), "ssh_vault_status");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_vault_status");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "vault_addr": "https://vault.example.com:8200",
            "format": "json",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/vault_status.txt"
        });
        let args: SshVaultStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(
            args.vault_addr.as_deref(),
            Some("https://vault.example.com:8200")
        );
        assert_eq!(args.output_format.as_deref(), Some("json"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/vault_status.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshVaultStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.vault_addr.is_none());
        assert!(args.output_format.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshVaultStatusHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("vault_addr"));
        assert!(properties.contains_key("format"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost"});
        let args: SshVaultStatusArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshVaultStatusArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshVaultStatusHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
