use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::terraform::TerraformCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshTerraformInitArgs {
    host: String,
    dir: String,
    backend: Option<bool>,
    upgrade: Option<bool>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshTerraformInitArgs);

pub struct TerraformInitTool;

impl StandardTool for TerraformInitTool {
    type Args = SshTerraformInitArgs;

    const NAME: &'static str = "ssh_terraform_init";

    const DESCRIPTION: &'static str = "Initialize a Terraform working directory on a remote host. Downloads providers and \
        modules. Required before ssh_terraform_plan or ssh_terraform_apply. Idempotent and \
        safe to run multiple times.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "SSH host to connect through"
                    },
                    "dir": {
                        "type": "string",
                        "description": "Path to Terraform directory"
                    },
                    "backend": {
                        "type": "boolean",
                        "description": "Enable backend (default: true)"
                    },
                    "upgrade": {
                        "type": "boolean",
                        "description": "Upgrade providers and modules"
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
                "required": ["host", "dir"]
            }"#;

    fn build_command(args: &SshTerraformInitArgs, _host_config: &HostConfig) -> Result<String> {
        TerraformCommandBuilder::build_init_command(
            &args.dir,
            args.backend.unwrap_or(true),
            args.upgrade.unwrap_or(false),
        )
    }
}

/// Handler for the `ssh_terraform_init` tool.
pub type SshTerraformInitHandler = StandardToolHandler<TerraformInitTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTerraformInitHandler::new();
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
        let handler = SshTerraformInitHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "dir": "/opt/terraform"})),
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
        let handler = SshTerraformInitHandler::new();
        assert_eq!(handler.name(), "ssh_terraform_init");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_terraform_init");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("dir")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "dir": "/opt/terraform",
            "backend": false,
            "upgrade": true,
            "timeout_seconds": 120,
            "max_output": 10000,
            "save_output": "/tmp/tf_init.txt"
        });
        let args: SshTerraformInitArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.dir, "/opt/terraform");
        assert_eq!(args.backend, Some(false));
        assert_eq!(args.upgrade, Some(true));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/tf_init.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "dir": "/opt/terraform"});
        let args: SshTerraformInitArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.dir, "/opt/terraform");
        assert!(args.backend.is_none());
        assert!(args.upgrade.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTerraformInitHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("backend"));
        assert!(properties.contains_key("upgrade"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "dir": "/opt/terraform"});
        let args: SshTerraformInitArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshTerraformInitArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshTerraformInitHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "dir": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
