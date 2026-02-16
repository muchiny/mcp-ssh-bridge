//! Handler for the `ssh_reg_delete` tool.
//!
//! Deletes a Windows Registry property via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_registry::{
    WindowsRegistryCommandBuilder, validate_registry_name, validate_registry_path,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshRegDeleteArgs {
    host: String,
    path: String,
    name: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshRegDeleteArgs);

pub struct RegDeleteTool;

impl StandardTool for RegDeleteTool {
    type Args = SshRegDeleteArgs;

    const NAME: &'static str = "ssh_reg_delete";

    const DESCRIPTION: &'static str = "Delete a Windows Registry property. This is destructive and cannot be undone. Use \
        `ssh_reg_export` to back up the key before deleting.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "path", "name"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "path": {
                "type": "string",
                "description": "Registry path containing the property (e.g., HKLM:\\SOFTWARE\\MyApp)"
            },
            "name": {
                "type": "string",
                "description": "Property name to delete"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshRegDeleteArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsRegistryCommandBuilder::delete_property(
            &args.path, &args.name,
        ))
    }

    fn validate(args: &SshRegDeleteArgs, _host_config: &HostConfig) -> Result<()> {
        validate_registry_path(&args.path)?;
        validate_registry_name(&args.name)?;
        Ok(())
    }
}

/// Handler for the `ssh_reg_delete` tool.
pub type SshRegDeleteHandler = StandardToolHandler<RegDeleteTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRegDeleteHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshRegDeleteHandler::new();
        let ctx = create_test_context();
        let args = json!({
            "host": "nonexistent",
            "path": "HKLM:\\SOFTWARE\\MyApp",
            "name": "OldValue"
        });
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshRegDeleteHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_reg_delete");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("path")));
        assert!(required.iter().any(|v| v.as_str() == Some("name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "path": "HKLM:\\SOFTWARE\\MyApp",
            "name": "OldValue",
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshRegDeleteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.path, "HKLM:\\SOFTWARE\\MyApp");
        assert_eq!(args.name, "OldValue");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "myhost",
            "path": "HKLM:\\SOFTWARE\\MyApp",
            "name": "OldValue"
        });
        let args: SshRegDeleteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.path, "HKLM:\\SOFTWARE\\MyApp");
        assert_eq!(args.name, "OldValue");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshRegDeleteHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "h",
            "path": "HKLM:\\SOFTWARE",
            "name": "n"
        });
        let args: SshRegDeleteArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshRegDeleteArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({
            "host": 123,
            "path": "HKLM:\\SOFTWARE",
            "name": "n"
        });
        let result = serde_json::from_value::<SshRegDeleteArgs>(json);
        assert!(result.is_err());
    }
}
