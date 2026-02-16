//! Handler for the `ssh_reg_set` tool.
//!
//! Sets a Windows Registry property value via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_registry::{
    WindowsRegistryCommandBuilder, validate_registry_name, validate_registry_path,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshRegSetArgs {
    host: String,
    path: String,
    name: String,
    value: String,
    #[serde(default)]
    value_type: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshRegSetArgs);

pub struct RegSetTool;

impl StandardTool for RegSetTool {
    type Args = SshRegSetArgs;

    const NAME: &'static str = "ssh_reg_set";

    const DESCRIPTION: &'static str = "Set a Windows Registry property value. Creates the property if it does not exist. Use \
        `ssh_reg_query` to verify the value after setting.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "path", "name", "value"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "path": {
                "type": "string",
                "description": "Registry path (e.g., HKLM:\\SOFTWARE\\MyApp)"
            },
            "name": {
                "type": "string",
                "description": "Property name to set"
            },
            "value": {
                "type": "string",
                "description": "Value to set"
            },
            "value_type": {
                "type": "string",
                "description": "Registry value type (String, DWord, QWord, Binary, MultiString, ExpandString)"
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

    fn build_command(args: &SshRegSetArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsRegistryCommandBuilder::set_value(
            &args.path,
            &args.name,
            &args.value,
            args.value_type.as_deref(),
        ))
    }

    fn validate(args: &SshRegSetArgs, _host_config: &HostConfig) -> Result<()> {
        validate_registry_path(&args.path)?;
        validate_registry_name(&args.name)?;
        Ok(())
    }
}

/// Handler for the `ssh_reg_set` tool.
pub type SshRegSetHandler = StandardToolHandler<RegSetTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRegSetHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshRegSetHandler::new();
        let ctx = create_test_context();
        let args = json!({
            "host": "nonexistent",
            "path": "HKLM:\\SOFTWARE\\MyApp",
            "name": "Version",
            "value": "1.0"
        });
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshRegSetHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_reg_set");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("path")));
        assert!(required.iter().any(|v| v.as_str() == Some("name")));
        assert!(required.iter().any(|v| v.as_str() == Some("value")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "path": "HKLM:\\SOFTWARE\\MyApp",
            "name": "Version",
            "value": "2.0",
            "value_type": "String",
            "timeout_seconds": 30,
            "max_output": 5000
        });
        let args: SshRegSetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.path, "HKLM:\\SOFTWARE\\MyApp");
        assert_eq!(args.name, "Version");
        assert_eq!(args.value, "2.0");
        assert_eq!(args.value_type, Some("String".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "myhost",
            "path": "HKLM:\\SOFTWARE\\MyApp",
            "name": "Version",
            "value": "1.0"
        });
        let args: SshRegSetArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.path, "HKLM:\\SOFTWARE\\MyApp");
        assert_eq!(args.name, "Version");
        assert_eq!(args.value, "1.0");
        assert!(args.value_type.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshRegSetHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("value_type"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "h",
            "path": "HKLM:\\SOFTWARE",
            "name": "n",
            "value": "v"
        });
        let args: SshRegSetArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshRegSetArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({
            "host": 123,
            "path": "HKLM:\\SOFTWARE",
            "name": "n",
            "value": "v"
        });
        let result = serde_json::from_value::<SshRegSetArgs>(json);
        assert!(result.is_err());
    }
}
