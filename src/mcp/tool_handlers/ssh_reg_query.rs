//! Handler for the `ssh_reg_query` tool.
//!
//! Queries Windows Registry values via `PowerShell`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_registry::{
    WindowsRegistryCommandBuilder, validate_registry_name, validate_registry_path,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshRegQueryArgs {
    host: String,
    path: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshRegQueryArgs);

pub struct RegQueryTool;

impl StandardTool for RegQueryTool {
    type Args = SshRegQueryArgs;

    const NAME: &'static str = "ssh_reg_query";

    const DESCRIPTION: &'static str = "Query Windows Registry values at a given path. Optionally query a specific property \
        by name. Use `ssh_reg_list` to discover subkeys first.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "path"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "path": {
                "type": "string",
                "description": "Registry path (e.g., HKLM:\\SOFTWARE\\Microsoft)"
            },
            "name": {
                "type": "string",
                "description": "Optional property name to query"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the local machine"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshRegQueryArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsRegistryCommandBuilder::query(
            &args.path,
            args.name.as_deref(),
        ))
    }

    fn validate(args: &SshRegQueryArgs, _host_config: &HostConfig) -> Result<()> {
        validate_registry_path(&args.path)?;
        if let Some(ref name) = args.name {
            validate_registry_name(name)?;
        }
        Ok(())
    }
}

/// Handler for the `ssh_reg_query` tool.
pub type SshRegQueryHandler = StandardToolHandler<RegQueryTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRegQueryHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshRegQueryHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "path": "HKLM:\\SOFTWARE"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshRegQueryHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_reg_query");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "path": "HKLM:\\SOFTWARE\\Microsoft",
            "name": "DisplayName",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshRegQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.path, "HKLM:\\SOFTWARE\\Microsoft");
        assert_eq!(args.name, Some("DisplayName".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "path": "HKLM:\\SOFTWARE"});
        let args: SshRegQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.path, "HKLM:\\SOFTWARE");
        assert!(args.name.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshRegQueryHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("name"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "path": "HKLM:\\SOFTWARE"});
        let args: SshRegQueryArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshRegQueryArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "path": "HKLM:\\SOFTWARE"});
        let result = serde_json::from_value::<SshRegQueryArgs>(json);
        assert!(result.is_err());
    }
}
