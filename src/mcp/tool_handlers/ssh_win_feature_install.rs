//! Handler for the `ssh_win_feature_install` tool.
//!
//! Installs a Windows feature on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_feature::{
    WindowsFeatureCommandBuilder, validate_feature_name,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshWinFeatureInstallArgs {
    host: String,
    name: String,
    #[serde(default)]
    include_management: bool,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinFeatureInstallArgs);

pub struct WinFeatureInstallTool;

impl StandardTool for WinFeatureInstallTool {
    type Args = SshWinFeatureInstallArgs;

    const NAME: &'static str = "ssh_win_feature_install";

    const DESCRIPTION: &'static str = "Install a Windows feature. Optionally include management tools. Validates the feature \
        name and shows install state after completion. Requires appropriate permissions.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "name"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "name": {
                "type": "string",
                "description": "Name of the Windows feature to install (e.g., Web-Server, Telnet-Client)"
            },
            "include_management": {
                "type": "boolean",
                "description": "Include management tools when installing the feature (default: false)"
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

    fn build_command(args: &SshWinFeatureInstallArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsFeatureCommandBuilder::install(
            &args.name,
            args.include_management,
        ))
    }

    fn validate(args: &SshWinFeatureInstallArgs, _host_config: &HostConfig) -> Result<()> {
        validate_feature_name(&args.name)?;
        Ok(())
    }
}

/// Handler for the `ssh_win_feature_install` tool.
pub type SshWinFeatureInstallHandler = StandardToolHandler<WinFeatureInstallTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinFeatureInstallHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinFeatureInstallHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "name": "Web-Server"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinFeatureInstallHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_feature_install");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "name": "Web-Server",
            "include_management": true,
            "timeout_seconds": 60,
            "max_output": 5000
        });
        let args: SshWinFeatureInstallArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "Web-Server");
        assert!(args.include_management);
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "name": "Web-Server"});
        let args: SshWinFeatureInstallArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "Web-Server");
        assert!(!args.include_management);
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinFeatureInstallHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("include_management"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "name": "f"});
        let args: SshWinFeatureInstallArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinFeatureInstallArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "name": "Web-Server"});
        let result = serde_json::from_value::<SshWinFeatureInstallArgs>(json);
        assert!(result.is_err());
    }
}
