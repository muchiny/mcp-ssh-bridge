//! Handler for the `ssh_win_feature_info` tool.
//!
//! Shows detailed information about a specific Windows feature.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_feature::{
    WindowsFeatureCommandBuilder, validate_feature_name,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshWinFeatureInfoArgs {
    host: String,
    name: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinFeatureInfoArgs);

pub struct WinFeatureInfoTool;

impl StandardTool for WinFeatureInfoTool {
    type Args = SshWinFeatureInfoArgs;

    const NAME: &'static str = "ssh_win_feature_info";

    const DESCRIPTION: &'static str = "Get details about a Windows feature including name, display name, install state, \
        description, dependencies, and parent. Use `ssh_win_feature_list` first to discover \
        feature names.";

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
                "description": "Name of the Windows feature (e.g., Web-Server, Telnet-Client)"
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

    fn build_command(args: &SshWinFeatureInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsFeatureCommandBuilder::info(&args.name))
    }

    fn validate(args: &SshWinFeatureInfoArgs, _host_config: &HostConfig) -> Result<()> {
        validate_feature_name(&args.name)?;
        Ok(())
    }
}

/// Handler for the `ssh_win_feature_info` tool.
pub type SshWinFeatureInfoHandler = StandardToolHandler<WinFeatureInfoTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinFeatureInfoHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinFeatureInfoHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "name": "Web-Server"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinFeatureInfoHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_feature_info");
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
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshWinFeatureInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "Web-Server");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "name": "Web-Server"});
        let args: SshWinFeatureInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "Web-Server");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinFeatureInfoHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "name": "f"});
        let args: SshWinFeatureInfoArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinFeatureInfoArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "name": "Web-Server"});
        let result = serde_json::from_value::<SshWinFeatureInfoArgs>(json);
        assert!(result.is_err());
    }
}
