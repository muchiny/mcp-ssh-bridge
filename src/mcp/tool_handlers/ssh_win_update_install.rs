//! Handler for the `ssh_win_update_install` tool.
//!
//! Installs a specific Windows update by KB article ID.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_update::{WindowsUpdateCommandBuilder, validate_kb_id};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshWinUpdateInstallArgs {
    host: String,
    kb: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinUpdateInstallArgs);

pub struct WinUpdateInstallTool;

impl StandardTool for WinUpdateInstallTool {
    type Args = SshWinUpdateInstallArgs;

    const NAME: &'static str = "ssh_win_update_install";

    const DESCRIPTION: &'static str = "Install a specific Windows update by KB article ID on a Windows host. Does not \
        auto-reboot. Use ssh_win_update_search or ssh_win_update_list to find available KB \
        IDs first. Check ssh_win_update_reboot afterward to see if a reboot is required.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "kb"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "kb": {
                "type": "string",
                "description": "KB article ID to install (e.g., KB5034441)"
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

    fn build_command(args: &SshWinUpdateInstallArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsUpdateCommandBuilder::build_install_command(&args.kb))
    }

    fn validate(args: &SshWinUpdateInstallArgs, _host_config: &HostConfig) -> Result<()> {
        validate_kb_id(&args.kb)?;
        Ok(())
    }
}

/// Handler for the `ssh_win_update_install` tool.
pub type SshWinUpdateInstallHandler = StandardToolHandler<WinUpdateInstallTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinUpdateInstallHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinUpdateInstallHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "kb": "KB5034441"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinUpdateInstallHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_update_install");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("kb")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "kb": "KB5034441",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshWinUpdateInstallArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.kb, "KB5034441");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "kb": "KB5034441"});
        let args: SshWinUpdateInstallArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.kb, "KB5034441");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinUpdateInstallHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "kb": "KB123"});
        let args: SshWinUpdateInstallArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinUpdateInstallArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "kb": "KB5034441"});
        let result = serde_json::from_value::<SshWinUpdateInstallArgs>(json);
        assert!(result.is_err());
    }
}
