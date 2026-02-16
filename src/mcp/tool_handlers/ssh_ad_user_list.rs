//! Handler for the `ssh_ad_user_list` tool.
//!
//! List Active Directory users with display name, enabled status, and last logon date.
//! Optionally filter by name pattern. Requires the AD `PowerShell` module.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::active_directory::ActiveDirectoryCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshAdUserListArgs {
    host: String,
    filter: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshAdUserListArgs);

pub struct AdUserListTool;

impl StandardTool for AdUserListTool {
    type Args = SshAdUserListArgs;

    const NAME: &'static str = "ssh_ad_user_list";

    const DESCRIPTION: &'static str = "List Active Directory users with display name, enabled status, and last logon date. \
        Optionally filter by name pattern. Requires the AD PowerShell module.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured Windows host)"
            },
            "filter": {
                "type": "string",
                "description": "Filter users by name pattern (case-insensitive substring match)"
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

    fn build_command(args: &SshAdUserListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(ActiveDirectoryCommandBuilder::build_user_list_command(
            args.filter.as_deref(),
        ))
    }
}

/// Handler for the `ssh_ad_user_list` tool.
pub type SshAdUserListHandler = StandardToolHandler<AdUserListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAdUserListHandler::new();
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
        let handler = SshAdUserListHandler::new();
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
        let handler = SshAdUserListHandler::new();
        assert_eq!(handler.name(), "ssh_ad_user_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ad_user_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "windc01",
            "filter": "john",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/users.txt"
        });
        let args: SshAdUserListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "windc01");
        assert_eq!(args.filter, Some("john".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/users.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "windc01"});
        let args: SshAdUserListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "windc01");
        assert!(args.filter.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAdUserListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("filter"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "windc01"});
        let args: SshAdUserListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAdUserListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAdUserListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
