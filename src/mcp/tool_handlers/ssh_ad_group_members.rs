//! Handler for the `ssh_ad_group_members` tool.
//!
//! List members of an Active Directory group with name, SAM account name, and object class.
//! Requires the AD `PowerShell` module.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::active_directory::{
    ActiveDirectoryCommandBuilder, validate_ad_identity,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshAdGroupMembersArgs {
    host: String,
    group: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshAdGroupMembersArgs);

pub struct AdGroupMembersTool;

impl StandardTool for AdGroupMembersTool {
    type Args = SshAdGroupMembersArgs;

    const NAME: &'static str = "ssh_ad_group_members";

    const DESCRIPTION: &'static str = "List members of an Active Directory group with name, SAM account name, and object \
        class. Requires the AD PowerShell module.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "group"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured Windows host)"
            },
            "group": {
                "type": "string",
                "description": "Name of the AD group (e.g., Domain Admins, IT-Staff)"
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

    fn build_command(args: &SshAdGroupMembersArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(ActiveDirectoryCommandBuilder::build_group_members_command(
            &args.group,
        ))
    }

    fn validate(args: &SshAdGroupMembersArgs, _host_config: &HostConfig) -> Result<()> {
        validate_ad_identity(&args.group)?;
        Ok(())
    }
}

/// Handler for the `ssh_ad_group_members` tool.
pub type SshAdGroupMembersHandler = StandardToolHandler<AdGroupMembersTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAdGroupMembersHandler::new();
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
        let handler = SshAdGroupMembersHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "group": "Domain Admins"})),
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
        let handler = SshAdGroupMembersHandler::new();
        assert_eq!(handler.name(), "ssh_ad_group_members");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ad_group_members");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("group")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "windc01",
            "group": "Domain Admins",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/members.txt"
        });
        let args: SshAdGroupMembersArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "windc01");
        assert_eq!(args.group, "Domain Admins");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/members.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "windc01", "group": "Domain Admins"});
        let args: SshAdGroupMembersArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "windc01");
        assert_eq!(args.group, "Domain Admins");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAdGroupMembersHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "windc01", "group": "IT-Staff"});
        let args: SshAdGroupMembersArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAdGroupMembersArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAdGroupMembersHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "group": "Admins"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
