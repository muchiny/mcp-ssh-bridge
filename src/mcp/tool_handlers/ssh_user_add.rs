//! Handler for the `ssh_user_add` tool.
//!
//! Creates a new user on a remote Linux host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::user_management::UserCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshUserAddArgs {
    /// Target host name from configuration.
    host: String,
    /// Username to create.
    username: String,
    /// Home directory path.
    #[serde(default)]
    home_dir: Option<String>,
    /// Login shell.
    #[serde(default)]
    shell: Option<String>,
    /// Supplementary groups (comma-separated).
    #[serde(default)]
    groups: Option<String>,
    /// Create as a system account.
    #[serde(default)]
    system: Option<bool>,
    /// Create the user's home directory.
    #[serde(default)]
    create_home: Option<bool>,
    /// Override default command timeout in seconds.
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    #[serde(default)]
    max_output: Option<u64>,
    /// Save full output to a local file path.
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshUserAddArgs);

pub struct UserAddTool;

impl StandardTool for UserAddTool {
    type Args = SshUserAddArgs;

    const NAME: &'static str = "ssh_user_add";

    const DESCRIPTION: &'static str = "Create a new user on a remote Linux host. Optionally \
        specify home directory, shell, groups, and whether to create home directory.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "username"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "username": {
                "type": "string",
                "description": "Username to create"
            },
            "home_dir": {
                "type": "string",
                "description": "Home directory path for the new user"
            },
            "shell": {
                "type": "string",
                "description": "Login shell (e.g., /bin/bash, /usr/sbin/nologin)"
            },
            "groups": {
                "type": "string",
                "description": "Supplementary groups (comma-separated, e.g., docker,sudo)"
            },
            "system": {
                "type": "boolean",
                "description": "Create as a system account. Default: false"
            },
            "create_home": {
                "type": "boolean",
                "description": "Create the user's home directory. Default: true"
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

    fn build_command(args: &SshUserAddArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(UserCommandBuilder::build_user_add_command(
            &args.username,
            args.home_dir.as_deref(),
            args.shell.as_deref(),
            args.groups.as_deref(),
            args.system.unwrap_or(false),
            args.create_home.unwrap_or(true),
        ))
    }
}

/// Handler for the `ssh_user_add` tool.
pub type SshUserAddHandler = StandardToolHandler<UserAddTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshUserAddHandler::new();
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
        let handler = SshUserAddHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "username": "newuser"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshUserAddHandler::new();
        assert_eq!(handler.name(), "ssh_user_add");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("username")));
    }
}
