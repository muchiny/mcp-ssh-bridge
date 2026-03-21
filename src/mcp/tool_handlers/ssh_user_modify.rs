//! Handler for the `ssh_user_modify` tool.
//!
//! Modifies an existing user on a remote Linux host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::user_management::UserCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshUserModifyArgs {
    /// Target host name from configuration.
    host: String,
    /// Username to modify.
    username: String,
    /// New login shell.
    #[serde(default)]
    shell: Option<String>,
    /// Supplementary groups (comma-separated).
    #[serde(default)]
    groups: Option<String>,
    /// Append to existing groups instead of replacing.
    #[serde(default)]
    append_groups: Option<bool>,
    /// New home directory path.
    #[serde(default)]
    home_dir: Option<String>,
    /// Lock (true) or unlock (false) the account.
    #[serde(default)]
    lock: Option<bool>,
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

impl_common_args!(SshUserModifyArgs);

pub struct UserModifyTool;

impl StandardTool for UserModifyTool {
    type Args = SshUserModifyArgs;

    const NAME: &'static str = "ssh_user_modify";

    const DESCRIPTION: &'static str = "Modify an existing user on a remote Linux host. Change \
        shell, groups, home directory, or lock/unlock the account.";

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
                "description": "Username to modify"
            },
            "shell": {
                "type": "string",
                "description": "New login shell (e.g., /bin/bash, /bin/zsh)"
            },
            "groups": {
                "type": "string",
                "description": "Supplementary groups (comma-separated, e.g., docker,sudo)"
            },
            "append_groups": {
                "type": "boolean",
                "description": "Append to existing groups instead of replacing. Default: true"
            },
            "home_dir": {
                "type": "string",
                "description": "New home directory path"
            },
            "lock": {
                "type": "boolean",
                "description": "Lock (true) or unlock (false) the account"
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

    fn build_command(args: &SshUserModifyArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(UserCommandBuilder::build_user_modify_command(
            &args.username,
            args.shell.as_deref(),
            args.groups.as_deref(),
            args.append_groups.unwrap_or(true),
            args.home_dir.as_deref(),
            args.lock,
        ))
    }
}

/// Handler for the `ssh_user_modify` tool.
pub type SshUserModifyHandler = StandardToolHandler<UserModifyTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshUserModifyHandler::new();
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
        let handler = SshUserModifyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "username": "admin"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshUserModifyHandler::new();
        assert_eq!(handler.name(), "ssh_user_modify");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("username")));
    }
}
