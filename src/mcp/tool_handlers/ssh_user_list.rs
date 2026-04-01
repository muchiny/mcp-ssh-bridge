//! Handler for the `ssh_user_list` tool.
//!
//! Lists users on a remote Linux host.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::domain::use_cases::user_management::UserCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshUserListArgs {
    /// Target host name from configuration.
    host: String,
    /// Include system accounts (UID < 1000).
    #[serde(default)]
    system: Option<bool>,
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

impl_common_args!(SshUserListArgs);

pub struct UserListTool;

impl StandardTool for UserListTool {
    type Args = SshUserListArgs;

    const NAME: &'static str = "ssh_user_list";

    const DESCRIPTION: &'static str = "List users on a remote Linux host. By default shows only \
        regular users (UID >= 1000). Set system=true to include system accounts.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "system": {
                "type": "boolean",
                "description": "Include system accounts (UID < 1000). Default: false"
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

    fn build_command(args: &SshUserListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(UserCommandBuilder::build_user_list_command(
            args.system.unwrap_or(false),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshUserListArgs,
        output: &str,
    ) -> ToolCallResult {
        let lines: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.len() < 2 {
            return result;
        }
        let mut tbl = table("Users")
            .column("user", "User")
            .column("uid", "UID")
            .column("gid", "GID")
            .column("home", "Home")
            .column("shell", "Shell");
        for line in &lines[1..] {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 5 {
                tbl = tbl.row(json!({
                    "user": cols[0],
                    "uid": cols[1],
                    "gid": cols[2],
                    "home": cols[3],
                    "shell": cols[4],
                }));
            }
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_user_list",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(output).with_app(tbl.build())
    }
}

/// Handler for the `ssh_user_list` tool.
pub type SshUserListHandler = StandardToolHandler<UserListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshUserListHandler::new();
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
        let handler = SshUserListHandler::new();
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
        let handler = SshUserListHandler::new();
        assert_eq!(handler.name(), "ssh_user_list");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }
}
