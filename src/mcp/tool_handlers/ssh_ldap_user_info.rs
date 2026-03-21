//! SSH LDAP User Info Tool Handler
//!
//! Looks up a user in an LDAP directory on a remote host via SSH.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ldap::LdapCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshLdapUserInfoArgs {
    host: String,
    base_dn: String,
    username: String,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshLdapUserInfoArgs);

pub struct LdapUserInfoTool;

impl StandardTool for LdapUserInfoTool {
    type Args = SshLdapUserInfoArgs;

    const NAME: &'static str = "ssh_ldap_user_info";

    const DESCRIPTION: &'static str = "Look up a user in an LDAP directory on a remote host. \
        Returns all attributes for the matching user.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "base_dn": {
                "type": "string",
                "description": "Base DN to search from (e.g. 'dc=example,dc=com')"
            },
            "username": {
                "type": "string",
                "description": "Username to look up (matched against uid attribute)"
            },
            "uri": {
                "type": "string",
                "description": "LDAP URI (e.g. 'ldap://ldap.example.com'). Uses system default if omitted."
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "base_dn", "username"]
    }"#;

    fn build_command(args: &SshLdapUserInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(LdapCommandBuilder::build_user_info_command(
            &args.base_dn,
            &args.username,
            args.uri.as_deref(),
        ))
    }
}

/// Handler for the `ssh_ldap_user_info` tool.
pub type SshLdapUserInfoHandler = StandardToolHandler<LdapUserInfoTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshLdapUserInfoHandler::new();
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
        let handler = SshLdapUserInfoHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "base_dn": "dc=example,dc=com", "username": "jdoe"})),
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
        let handler = SshLdapUserInfoHandler::new();
        assert_eq!(handler.name(), "ssh_ldap_user_info");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("base_dn")));
        assert!(required.contains(&json!("username")));
    }
}
