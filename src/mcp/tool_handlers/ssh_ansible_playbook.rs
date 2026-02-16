//! SSH Ansible Playbook Tool Handler
//!
//! Runs an Ansible playbook on a remote host via SSH.
//! Supports inventory, tags, extra variables, check mode, and verbosity control.

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::ansible::AnsibleCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshAnsiblePlaybookArgs {
    host: String,
    playbook: String,
    #[serde(default)]
    inventory: Option<String>,
    #[serde(default)]
    limit: Option<String>,
    #[serde(default)]
    tags: Option<String>,
    #[serde(default)]
    skip_tags: Option<String>,
    #[serde(default)]
    extra_vars: Option<HashMap<String, String>>,
    #[serde(default)]
    check: Option<bool>,
    #[serde(default)]
    diff: Option<bool>,
    #[serde(default)]
    verbose: Option<u8>,
    #[serde(default)]
    forks: Option<u32>,
    #[serde(default, rename = "become")]
    use_become: Option<bool>,
    #[serde(default)]
    become_user: Option<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshAnsiblePlaybookArgs);

pub struct AnsiblePlaybookTool;

impl StandardTool for AnsiblePlaybookTool {
    type Args = SshAnsiblePlaybookArgs;

    const NAME: &'static str = "ssh_ansible_playbook";

    const DESCRIPTION: &'static str = "Run an Ansible playbook on a remote host via SSH. The playbook file must exist on the \
        remote host. Use check=true for dry-run mode to preview changes without applying. Use \
        ssh_ansible_inventory first to discover available hosts and groups. For quick \
        single-module tasks, prefer ssh_ansible_adhoc instead. Returns ansible-playbook text \
        output.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "playbook": {
                "type": "string",
                "description": "Path to the Ansible playbook YAML file on the remote host"
            },
            "inventory": {
                "type": "string",
                "description": "Inventory file or comma-separated host list"
            },
            "limit": {
                "type": "string",
                "description": "Limit to subset of hosts"
            },
            "tags": {
                "type": "string",
                "description": "Only run plays/tasks matching these tags"
            },
            "skip_tags": {
                "type": "string",
                "description": "Skip plays/tasks matching these tags"
            },
            "extra_vars": {
                "type": "object",
                "description": "Extra variables as key-value pairs"
            },
            "check": {
                "type": "boolean",
                "description": "Dry-run mode"
            },
            "diff": {
                "type": "boolean",
                "description": "Show file change diffs"
            },
            "verbose": {
                "type": "integer",
                "description": "Verbosity level 0-4",
                "minimum": 0,
                "maximum": 4
            },
            "forks": {
                "type": "integer",
                "description": "Number of parallel processes",
                "minimum": 1
            },
            "become": {
                "type": "boolean",
                "description": "Escalate privileges with sudo"
            },
            "become_user": {
                "type": "string",
                "description": "User to become"
            },
            "working_dir": {
                "type": "string",
                "description": "Directory to cd into before running"
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
        "required": ["host", "playbook"]
    }"#;

    fn build_command(args: &SshAnsiblePlaybookArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(AnsibleCommandBuilder::build_playbook_command(
            &args.playbook,
            args.inventory.as_deref(),
            args.limit.as_deref(),
            args.tags.as_deref(),
            args.skip_tags.as_deref(),
            args.extra_vars.as_ref(),
            args.check.unwrap_or(false),
            args.diff.unwrap_or(false),
            args.verbose,
            args.forks,
            args.use_become.unwrap_or(false),
            args.become_user.as_deref(),
            args.working_dir.as_deref(),
        ))
    }

    fn validate(args: &SshAnsiblePlaybookArgs, _host_config: &HostConfig) -> Result<()> {
        AnsibleCommandBuilder::validate_playbook_path(&args.playbook)?;
        Ok(())
    }
}

/// Handler for the `ssh_ansible_playbook` tool.
pub type SshAnsiblePlaybookHandler = StandardToolHandler<AnsiblePlaybookTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "playbook": "site.yml"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "nonexistent");
            }
            e => panic!("Expected UnknownHost error, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshAnsiblePlaybookHandler::new();
        assert_eq!(handler.name(), "ssh_ansible_playbook");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ansible_playbook");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("playbook")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "playbook": "site.yml",
            "inventory": "hosts.ini",
            "limit": "webservers",
            "tags": "deploy",
            "skip_tags": "debug",
            "extra_vars": {"env": "production", "version": "1.2.3"},
            "check": true,
            "diff": true,
            "verbose": 2,
            "forks": 10,
            "become": true,
            "become_user": "root",
            "working_dir": "/opt/ansible",
            "timeout_seconds": 600,
            "max_output": 15000
        });

        let args: SshAnsiblePlaybookArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert_eq!(args.inventory, Some("hosts.ini".to_string()));
        assert_eq!(args.limit, Some("webservers".to_string()));
        assert_eq!(args.tags, Some("deploy".to_string()));
        assert_eq!(args.skip_tags, Some("debug".to_string()));
        let extra_vars = args.extra_vars.unwrap();
        assert_eq!(extra_vars.get("env"), Some(&"production".to_string()));
        assert_eq!(extra_vars.get("version"), Some(&"1.2.3".to_string()));
        assert_eq!(args.check, Some(true));
        assert_eq!(args.diff, Some(true));
        assert_eq!(args.verbose, Some(2));
        assert_eq!(args.forks, Some(10));
        assert_eq!(args.use_become, Some(true));
        assert_eq!(args.become_user, Some("root".to_string()));
        assert_eq!(args.working_dir, Some("/opt/ansible".to_string()));
        assert_eq!(args.timeout_seconds, Some(600));
        assert_eq!(args.max_output, Some(15000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "playbook": "site.yml"
        });

        let args: SshAnsiblePlaybookArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.playbook, "site.yml");
        assert!(args.inventory.is_none());
        assert!(args.limit.is_none());
        assert!(args.tags.is_none());
        assert!(args.skip_tags.is_none());
        assert!(args.extra_vars.is_none());
        assert!(args.check.is_none());
        assert!(args.diff.is_none());
        assert!(args.verbose.is_none());
        assert!(args.forks.is_none());
        assert!(args.use_become.is_none());
        assert!(args.become_user.is_none());
        assert!(args.working_dir.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context();

        // Missing playbook field
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_playbook_path_traversal_rejected() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "playbook": "../../../etc/shadow"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Path traversal"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshAnsiblePlaybookHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("inventory"));
        assert!(properties.contains_key("limit"));
        assert!(properties.contains_key("tags"));
        assert!(properties.contains_key("skip_tags"));
        assert!(properties.contains_key("extra_vars"));
        assert!(properties.contains_key("check"));
        assert!(properties.contains_key("diff"));
        assert!(properties.contains_key("verbose"));
        assert!(properties.contains_key("forks"));
        assert!(properties.contains_key("become"));
        assert!(properties.contains_key("become_user"));
        assert!(properties.contains_key("working_dir"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "playbook": "site.yml"
        });
        let args: SshAnsiblePlaybookArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshAnsiblePlaybookArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshAnsiblePlaybookHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "playbook": "site.yml"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
