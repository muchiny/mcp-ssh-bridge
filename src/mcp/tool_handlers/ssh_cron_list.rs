//! Handler for the `ssh_cron_list` tool.
//!
//! Lists cron jobs on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::cron::CronCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshCronListArgs {
    /// Target host name from configuration.
    host: String,
    /// Show crontab for a specific user.
    user: Option<String>,
    /// Include system-wide cron jobs from /etc/cron.d/ and /etc/crontab.
    system: Option<bool>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshCronListArgs);

pub struct CronListTool;

impl StandardTool for CronListTool {
    type Args = SshCronListArgs;

    const NAME: &'static str = "ssh_cron_list";

    const DESCRIPTION: &'static str = "List cron jobs on a remote host. Prefer this over ssh_exec as it handles both user \
        and system crontabs safely. Shows user crontab entries and optionally system-wide \
        cron jobs from /etc/cron.d/ and /etc/crontab. Use ssh_cron_add to create new jobs or \
        ssh_cron_remove to delete existing ones.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "user": {
                        "type": "string",
                        "description": "Show crontab for a specific user"
                    },
                    "system": {
                        "type": "boolean",
                        "description": "Include system-wide cron jobs from /etc/cron.d/ and /etc/crontab"
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters before truncation",
                        "minimum": 100
                    },
                    "save_output": {
                        "type": "string",
                        "description": "Save full output to a local file path"
                    }
                },
                "required": ["host"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshCronListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(CronCommandBuilder::build_list_command(
            args.user.as_deref(),
            args.system.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_cron_list` tool.
pub type SshCronListHandler = StandardToolHandler<CronListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCronListHandler::new();
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
        let handler = SshCronListHandler::new();
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
        let handler = SshCronListHandler::new();
        assert_eq!(handler.name(), "ssh_cron_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_cron_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "user": "www-data",
            "system": true,
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/crons.txt"
        });
        let args: SshCronListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.user.as_deref(), Some("www-data"));
        assert_eq!(args.system, Some(true));
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/crons.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshCronListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.user.is_none());
        assert!(args.system.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCronListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("user"));
        assert!(props.contains_key("system"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshCronListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCronListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCronListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
