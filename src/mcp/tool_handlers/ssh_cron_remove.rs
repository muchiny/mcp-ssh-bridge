//! Handler for the `ssh_cron_remove` tool.
//!
//! Removes cron jobs matching a pattern on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::cron::CronCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshCronRemoveArgs {
    /// Target host name from configuration.
    host: String,
    /// Pattern to match crontab entries for removal.
    pattern: String,
    /// User whose crontab to modify.
    user: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshCronRemoveArgs);

pub struct CronRemoveTool;

impl StandardTool for CronRemoveTool {
    type Args = SshCronRemoveArgs;

    const NAME: &'static str = "ssh_cron_remove";

    const DESCRIPTION: &'static str = "Remove cron jobs matching a pattern on a remote host. Prefer this over ssh_exec as it \
        safely filters the crontab without risk of data loss. Removes all entries containing \
        the specified pattern. Use ssh_cron_list first to verify which entries will be \
        removed.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Pattern to match crontab entries for removal"
                    },
                    "user": {
                        "type": "string",
                        "description": "User whose crontab to modify"
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
                "required": ["host", "pattern"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshCronRemoveArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(CronCommandBuilder::build_remove_command(
            &args.pattern,
            args.user.as_deref(),
        ))
    }
}

/// Handler for the `ssh_cron_remove` tool.
pub type SshCronRemoveHandler = StandardToolHandler<CronRemoveTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCronRemoveHandler::new();
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
        let handler = SshCronRemoveHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "pattern": "backup"})),
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
        let handler = SshCronRemoveHandler::new();
        assert_eq!(handler.name(), "ssh_cron_remove");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_cron_remove");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("pattern")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "pattern": "backup.sh",
            "user": "root",
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/cron_rm.txt"
        });
        let args: SshCronRemoveArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pattern, "backup.sh");
        assert_eq!(args.user.as_deref(), Some("root"));
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/cron_rm.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "pattern": "cleanup"});
        let args: SshCronRemoveArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pattern, "cleanup");
        assert!(args.user.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCronRemoveHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("user"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "pattern": "backup"});
        let args: SshCronRemoveArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCronRemoveArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCronRemoveHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "pattern": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
