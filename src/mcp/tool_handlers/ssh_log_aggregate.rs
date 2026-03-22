//! Handler for the `ssh_log_aggregate` tool.
//!
//! Aggregates log statistics (total, error, warning counts) on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::log_aggregation::LogAggregationCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshLogAggregateArgs {
    /// Target host name from configuration.
    host: String,
    /// Log files to aggregate (space-separated). Defaults to common log paths.
    #[serde(default)]
    log_files: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshLogAggregateArgs);

pub struct LogAggregateTool;

impl StandardTool for LogAggregateTool {
    type Args = SshLogAggregateArgs;

    const NAME: &'static str = "ssh_log_aggregate";

    const DESCRIPTION: &'static str = "Aggregate log statistics on a remote host. Counts total lines, \
        error lines, and warning lines across specified log files. Useful for quick health \
        assessment and identifying problematic log files.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "log_files": {
                        "type": "string",
                        "description": "Space-separated log file paths (default: /var/log/syslog /var/log/messages /var/log/auth.log)"
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

    fn build_command(args: &SshLogAggregateArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(LogAggregationCommandBuilder::build_log_aggregate_command(
            args.log_files.as_deref(),
        ))
    }
}

/// Handler for the `ssh_log_aggregate` tool.
pub type SshLogAggregateHandler = StandardToolHandler<LogAggregateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshLogAggregateHandler::new();
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
        let handler = SshLogAggregateHandler::new();
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
        let handler = SshLogAggregateHandler::new();
        assert_eq!(handler.name(), "ssh_log_aggregate");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_log_aggregate");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "log_files": "/var/log/app.log /var/log/nginx/error.log",
            "timeout_seconds": 60,
            "max_output": 10000,
            "save_output": "/tmp/aggregate.txt"
        });
        let args: SshLogAggregateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(
            args.log_files.as_deref(),
            Some("/var/log/app.log /var/log/nginx/error.log")
        );
        assert_eq!(args.timeout_seconds, Some(60));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshLogAggregateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.log_files.is_none());
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshLogAggregateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("log_files"));
        assert!(props.contains_key("timeout_seconds"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshLogAggregateArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshLogAggregateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshLogAggregateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    fn test_host_config() -> HostConfig {
        HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::default(),
            shell: None,
            retry: None,
        }
    }

    #[test]
    fn test_build_command_defaults() {
        let args = SshLogAggregateArgs {
            host: "s".to_string(),
            log_files: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = LogAggregateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("Log Aggregation"));
        assert!(cmd.contains("wc -l"));
    }

    #[test]
    fn test_build_command_custom_files() {
        let args = SshLogAggregateArgs {
            host: "s".to_string(),
            log_files: Some("/var/log/nginx/access.log".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = LogAggregateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("/var/log/nginx/access.log"));
    }
}
