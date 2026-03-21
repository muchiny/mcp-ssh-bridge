//! Handler for the `ssh_journal_query` tool.
//!
//! Query systemd journal logs on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::journald::JournaldCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshJournalQueryArgs {
    host: String,
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    lines: Option<u64>,
    #[serde(default)]
    grep: Option<String>,
    #[serde(default)]
    reverse: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshJournalQueryArgs);

pub struct JournalQueryTool;

impl StandardTool for JournalQueryTool {
    type Args = SshJournalQueryArgs;

    const NAME: &'static str = "ssh_journal_query";

    const DESCRIPTION: &'static str = "Query systemd journal logs on a remote host. Filter by \
        unit, priority, time range, and grep pattern.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "unit": {
                "type": "string",
                "description": "Filter by systemd unit name (e.g., nginx.service, sshd.service)"
            },
            "priority": {
                "type": "string",
                "description": "Filter by priority level (e.g., emerg, alert, crit, err, warning, notice, info, debug)"
            },
            "since": {
                "type": "string",
                "description": "Show entries since this time (e.g., '1 hour ago', '2024-01-01 00:00:00', 'today')"
            },
            "until": {
                "type": "string",
                "description": "Show entries until this time (e.g., 'now', '2024-01-01 12:00:00')"
            },
            "lines": {
                "type": "integer",
                "description": "Number of recent log lines to show"
            },
            "grep": {
                "type": "string",
                "description": "Filter log entries matching this pattern"
            },
            "reverse": {
                "type": "boolean",
                "description": "Show newest entries first (default: false)"
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

    fn build_command(args: &SshJournalQueryArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(JournaldCommandBuilder::build_query_command(
            args.unit.as_deref(),
            args.priority.as_deref(),
            args.since.as_deref(),
            args.until.as_deref(),
            args.lines,
            args.grep.as_deref(),
            args.reverse.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_journal_query` tool.
pub type SshJournalQueryHandler = StandardToolHandler<JournalQueryTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshJournalQueryHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshJournalQueryHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshJournalQueryHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_journal_query");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "unit": "nginx.service",
            "priority": "err",
            "since": "1 hour ago",
            "until": "now",
            "lines": 100,
            "grep": "error",
            "reverse": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshJournalQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.unit, Some("nginx.service".to_string()));
        assert_eq!(args.priority, Some("err".to_string()));
        assert_eq!(args.reverse, Some(true));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshJournalQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.unit.is_none());
        assert!(args.priority.is_none());
        assert!(args.since.is_none());
        assert!(args.until.is_none());
        assert!(args.lines.is_none());
        assert!(args.grep.is_none());
        assert!(args.reverse.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshJournalQueryHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h"});
        let args: SshJournalQueryArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshJournalQueryArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123});
        let result = serde_json::from_value::<SshJournalQueryArgs>(json);
        assert!(result.is_err());
    }
}
