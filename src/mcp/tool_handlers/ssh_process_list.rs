//! Handler for the `ssh_process_list` tool.
//!
//! Lists running processes on a remote host with optional filtering and sorting.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::domain::use_cases::process::ProcessCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshProcessListArgs {
    /// Target host name from configuration.
    host: String,
    /// Filter processes by user.
    user: Option<String>,
    /// Sort field: %cpu, %mem, rss, vsz.
    sort_by: Option<String>,
    /// Filter processes by name pattern.
    filter: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshProcessListArgs);

#[mcp_standard_tool(name = "ssh_process_list", group = "process", annotation = "read_only")]
pub struct ProcessListTool;

impl StandardTool for ProcessListTool {
    type Args = SshProcessListArgs;

    const NAME: &'static str = "ssh_process_list";

    const DESCRIPTION: &'static str = "List running processes on a remote host. Prefer this over ssh_exec as it provides \
        structured filtering by user or process name with safe parameter handling. Sort by \
        CPU or memory usage. Returns PID, user, CPU%, memory%, and command. Use \
        ssh_process_kill to send signals to specific processes.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "user": {
                        "type": "string",
                        "description": "Filter processes by user"
                    },
                    "sort_by": {
                        "type": "string",
                        "description": "Sort field: %cpu, %mem, rss, vsz"
                    },
                    "filter": {
                        "type": "string",
                        "description": "Filter processes by name pattern"
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
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshProcessListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(ProcessCommandBuilder::build_list_command(
            args.user.as_deref(),
            args.sort_by.as_deref(),
            args.filter.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshProcessListArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Processes")
            .column("user", "User")
            .column("pid", "PID")
            .column("cpu", "%CPU")
            .column("mem", "%MEM")
            .column("command", "Command");

        let user_idx = parsed.headers.iter().position(|h| h == "user");
        let pid_idx = parsed.headers.iter().position(|h| h == "pid");
        let cpu_idx = parsed.headers.iter().position(|h| h == "%cpu");
        let mem_idx = parsed.headers.iter().position(|h| h == "%mem");
        let cmd_idx = parsed.headers.iter().position(|h| h == "command");

        for row in &parsed.rows {
            let get = |idx: Option<usize>| idx.and_then(|i| row.get(i)).map_or("", String::as_str);
            let user = get(user_idx);
            if !user.is_empty() {
                tbl = tbl.row(json!({
                    "user": user,
                    "pid": get(pid_idx),
                    "cpu": get(cpu_idx),
                    "mem": get(mem_idx),
                    "command": get(cmd_idx),
                }));
            }
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_process_list",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_process_list` tool.
pub type SshProcessListHandler = StandardToolHandler<ProcessListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshProcessListHandler::new();
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
        let handler = SshProcessListHandler::new();
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
        let handler = SshProcessListHandler::new();
        assert_eq!(handler.name(), "ssh_process_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_process_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "user": "root",
            "sort_by": "%cpu",
            "filter": "nginx",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/procs.txt"
        });
        let args: SshProcessListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.user.as_deref(), Some("root"));
        assert_eq!(args.sort_by.as_deref(), Some("%cpu"));
        assert_eq!(args.filter.as_deref(), Some("nginx"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/procs.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshProcessListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.user.is_none());
        assert!(args.sort_by.is_none());
        assert!(args.filter.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshProcessListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("user"));
        assert!(props.contains_key("sort_by"));
        assert!(props.contains_key("filter"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshProcessListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshProcessListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshProcessListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command & post_process Tests ==============

    use crate::config::{HostConfig, HostKeyVerification, OsType};

    fn test_host_config() -> HostConfig {
        HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::default(),
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),
        }
    }

    #[test]
    fn test_build_command_defaults() {
        let args: SshProcessListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = ProcessListTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("ps"));
    }

    #[test]
    fn test_build_command_with_options() {
        let args: SshProcessListArgs = serde_json::from_value(json!({
            "host": "s",
            "user": "root",
            "sort_by": "%cpu",
            "filter": "nginx"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = ProcessListTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("root"));
        assert!(cmd.contains("cpu") || cmd.contains("sort"));
        assert!(cmd.contains("nginx") || cmd.contains("grep"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshProcessListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "USER     PID   %CPU  %MEM  COMMAND\nroot       1    0.0   0.1  /sbin/init\nnginx    123    1.2   0.5  nginx: worker\n";
        let result = ProcessListTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
        assert!(result.content.len() > 1);
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshProcessListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = ProcessListTool::post_process(result, &args, "", &dr);
        assert!(!result.content.is_empty());
    }

    // ============== Full Pipeline Test ==============

    fn mock_output(stdout: &str) -> crate::ssh::CommandOutput {
        crate::ssh::CommandOutput {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            duration_ms: 42,
        }
    }

    fn server1_hosts() -> std::collections::HashMap<String, crate::config::HostConfig> {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "server1".to_string(),
            crate::config::HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "test".to_string(),
                auth: crate::config::AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                tags: Vec::new(),
                os_type: OsType::default(),
                shell: None,
                retry: None,
                protocol: crate::config::Protocol::default(),
            },
        );
        hosts
    }

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshProcessListHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(
                "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 225516  9264 ?        Ss   Jan01   0:15 /sbin/init\n",
            ),
        );
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        // post_process adds App content
        assert!(result.content.len() >= 2);
        assert!(result.structured_content.is_some());
    }
}
