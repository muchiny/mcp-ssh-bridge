//! Handler for the `ssh_service_list` tool.
//!
//! Lists systemd services on a remote host.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::systemd::SystemdCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshServiceListArgs {
    host: String,
    state: Option<String>,
    all: Option<bool>,
    unit_type: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshServiceListArgs);

#[mcp_standard_tool(name = "ssh_service_list", group = "systemd", annotation = "read_only")]
pub struct ServiceListTool;

impl StandardTool for ServiceListTool {
    type Args = SshServiceListArgs;

    const NAME: &'static str = "ssh_service_list";

    const DESCRIPTION: &'static str = "List systemd services on a remote host. Start here to discover service names before \
        using ssh_service_status, ssh_service_start, ssh_service_stop, or \
        ssh_service_restart. Filter by state (running, failed, inactive) and unit type. \
        Returns service name, load state, active state, and description.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "state": {
                "type": "string",
                "description": "Filter by state: running, failed, inactive, active, etc."
            },
            "all": {
                "type": "boolean",
                "description": "Show all loaded units including inactive ones (default: false)"
            },
            "unit_type": {
                "type": "string",
                "description": "Filter by unit type: service, socket, timer, mount, etc."
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

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshServiceListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(SystemdCommandBuilder::build_list_command(
            args.state.as_deref(),
            args.all.unwrap_or(false),
            args.unit_type.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshServiceListArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_reduce_table(parsed, dr);
        let mut tbl = table("Systemd Services")
            .column("unit", "Unit")
            .column("load", "Load")
            .column("active", "Active")
            .column("sub", "Sub");

        let unit_idx = parsed.headers.iter().position(|h| h == "unit");
        let load_idx = parsed.headers.iter().position(|h| h == "load");
        let active_idx = parsed.headers.iter().position(|h| h == "active");
        let sub_idx = parsed.headers.iter().position(|h| h == "sub");

        for row in &parsed.rows {
            let get = |idx: Option<usize>| idx.and_then(|i| row.get(i)).map_or("", String::as_str);
            let unit = get(unit_idx);
            if !unit.is_empty() {
                tbl = tbl.row(json!({
                    "unit": unit,
                    "load": get(load_idx),
                    "active": get(active_idx),
                    "sub": get(sub_idx),
                }));
            }
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_service_list",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_service_list` tool.
pub type SshServiceListHandler = StandardToolHandler<ServiceListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshServiceListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshServiceListHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshServiceListHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_service_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "state": "running",
            "all": true,
            "unit_type": "service",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshServiceListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.state, Some("running".to_string()));
        assert_eq!(args.all, Some(true));
        assert_eq!(args.unit_type, Some("service".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshServiceListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.state.is_none());
        assert!(args.all.is_none());
        assert!(args.unit_type.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshServiceListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("state"));
        assert!(props.contains_key("all"));
        assert!(props.contains_key("unit_type"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h"});
        let args: SshServiceListArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshServiceListArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123});
        let result = serde_json::from_value::<SshServiceListArgs>(json);
        assert!(result.is_err());
    }

    // ============== build_command & post_process Tests ==============

    use crate::config::{HostConfig, HostKeyVerification};

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

            #[cfg(feature = "winrm")]
            winrm_use_tls: None,

            #[cfg(feature = "winrm")]
            winrm_accept_invalid_certs: None,

            #[cfg(feature = "winrm")]
            winrm_operation_timeout_secs: None,

            #[cfg(feature = "winrm")]
            winrm_max_envelope_size: None,
        }
    }

    #[test]
    fn test_build_command_defaults() {
        let args: SshServiceListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = ServiceListTool::build_command(&args, &host).unwrap();
        assert!(!cmd.is_empty());
        assert!(cmd.contains("systemctl") || cmd.contains("list-units"));
    }

    #[test]
    fn test_build_command_with_options() {
        let args: SshServiceListArgs = serde_json::from_value(json!({
            "host": "s",
            "state": "running",
            "all": true,
            "unit_type": "service"
        }))
        .unwrap();
        let host = test_host_config();
        let cmd = ServiceListTool::build_command(&args, &host).unwrap();
        assert!(cmd.contains("running"));
        assert!(cmd.contains("--all"));
        assert!(cmd.contains("service"));
    }

    #[test]
    fn test_post_process_with_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshServiceListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let output = "UNIT                  LOAD    ACTIVE  SUB\nnginx.service         loaded  active  running\nsshd.service          loaded  active  running\n";
        let result = ServiceListTool::post_process(result, &args, output, &dr);
        assert!(!result.content.is_empty());
        assert!(result.content.len() > 1);
    }

    #[test]
    fn test_post_process_empty_output() {
        let result = crate::ports::protocol::ToolCallResult::text("raw");
        let args: SshServiceListArgs = serde_json::from_value(json!({
            "host": "s"
        }))
        .unwrap();
        let dr = crate::domain::data_reduction::DataReductionArgs::default();
        let result = ServiceListTool::post_process(result, &args, "", &dr);
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
                os_type: crate::config::OsType::default(),
                shell: None,
                retry: None,
                protocol: crate::config::Protocol::default(),
                #[cfg(feature = "winrm")]
                winrm_use_tls: None,
                #[cfg(feature = "winrm")]
                winrm_accept_invalid_certs: None,
                #[cfg(feature = "winrm")]
                winrm_operation_timeout_secs: None,
                #[cfg(feature = "winrm")]
                winrm_max_envelope_size: None,
            },
        );
        hosts
    }

    #[tokio::test]
    async fn test_full_pipeline_success() {
        let handler = SshServiceListHandler::new();
        let ctx = crate::ports::mock::create_test_context_with_mock_executor(
            server1_hosts(),
            mock_output(
                "UNIT                 LOAD   ACTIVE SUB     DESCRIPTION\nnginx.service        loaded active running Nginx\nsshd.service         loaded active running OpenSSH\n",
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
