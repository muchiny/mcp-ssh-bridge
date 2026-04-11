//! SSH Incident Triage Tool Handler
//!
//! Automated incident triage that adapts diagnostic commands based on
//! the reported symptom type (slow, crash, OOM, disk, network).

use serde::Deserialize;

use crate::mcp_standard_tool;
use crate::config::HostConfig;
use crate::domain::use_cases::diagnostics::DiagnosticsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshIncidentTriageArgs {
    host: String,
    symptom: String,
    #[serde(default = "default_since")]
    since: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

fn default_since() -> String {
    "1 hour ago".to_string()
}

impl_common_args!(SshIncidentTriageArgs);

#[mcp_standard_tool(name = "ssh_incident_triage", group = "diagnostics", annotation = "read_only")]

pub struct IncidentTriageTool;

impl StandardTool for IncidentTriageTool {
    type Args = SshIncidentTriageArgs;

    const NAME: &'static str = "ssh_incident_triage";

    const DESCRIPTION: &'static str = "Automated incident triage that adapts diagnostics to the \
        reported symptom. Supports: slow/performance, crash/restart, oom/memory, disk/storage, \
        network/connectivity. Correlates logs, metrics, and service states in one call.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "symptom": {
                "type": "string",
                "description": "Type of issue: slow, crash, oom, disk, network",
                "enum": ["slow", "performance", "crash", "restart", "oom", "memory", "disk", "storage", "network", "connectivity"]
            },
            "since": {
                "type": "string",
                "description": "Time range for log analysis (default: '1 hour ago'). Accepts journalctl-style time specs."
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds (default: 90)",
                "minimum": 1,
                "maximum": 300
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to local file"
            }
        },
        "required": ["host", "symptom"]
    }"#;

    fn build_command(args: &SshIncidentTriageArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DiagnosticsCommandBuilder::build_triage_command(
            &args.symptom,
            &args.since,
        ))
    }
}

pub type SshIncidentTriageHandler = StandardToolHandler<IncidentTriageTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshIncidentTriageHandler::new();
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
        let handler = SshIncidentTriageHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "symptom": "slow"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshIncidentTriageHandler::new();
        assert_eq!(handler.name(), "ssh_incident_triage");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("symptom")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "symptom": "oom", "since": "2 hours ago"});
        let args: SshIncidentTriageArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.symptom, "oom");
        assert_eq!(args.since, "2 hours ago");
    }

    #[test]
    fn test_args_default_since() {
        let json = json!({"host": "server1", "symptom": "disk"});
        let args: SshIncidentTriageArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.since, "1 hour ago");
    }

    #[test]
    fn test_build_command_oom() {
        use crate::config::{HostConfig, HostKeyVerification, OsType};
        let host_config = HostConfig {
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
        };
        let args = SshIncidentTriageArgs {
            host: "server1".to_string(),
            symptom: "oom".to_string(),
            since: "1 hour ago".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = IncidentTriageTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("MEMORY DETAIL"));
        assert!(cmd.contains("TOP MEM"));
    }
}
