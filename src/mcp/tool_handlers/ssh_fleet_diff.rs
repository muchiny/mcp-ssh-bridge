//! SSH Fleet Diff Tool Handler
//!
//! Executes a command on a host and returns its output for fleet-wide
//! comparison. Run on multiple hosts and compare outputs to detect
//! configuration drift.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::orchestration::OrchestrationCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshFleetDiffArgs {
    host: String,
    command: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshFleetDiffArgs);

pub struct FleetDiffTool;

impl StandardTool for FleetDiffTool {
    type Args = SshFleetDiffArgs;

    const NAME: &'static str = "ssh_fleet_diff";

    const DESCRIPTION: &'static str = "Execute a command on a host and return its output for \
        fleet-wide comparison. Run on multiple hosts and compare outputs to detect configuration \
        drift.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "command": {
                "type": "string",
                "description": "The command to execute (output will be compared across hosts)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 300
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from config)",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to local file"
            }
        },
        "required": ["host", "command"]
    }"#;

    fn build_command(args: &SshFleetDiffArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(OrchestrationCommandBuilder::build_fleet_diff_command(
            &args.command,
        ))
    }
}

pub type SshFleetDiffHandler = StandardToolHandler<FleetDiffTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFleetDiffHandler::new();
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
        let handler = SshFleetDiffHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "command": "cat /etc/os-release"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshFleetDiffHandler::new();
        assert_eq!(handler.name(), "ssh_fleet_diff");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "web1",
            "command": "cat /etc/os-release",
            "timeout_seconds": 30
        });
        let args: SshFleetDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "web1");
        assert_eq!(args.command, "cat /etc/os-release");
        assert_eq!(args.timeout_seconds, Some(30));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1", "command": "uname -a"});
        let args: SshFleetDiffArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.command, "uname -a");
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_build_command() {
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
        let args = SshFleetDiffArgs {
            host: "web1".to_string(),
            command: "cat /etc/os-release".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FleetDiffTool::build_command(&args, &host_config).unwrap();
        assert_eq!(cmd, "cat /etc/os-release");
    }
}
