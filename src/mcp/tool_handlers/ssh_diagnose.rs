//! SSH Diagnose Tool Handler
//!
//! Comprehensive single-call host diagnostic combining CPU, memory, disk,
//! processes, services, errors, and network in one compound command.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::diagnostics::DiagnosticsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{impl_common_args, StandardTool, StandardToolHandler};

#[derive(Debug, Deserialize)]
pub struct SshDiagnoseArgs {
    host: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshDiagnoseArgs);

pub struct DiagnoseTool;

impl StandardTool for DiagnoseTool {
    type Args = SshDiagnoseArgs;

    const NAME: &'static str = "ssh_diagnose";

    const DESCRIPTION: &'static str = "Run a comprehensive diagnostic on a remote host in a \
        single call. Collects uptime, CPU load, memory, disk usage, top processes, failed \
        services, recent errors, OOM kills, and network listeners. Much faster than running \
        individual commands sequentially.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds (default: 60, recommended for diagnostics)",
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
        "required": ["host"]
    }"#;

    fn build_command(
        _args: &SshDiagnoseArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        Ok(DiagnosticsCommandBuilder::build_diagnose_command())
    }
}

pub type SshDiagnoseHandler = StandardToolHandler<DiagnoseTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::mock::create_test_context;
    use crate::ports::ToolHandler;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDiagnoseHandler::new();
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
        let handler = SshDiagnoseHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshDiagnoseHandler::new();
        assert_eq!(handler.name(), "ssh_diagnose");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "timeout_seconds": 120});
        let args: SshDiagnoseArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshDiagnoseArgs = serde_json::from_value(json).unwrap();
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
        };
        let args = SshDiagnoseArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = DiagnoseTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("free -m"));
        assert!(cmd.contains("df -h"));
        assert!(cmd.contains("systemctl --failed"));
    }
}
