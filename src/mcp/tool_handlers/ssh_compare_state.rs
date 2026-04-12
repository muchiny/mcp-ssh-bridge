//! SSH Compare State Tool Handler
//!
//! Captures current system state (packages, services, listeners, kernel)
//! for comparison against a known baseline.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::diagnostics::DiagnosticsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;

#[derive(Debug, Deserialize)]
pub struct SshCompareStateArgs {
    host: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshCompareStateArgs);

#[mcp_standard_tool(
    name = "ssh_compare_state",
    group = "diagnostics",
    annotation = "read_only"
)]
pub struct CompareStateTool;

impl StandardTool for CompareStateTool {
    type Args = SshCompareStateArgs;

    const NAME: &'static str = "ssh_compare_state";

    const DESCRIPTION: &'static str = "Capture the current system state of a host including \
        installed packages, active services, network listeners, and kernel version. Save the \
        output to a file and use it later to compare against the same or different hosts.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds (default: 60)",
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
                "description": "Save full output to local file for later comparison (recommended)"
            }
        },
        "required": ["host"]
    }"#;

    fn build_command(_args: &SshCompareStateArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DiagnosticsCommandBuilder::build_state_snapshot_command())
    }
}

pub type SshCompareStateHandler = StandardToolHandler<CompareStateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCompareStateHandler::new();
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
        let handler = SshCompareStateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshCompareStateHandler::new();
        assert_eq!(handler.name(), "ssh_compare_state");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "save_output": "/tmp/state.txt"});
        let args: SshCompareStateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.save_output, Some("/tmp/state.txt".to_string()));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshCompareStateArgs = serde_json::from_value(json).unwrap();
        assert!(args.save_output.is_none());
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

            #[cfg(feature = "winrm")]
            winrm_use_tls: None,

            #[cfg(feature = "winrm")]
            winrm_accept_invalid_certs: None,

            #[cfg(feature = "winrm")]
            winrm_operation_timeout_secs: None,

            #[cfg(feature = "winrm")]
            winrm_max_envelope_size: None,
        };
        let args = SshCompareStateArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = CompareStateTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("PACKAGES"));
        assert!(cmd.contains("SERVICES"));
        assert!(cmd.contains("uname -r"));
    }
}
