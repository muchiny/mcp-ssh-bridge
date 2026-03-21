//! SSH SBOM Generate Tool Handler
//!
//! Generates a Software Bill of Materials listing all installed packages,
//! versions, and architecture on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::sbom::SbomCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{impl_common_args, StandardTool, StandardToolHandler};

#[derive(Debug, Deserialize)]
pub struct SshSbomGenerateArgs {
    host: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshSbomGenerateArgs);

pub struct SbomGenerateTool;

impl StandardTool for SbomGenerateTool {
    type Args = SshSbomGenerateArgs;

    const NAME: &'static str = "ssh_sbom_generate";

    const DESCRIPTION: &'static str = "Generate a Software Bill of Materials (SBOM) listing all \
        installed packages, versions, and architecture on a remote host.";

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
        _args: &SshSbomGenerateArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        Ok(SbomCommandBuilder::build_sbom_command())
    }
}

pub type SshSbomGenerateHandler = StandardToolHandler<SbomGenerateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::mock::create_test_context;
    use crate::ports::ToolHandler;
    use serde_json::json;

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
        }
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshSbomGenerateHandler::new();
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
        let handler = SshSbomGenerateHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshSbomGenerateHandler::new();
        assert_eq!(handler.name(), "ssh_sbom_generate");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "timeout_seconds": 120});
        let args: SshSbomGenerateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshSbomGenerateArgs = serde_json::from_value(json).unwrap();
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_build_command() {
        let args = SshSbomGenerateArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = SbomGenerateTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("INSTALLED PACKAGES"));
        assert!(cmd.contains("dpkg-query"));
        assert!(cmd.contains("rpm -qa"));
    }
}
