//! SSH Compliance Check Tool Handler
//!
//! Runs CIS benchmark compliance checks including file permissions, SSH config,
//! firewall, password policy, and sysctl settings.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::sbom::SbomCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshComplianceCheckArgs {
    host: String,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshComplianceCheckArgs);

pub struct ComplianceCheckTool;

impl StandardTool for ComplianceCheckTool {
    type Args = SshComplianceCheckArgs;

    const NAME: &'static str = "ssh_compliance_check";

    const DESCRIPTION: &'static str = "Run CIS benchmark compliance checks including file \
        permissions, SSH config, firewall, password policy, and sysctl settings.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "profile": {
                "type": "string",
                "description": "Compliance profile to check (default: cis-level1)",
                "enum": ["cis-level1", "cis-level2", "basic"]
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

    fn build_command(args: &SshComplianceCheckArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(SbomCommandBuilder::build_compliance_command(
            args.profile.as_deref().unwrap_or("cis-level1"),
        ))
    }
}

pub type SshComplianceCheckHandler = StandardToolHandler<ComplianceCheckTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostConfig, HostKeyVerification, OsType};
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
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
            protocol: crate::config::Protocol::default(),
        }
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshComplianceCheckHandler::new();
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
        let handler = SshComplianceCheckHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshComplianceCheckHandler::new();
        assert_eq!(handler.name(), "ssh_compliance_check");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        // Verify profile enum is in schema
        let profile = &schema_json["properties"]["profile"];
        assert!(profile["enum"].is_array());
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "profile": "cis-level2", "timeout_seconds": 120});
        let args: SshComplianceCheckArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.profile, Some("cis-level2".to_string()));
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshComplianceCheckArgs = serde_json::from_value(json).unwrap();
        assert!(args.profile.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_build_command() {
        let args = SshComplianceCheckArgs {
            host: "server1".to_string(),
            profile: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = ComplianceCheckTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("CIS COMPLIANCE"));
        assert!(cmd.contains("SSH Configuration"));
        assert!(cmd.contains("Firewall"));
        assert!(cmd.contains("Password Policy"));
    }

    #[test]
    fn test_build_command_basic_profile() {
        let args = SshComplianceCheckArgs {
            host: "server1".to_string(),
            profile: Some("basic".to_string()),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = ComplianceCheckTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("BASIC COMPLIANCE"));
    }
}
