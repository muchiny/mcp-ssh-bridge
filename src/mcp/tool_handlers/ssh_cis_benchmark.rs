//! Handler for the `ssh_cis_benchmark` tool.
//!
//! Runs CIS benchmark checks on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::compliance::ComplianceCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshCisBenchmarkArgs {
    /// Target host name from configuration.
    host: String,
    /// CIS benchmark level (1 or 2).
    #[serde(default)]
    level: Option<u8>,
    /// Category to check (e.g., "filesystem", "ssh", "kernel", "password").
    #[serde(default)]
    category: Option<String>,
    /// Override default command timeout in seconds.
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    #[serde(default)]
    max_output: Option<u64>,
    /// Save full output to a local file path.
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshCisBenchmarkArgs);

pub struct CisBenchmarkTool;

impl StandardTool for CisBenchmarkTool {
    type Args = SshCisBenchmarkArgs;

    const NAME: &'static str = "ssh_cis_benchmark";

    const DESCRIPTION: &'static str = "Run CIS benchmark checks on a remote Linux host. Prefer this over ssh_exec \
        for compliance auditing as it checks file permissions, SSH hardening, kernel parameters, \
        password policy, and audit rules according to CIS benchmark levels 1 and 2.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "level": {
                        "type": "integer",
                        "description": "CIS benchmark level (1 or 2)",
                        "minimum": 1,
                        "maximum": 2
                    },
                    "category": {
                        "type": "string",
                        "description": "Category to check: filesystem, ssh, kernel, or password"
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

    fn build_command(
        args: &SshCisBenchmarkArgs,
        _host_config: &HostConfig,
    ) -> Result<String> {
        ComplianceCommandBuilder::build_cis_benchmark_command(
            args.level,
            args.category.as_deref(),
        )
    }
}

/// Handler for the `ssh_cis_benchmark` tool.
pub type SshCisBenchmarkHandler = StandardToolHandler<CisBenchmarkTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCisBenchmarkHandler::new();
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
        let handler = SshCisBenchmarkHandler::new();
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
        let handler = SshCisBenchmarkHandler::new();
        assert_eq!(handler.name(), "ssh_cis_benchmark");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_cis_benchmark");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "level": 2,
            "category": "ssh",
            "timeout_seconds": 60,
            "max_output": 10000,
            "save_output": "/tmp/cis.txt"
        });
        let args: SshCisBenchmarkArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.level, Some(2));
        assert_eq!(args.category.as_deref(), Some("ssh"));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/cis.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshCisBenchmarkArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.level.is_none());
        assert!(args.category.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCisBenchmarkHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("level"));
        assert!(props.contains_key("category"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshCisBenchmarkArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCisBenchmarkArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCisBenchmarkHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
