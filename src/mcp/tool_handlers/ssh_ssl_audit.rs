//! Handler for the `ssh_ssl_audit` tool.
//!
//! Audits SSL/TLS certificate and configuration on a remote target.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::network_security::{
    NetworkSecurityCommandBuilder, validate_port, validate_target,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshSslAuditArgs {
    /// Target host name from configuration.
    host: String,
    /// Target hostname or IP to audit SSL/TLS.
    target_host: String,
    /// Port to connect to for SSL/TLS audit.
    port: u16,
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

impl_common_args!(SshSslAuditArgs);

pub struct SslAuditTool;

impl StandardTool for SslAuditTool {
    type Args = SshSslAuditArgs;

    const NAME: &'static str = "ssh_ssl_audit";

    const DESCRIPTION: &'static str = "Audit SSL/TLS certificate and configuration on a remote target. Prefer this \
        over ssh_exec for SSL inspection as it safely retrieves and displays certificate details \
        including validity, issuer, subject, and expiry using openssl.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "target_host": {
                        "type": "string",
                        "description": "Target hostname or IP to audit SSL/TLS"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port to connect to for SSL/TLS audit (e.g., 443)",
                        "minimum": 1,
                        "maximum": 65535
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
                "required": ["host", "target_host", "port"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn validate(args: &SshSslAuditArgs, _host_config: &HostConfig) -> Result<()> {
        validate_target(&args.target_host)?;
        validate_port(args.port)?;
        Ok(())
    }

    fn build_command(args: &SshSslAuditArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(NetworkSecurityCommandBuilder::build_ssl_audit_command(
            &args.target_host,
            args.port,
        ))
    }
}

/// Handler for the `ssh_ssl_audit` tool.
pub type SshSslAuditHandler = StandardToolHandler<SslAuditTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshSslAuditHandler::new();
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
        let handler = SshSslAuditHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "target_host": "example.com",
                    "port": 443
                })),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshSslAuditHandler::new();
        assert_eq!(handler.name(), "ssh_ssl_audit");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_ssl_audit");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("target_host")));
        assert!(required.contains(&json!("port")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "target_host": "example.com",
            "port": 443,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/ssl_audit.txt"
        });
        let args: SshSslAuditArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.target_host, "example.com");
        assert_eq!(args.port, 443);
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/ssl_audit.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "target_host": "example.com",
            "port": 443
        });
        let args: SshSslAuditArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.target_host, "example.com");
        assert_eq!(args.port, 443);
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshSslAuditHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "server1",
            "target_host": "example.com",
            "port": 443
        });
        let args: SshSslAuditArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshSslAuditArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshSslAuditHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "target_host": 456, "port": "abc"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
