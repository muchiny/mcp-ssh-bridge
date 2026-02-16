//! SSH Certificate Expiry Tool Handler
//!
//! Checks TLS/SSL certificate expiry on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::certificate::CertificateCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshCertExpiryArgs {
    host: String,
    target: String,
    is_file: Option<bool>,
    days: Option<u32>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshCertExpiryArgs);

pub struct CertExpiryTool;

impl StandardTool for CertExpiryTool {
    type Args = SshCertExpiryArgs;

    const NAME: &'static str = "ssh_cert_expiry";

    const DESCRIPTION: &'static str = "Check TLS/SSL certificate expiry from a remote host. \
        Verifies if a certificate (local file or remote service) will expire within a given \
        number of days. Returns expiry date and whether the certificate is still valid. Use \
        ssh_cert_check for full certificate details or ssh_cert_info for local file inspection.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "SSH host to connect through"
            },
            "target": {
                "type": "string",
                "description": "Certificate file path or host:port to check"
            },
            "is_file": {
                "type": "boolean",
                "description": "True if target is a file path, false for remote host:port (default: false)"
            },
            "days": {
                "type": "integer",
                "description": "Days threshold for expiry warning (default: 30)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters"
            },
            "save_output": {
                "type": "string",
                "description": "File path to save full output"
            }
        },
        "required": ["host", "target"]
    }"#;

    fn build_command(args: &SshCertExpiryArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(CertificateCommandBuilder::build_expiry_command(
            &args.target,
            args.is_file.unwrap_or(false),
            args.days,
        ))
    }
}

/// Handler for the `ssh_cert_expiry` tool.
pub type SshCertExpiryHandler = StandardToolHandler<CertExpiryTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCertExpiryHandler::new();
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
        let handler = SshCertExpiryHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "target": "example.com:443"})),
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
        let handler = SshCertExpiryHandler::new();
        assert_eq!(handler.name(), "ssh_cert_expiry");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_cert_expiry");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("target")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "target": "example.com:443",
            "is_file": false,
            "days": 60,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/expiry.txt"
        });
        let args: SshCertExpiryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "example.com:443");
        assert_eq!(args.is_file, Some(false));
        assert_eq!(args.days, Some(60));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/expiry.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "target": "example.com:443"});
        let args: SshCertExpiryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "example.com:443");
        assert!(args.is_file.is_none());
        assert!(args.days.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCertExpiryHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("is_file"));
        assert!(properties.contains_key("days"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "target": "example.com:443"});
        let args: SshCertExpiryArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCertExpiryArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCertExpiryHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "target": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
