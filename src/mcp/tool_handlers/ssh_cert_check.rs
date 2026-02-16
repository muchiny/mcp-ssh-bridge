//! SSH Certificate Check Tool Handler
//!
//! Checks a remote TLS/SSL certificate from a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::certificate::CertificateCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshCertCheckArgs {
    host: String,
    target: String,
    port: Option<u16>,
    servername: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshCertCheckArgs);

pub struct CertCheckTool;

impl StandardTool for CertCheckTool {
    type Args = SshCertCheckArgs;

    const NAME: &'static str = "ssh_cert_check";

    const DESCRIPTION: &'static str = "Check a remote TLS/SSL certificate by connecting to a \
        host:port from a remote host. Use this to verify HTTPS certificates of live services. \
        Returns subject, issuer, validity dates, and fingerprint. For inspecting local \
        certificate files, use ssh_cert_info instead. For expiry monitoring, use ssh_cert_expiry.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "SSH host to connect through"
            },
            "target": {
                "type": "string",
                "description": "Target hostname to check certificate for"
            },
            "port": {
                "type": "integer",
                "description": "Target port (default: 443)"
            },
            "servername": {
                "type": "string",
                "description": "SNI server name override"
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

    fn build_command(args: &SshCertCheckArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(CertificateCommandBuilder::build_check_command(
            &args.target,
            args.port,
            args.servername.as_deref(),
        ))
    }
}

/// Handler for the `ssh_cert_check` tool.
pub type SshCertCheckHandler = StandardToolHandler<CertCheckTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCertCheckHandler::new();
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
        let handler = SshCertCheckHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "target": "example.com"})),
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
        let handler = SshCertCheckHandler::new();
        assert_eq!(handler.name(), "ssh_cert_check");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_cert_check");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("target")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "target": "example.com",
            "port": 8443,
            "servername": "sni.example.com",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/cert.txt"
        });
        let args: SshCertCheckArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "example.com");
        assert_eq!(args.port, Some(8443));
        assert_eq!(args.servername.as_deref(), Some("sni.example.com"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/cert.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "target": "example.com"});
        let args: SshCertCheckArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.target, "example.com");
        assert!(args.port.is_none());
        assert!(args.servername.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCertCheckHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("port"));
        assert!(properties.contains_key("servername"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "target": "example.com"});
        let args: SshCertCheckArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCertCheckArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCertCheckHandler::new();
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
