//! SSH Nginx List Sites Tool Handler
//!
//! Lists enabled sites/virtual hosts on a remote web server.

use serde::Deserialize;

use crate::config::{HostConfig, OsType};
use crate::domain::use_cases::nginx::NginxCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshNginxListSitesArgs {
    host: String,
    server: Option<String>,
    config_dir: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshNginxListSitesArgs);

pub struct NginxListSitesTool;

impl StandardTool for NginxListSitesTool {
    type Args = SshNginxListSitesArgs;

    const NAME: &'static str = "ssh_nginx_list_sites";

    const DESCRIPTION: &'static str = "List enabled sites/virtual hosts on a remote web server. \
        Prefer this over ssh_exec as it auto-detects the config directory for nginx or apache. \
        Shows files in sites-enabled or conf.d. Use ssh_nginx_status to check the server state.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "SSH host to connect through"
            },
            "server": {
                "type": "string",
                "description": "Web server name: nginx, apache2, httpd (default: auto-detect)"
            },
            "config_dir": {
                "type": "string",
                "description": "Custom configuration directory path"
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
        "required": ["host"]
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshNginxListSitesArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(NginxCommandBuilder::build_list_sites_command(
            args.server.as_deref(),
            args.config_dir.as_deref(),
        ))
    }
}

/// Handler for the `ssh_nginx_list_sites` tool.
pub type SshNginxListSitesHandler = StandardToolHandler<NginxListSitesTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshNginxListSitesHandler::new();
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
        let handler = SshNginxListSitesHandler::new();
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
        let handler = SshNginxListSitesHandler::new();
        assert_eq!(handler.name(), "ssh_nginx_list_sites");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_nginx_list_sites");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "server": "nginx",
            "config_dir": "/etc/nginx/sites-enabled",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/sites.txt"
        });
        let args: SshNginxListSitesArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.server.as_deref(), Some("nginx"));
        assert_eq!(args.config_dir.as_deref(), Some("/etc/nginx/sites-enabled"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/sites.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshNginxListSitesArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.server.is_none());
        assert!(args.config_dir.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshNginxListSitesHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("server"));
        assert!(properties.contains_key("config_dir"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost"});
        let args: SshNginxListSitesArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshNginxListSitesArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshNginxListSitesHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
