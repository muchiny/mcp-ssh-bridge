//! Handler for the `ssh_iis_restart` tool.
//!
//! Restarts an IIS application pool by name.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::iis::{IisCommandBuilder, validate_site_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshIisRestartArgs {
    host: String,
    name: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshIisRestartArgs);

pub struct IisRestartTool;

impl StandardTool for IisRestartTool {
    type Args = SshIisRestartArgs;

    const NAME: &'static str = "ssh_iis_restart";

    const DESCRIPTION: &'static str = "Restart (recycle) an IIS application pool on a Windows host by name. Use \
        ssh_iis_list_pools to discover pool names. Idempotent and safe to retry.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "name"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured Windows host)"
            },
            "name": {
                "type": "string",
                "description": "Name of the IIS website or application pool"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the local machine"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshIisRestartArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(IisCommandBuilder::build_restart_pool_command(&args.name))
    }

    fn validate(args: &SshIisRestartArgs, _host_config: &HostConfig) -> Result<()> {
        validate_site_name(&args.name)?;
        Ok(())
    }
}

/// Handler for the `ssh_iis_restart` tool.
pub type SshIisRestartHandler = StandardToolHandler<IisRestartTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshIisRestartHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshIisRestartHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "name": "DefaultAppPool"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshIisRestartHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_iis_restart");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "name": "DefaultAppPool",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshIisRestartArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "DefaultAppPool");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "name": "DefaultAppPool"});
        let args: SshIisRestartArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "DefaultAppPool");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshIisRestartHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "name": "s"});
        let args: SshIisRestartArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshIisRestartArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "name": "DefaultAppPool"});
        let result = serde_json::from_value::<SshIisRestartArgs>(json);
        assert!(result.is_err());
    }
}
