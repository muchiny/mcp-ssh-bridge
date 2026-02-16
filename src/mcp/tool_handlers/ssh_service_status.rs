//! Handler for the `ssh_service_status` tool.
//!
//! Shows the status of a systemd service on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::systemd::{SystemdCommandBuilder, validate_service_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshServiceStatusArgs {
    host: String,
    service: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshServiceStatusArgs);

pub struct ServiceStatusTool;

impl StandardTool for ServiceStatusTool {
    type Args = SshServiceStatusArgs;

    const NAME: &'static str = "ssh_service_status";

    const DESCRIPTION: &'static str = "Show the status of a systemd service on a remote host. Prefer this over ssh_exec as \
        it provides structured output with active state, loaded state, PID, memory usage, and \
        recent log entries. Use ssh_service_list first to discover available services. Use \
        ssh_service_logs for detailed log history.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "service"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "service": {
                "type": "string",
                "description": "Name of the systemd service (e.g., nginx, sshd, docker)"
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

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshServiceStatusArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(SystemdCommandBuilder::build_status_command(&args.service))
    }

    fn validate(args: &SshServiceStatusArgs, _host_config: &HostConfig) -> Result<()> {
        validate_service_name(&args.service)?;
        Ok(())
    }
}

/// Handler for the `ssh_service_status` tool.
pub type SshServiceStatusHandler = StandardToolHandler<ServiceStatusTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshServiceStatusHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshServiceStatusHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "service": "nginx"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshServiceStatusHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_service_status");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("service")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "service": "nginx",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshServiceStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.service, "nginx");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "service": "nginx"});
        let args: SshServiceStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.service, "nginx");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshServiceStatusHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "service": "s"});
        let args: SshServiceStatusArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshServiceStatusArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "service": "nginx"});
        let result = serde_json::from_value::<SshServiceStatusArgs>(json);
        assert!(result.is_err());
    }
}
