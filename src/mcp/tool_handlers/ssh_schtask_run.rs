//! Handler for the `ssh_schtask_run` tool.
//!
//! Manually run a Windows scheduled task immediately.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::scheduled_task::{ScheduledTaskCommandBuilder, validate_task_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshSchtaskRunArgs {
    host: String,
    name: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshSchtaskRunArgs);

pub struct SchtaskRunTool;

impl StandardTool for SchtaskRunTool {
    type Args = SshSchtaskRunArgs;

    const NAME: &'static str = "ssh_schtask_run";

    const DESCRIPTION: &'static str = "Manually run a Windows scheduled task immediately, regardless of its schedule. Use \
        ssh_schtask_list to discover task names. Use ssh_schtask_info to check triggers and \
        last run result.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "name"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "name": {
                "type": "string",
                "description": "Name of the scheduled task (use ssh_schtask_list to discover names)"
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

    fn build_command(args: &SshSchtaskRunArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(ScheduledTaskCommandBuilder::build_run_command(&args.name))
    }

    fn validate(args: &SshSchtaskRunArgs, _host_config: &HostConfig) -> Result<()> {
        validate_task_name(&args.name)?;
        Ok(())
    }
}

/// Handler for the `ssh_schtask_run` tool.
pub type SshSchtaskRunHandler = StandardToolHandler<SchtaskRunTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshSchtaskRunHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshSchtaskRunHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "name": "MyTask"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshSchtaskRunHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_schtask_run");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "name": "MyTask",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshSchtaskRunArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "MyTask");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "name": "MyTask"});
        let args: SshSchtaskRunArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.name, "MyTask");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshSchtaskRunHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "name": "t"});
        let args: SshSchtaskRunArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshSchtaskRunArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "name": "MyTask"});
        let result = serde_json::from_value::<SshSchtaskRunArgs>(json);
        assert!(result.is_err());
    }
}
