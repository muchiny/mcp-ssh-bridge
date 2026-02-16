//! Handler for the `ssh_win_event_export` tool.
//!
//! Export a Windows Event Log to an `.evtx` file on the remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_event::{WindowsEventCommandBuilder, validate_log_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshWinEventExportArgs {
    host: String,
    log: String,
    file: String,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshWinEventExportArgs);

pub struct WinEventExportTool;

impl StandardTool for WinEventExportTool {
    type Args = SshWinEventExportArgs;

    const NAME: &'static str = "ssh_win_event_export";

    const DESCRIPTION: &'static str = "Export a Windows Event Log to an .evtx file on the remote host using `wevtutil`. The \
        exported file can be transferred with `ssh_download`.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "log", "file"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "log": {
                "type": "string",
                "description": "Event log name (e.g., System, Application, Security, Microsoft-Windows-Sysmon/Operational)"
            },
            "file": {
                "type": "string",
                "description": "Destination file path on the remote host (e.g., C:\\Logs\\export.evtx)"
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

    fn build_command(args: &SshWinEventExportArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsEventCommandBuilder::build_export_command(
            &args.log, &args.file,
        ))
    }

    fn validate(args: &SshWinEventExportArgs, _host_config: &HostConfig) -> Result<()> {
        validate_log_name(&args.log)?;
        Ok(())
    }
}

/// Handler for the `ssh_win_event_export` tool.
pub type SshWinEventExportHandler = StandardToolHandler<WinEventExportTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshWinEventExportHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshWinEventExportHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "log": "Application", "file": "C:\\out.evtx"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshWinEventExportHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_win_event_export");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("log")));
        assert!(required.iter().any(|v| v.as_str() == Some("file")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "log": "Application",
            "file": "C:\\Logs\\export.evtx",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/out.txt"
        });
        let args: SshWinEventExportArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.log, "Application");
        assert_eq!(args.file, "C:\\Logs\\export.evtx");
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output, Some("/tmp/out.txt".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "log": "System", "file": "C:\\out.evtx"});
        let args: SshWinEventExportArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.log, "System");
        assert_eq!(args.file, "C:\\out.evtx");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshWinEventExportHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("file"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "log": "Application", "file": "C:\\out.evtx"});
        let args: SshWinEventExportArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshWinEventExportArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "log": "Application", "file": "C:\\out.evtx"});
        let result = serde_json::from_value::<SshWinEventExportArgs>(json);
        assert!(result.is_err());
    }
}
