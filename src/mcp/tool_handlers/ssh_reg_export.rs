//! Handler for the `ssh_reg_export` tool.
//!
//! Exports a Windows Registry key to a `.reg` file via `reg.exe`.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::windows_registry::{
    WindowsRegistryCommandBuilder, validate_file_path,
};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshRegExportArgs {
    host: String,
    key: String,
    file: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshRegExportArgs);

pub struct RegExportTool;

impl StandardTool for RegExportTool {
    type Args = SshRegExportArgs;

    const NAME: &'static str = "ssh_reg_export";

    const DESCRIPTION: &'static str = "Export a Windows Registry key to a `.reg` file on the remote host. The file can be \
        used for backup or to import on another machine.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "key", "file"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Target host name (must match a configured host)"
            },
            "key": {
                "type": "string",
                "description": "Registry key to export (e.g., HKLM\\SOFTWARE\\MyApp)"
            },
            "file": {
                "type": "string",
                "description": "Destination file path on the remote host (e.g., C:\\backup\\myapp.reg)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Windows);

    fn build_command(args: &SshRegExportArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(WindowsRegistryCommandBuilder::export_key(
            &args.key, &args.file,
        ))
    }

    fn validate(args: &SshRegExportArgs, _host_config: &HostConfig) -> Result<()> {
        validate_file_path(&args.file)?;
        Ok(())
    }
}

/// Handler for the `ssh_reg_export` tool.
pub type SshRegExportHandler = StandardToolHandler<RegExportTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRegExportHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshRegExportHandler::new();
        let ctx = create_test_context();
        let args = json!({
            "host": "nonexistent",
            "key": "HKLM\\SOFTWARE\\MyApp",
            "file": "C:\\backup.reg"
        });
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshRegExportHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_reg_export");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("key")));
        assert!(required.iter().any(|v| v.as_str() == Some("file")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "key": "HKLM\\SOFTWARE\\MyApp",
            "file": "C:\\backup\\myapp.reg",
            "timeout_seconds": 60,
            "max_output": 10000
        });
        let args: SshRegExportArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.key, "HKLM\\SOFTWARE\\MyApp");
        assert_eq!(args.file, "C:\\backup\\myapp.reg");
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "myhost",
            "key": "HKLM\\SOFTWARE\\MyApp",
            "file": "C:\\backup.reg"
        });
        let args: SshRegExportArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.key, "HKLM\\SOFTWARE\\MyApp");
        assert_eq!(args.file, "C:\\backup.reg");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshRegExportHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({
            "host": "h",
            "key": "HKLM\\SOFTWARE",
            "file": "C:\\out.reg"
        });
        let args: SshRegExportArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshRegExportArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({
            "host": 123,
            "key": "HKLM\\SOFTWARE",
            "file": "C:\\out.reg"
        });
        let result = serde_json::from_value::<SshRegExportArgs>(json);
        assert!(result.is_err());
    }
}
