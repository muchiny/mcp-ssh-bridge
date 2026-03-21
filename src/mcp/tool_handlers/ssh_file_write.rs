//! SSH File Write Tool Handler
//!
//! Writes or appends content to a file on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::file_ops::FileOpsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshFileWriteArgs {
    host: String,
    path: String,
    content: String,
    #[serde(default)]
    append: Option<bool>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshFileWriteArgs);

pub struct FileWriteTool;

impl StandardTool for FileWriteTool {
    type Args = SshFileWriteArgs;

    const NAME: &'static str = "ssh_file_write";

    const DESCRIPTION: &'static str = "Write or append content to a file on a remote host. Use \
        append=true to add to existing files. Creates the file if it does not exist. For \
        uploading binary files, use ssh_upload instead.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "path": {
                "type": "string",
                "description": "Absolute path of the file to write on the remote host"
            },
            "content": {
                "type": "string",
                "description": "Content to write to the file"
            },
            "append": {
                "type": "boolean",
                "description": "Append to existing file instead of overwriting (default: false)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "path", "content"]
    }"#;

    fn build_command(args: &SshFileWriteArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(FileOpsCommandBuilder::build_write_command(
            &args.path,
            &args.content,
            args.append.unwrap_or(false),
        ))
    }
}

/// Handler for the `ssh_file_write` tool.
pub type SshFileWriteHandler = StandardToolHandler<FileWriteTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFileWriteHandler::new();
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
        let handler = SshFileWriteHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "/tmp/test", "content": "hello"})),
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
        let handler = SshFileWriteHandler::new();
        assert_eq!(handler.name(), "ssh_file_write");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_file_write");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
        assert!(required.contains(&json!("content")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/tmp/test.txt",
            "content": "hello world",
            "append": true,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/output.txt"
        });
        let args: SshFileWriteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/tmp/test.txt");
        assert_eq!(args.content, "hello world");
        assert_eq!(args.append, Some(true));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/tmp/test.txt", "content": "data"});
        let args: SshFileWriteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/tmp/test.txt");
        assert_eq!(args.content, "data");
        assert!(args.append.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshFileWriteHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("append"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/tmp/test", "content": "x"});
        let args: SshFileWriteArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshFileWriteArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshFileWriteHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    // ============== build_command Tests ==============

    use crate::config::{HostConfig, HostKeyVerification, OsType};

    fn test_host_config() -> HostConfig {
        HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::default(),
            shell: None,
            retry: None,
        }
    }

    #[test]
    fn test_build_command_overwrite() {
        let args = SshFileWriteArgs {
            host: "server1".to_string(),
            path: "/tmp/test.txt".to_string(),
            content: "hello".to_string(),
            append: None,
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FileWriteTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains("> "));
        assert!(!cmd.contains(">>"));
    }

    #[test]
    fn test_build_command_append() {
        let args = SshFileWriteArgs {
            host: "server1".to_string(),
            path: "/tmp/test.txt".to_string(),
            content: "hello".to_string(),
            append: Some(true),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
        };
        let cmd = FileWriteTool::build_command(&args, &test_host_config()).unwrap();
        assert!(cmd.contains(">>"));
    }
}
