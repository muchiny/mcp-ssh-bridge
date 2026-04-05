//! Handler for the `ssh_storage_df` tool.
//!
//! Shows disk space usage on a remote host.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::storage::StorageCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshStorageDfArgs {
    /// Target host name from configuration.
    host: String,
    /// Optional path to check disk usage for.
    #[serde(default)]
    path: Option<String>,
    /// Show inode usage instead of block usage.
    #[serde(default)]
    inodes: Option<bool>,
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

impl_common_args!(SshStorageDfArgs);

pub struct StorageDfTool;

impl StandardTool for StorageDfTool {
    type Args = SshStorageDfArgs;

    const NAME: &'static str = "ssh_storage_df";

    const DESCRIPTION: &'static str = "Show disk space usage on a remote host. Displays \
        filesystem type, size, used, available, and mount point. Set inodes=true for inode usage.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "path": {
                        "type": "string",
                        "description": "Optional path to check disk usage for a specific filesystem"
                    },
                    "inodes": {
                        "type": "boolean",
                        "description": "Show inode usage instead of block usage"
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
                "required": ["host"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind = crate::domain::output_kind::OutputKind::Tabular;

    fn build_command(args: &SshStorageDfArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(StorageCommandBuilder::build_df_command(
            args.path.as_deref(),
            args.inodes.unwrap_or(false),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshStorageDfArgs,
        output: &str,
        dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let parsed = super::utils::maybe_select_columns(parsed, dr);
        let mut tbl = table("Disk Usage");
        for h in &parsed.headers {
            tbl = tbl.column(h, h.to_uppercase());
        }
        for row in &parsed.rows {
            let first = row.first().map_or("", String::as_str);
            if first.is_empty() {
                continue;
            }
            let mut obj = serde_json::Map::new();
            for (i, h) in parsed.headers.iter().enumerate() {
                obj.insert(
                    h.clone(),
                    serde_json::Value::String(row.get(i).map_or_else(String::new, Clone::clone)),
                );
            }
            tbl = tbl.row(serde_json::Value::Object(obj));
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_storage_df",
            Some(json!({"host": args.host})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_storage_df` tool.
pub type SshStorageDfHandler = StandardToolHandler<StorageDfTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshStorageDfHandler::new();
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
        let handler = SshStorageDfHandler::new();
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
        let handler = SshStorageDfHandler::new();
        assert_eq!(handler.name(), "ssh_storage_df");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_storage_df");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/var",
            "inodes": true,
            "timeout_seconds": 15,
            "max_output": 5000,
            "save_output": "/tmp/df.txt"
        });
        let args: SshStorageDfArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path.as_deref(), Some("/var"));
        assert_eq!(args.inodes, Some(true));
        assert_eq!(args.timeout_seconds, Some(15));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/df.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshStorageDfArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.path.is_none());
        assert!(args.inodes.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshStorageDfHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("path"));
        assert!(props.contains_key("inodes"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshStorageDfArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshStorageDfArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshStorageDfHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
