//! SSH `MongoDB` Status Tool Handler
//!
//! Gets `MongoDB` server status on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshMongodbStatusArgs {
    host: String,
    db_port: Option<u16>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshMongodbStatusArgs);

pub struct MongodbStatusTool;

impl StandardTool for MongodbStatusTool {
    type Args = SshMongodbStatusArgs;

    const NAME: &'static str = "ssh_mongodb_status";

    const DESCRIPTION: &'static str = "Get MongoDB server status on a remote host. Returns \
        server version, uptime, connections, and basic metrics. Tries mongosh first, then falls \
        back to the legacy mongo shell. Prefer this over ssh_exec for MongoDB status checks.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "db_port": {
                "type": "integer",
                "description": "MongoDB port (default: 27017)",
                "minimum": 1,
                "maximum": 65535
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds",
                "minimum": 1
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters",
                "minimum": 100
            },
            "save_output": {
                "type": "string",
                "description": "File path to save full output"
            }
        },
        "required": ["host"]
    }"#;

    fn build_command(args: &SshMongodbStatusArgs, _host_config: &HostConfig) -> Result<String> {
        let port = args.db_port.unwrap_or(27017);

        Ok(format!(
            "mongosh --port {port} --eval \
             'db.adminCommand({{serverStatus: 1, metrics: 0, wiredTiger: 0}})' \
             --quiet 2>/dev/null || \
             mongo --port {port} --eval 'db.serverStatus()' --quiet 2>/dev/null || \
             echo 'MongoDB client not found'"
        ))
    }
}

/// Handler for the `ssh_mongodb_status` tool.
pub type SshMongodbStatusHandler = StandardToolHandler<MongodbStatusTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshMongodbStatusHandler::new();
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
        let handler = SshMongodbStatusHandler::new();
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
        let handler = SshMongodbStatusHandler::new();
        assert_eq!(handler.name(), "ssh_mongodb_status");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_mongodb_status");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "db_port": 27018,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/mongo_status.txt"
        });
        let args: SshMongodbStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.db_port, Some(27018));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/mongo_status.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshMongodbStatusArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.db_port.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshMongodbStatusHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("db_port"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost"});
        let args: SshMongodbStatusArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshMongodbStatusArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshMongodbStatusHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
