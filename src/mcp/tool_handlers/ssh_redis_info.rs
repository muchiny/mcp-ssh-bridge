//! SSH Redis Info Tool Handler
//!
//! Gets Redis server information on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::redis::RedisCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshRedisInfoArgs {
    host: String,
    redis_host: Option<String>,
    redis_port: Option<u16>,
    section: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshRedisInfoArgs);

pub struct RedisInfoTool;

impl StandardTool for RedisInfoTool {
    type Args = SshRedisInfoArgs;

    const NAME: &'static str = "ssh_redis_info";

    const DESCRIPTION: &'static str = "Get Redis server information on a remote host. Prefer \
        this over ssh_exec as it handles authentication and connection parameters. Returns server \
        stats, memory usage, clients, replication status, and keyspace details. Optionally filter \
        by section. Use ssh_redis_keys to browse keys or ssh_redis_cli for ad-hoc commands.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "SSH host to connect through"
            },
            "redis_host": {
                "type": "string",
                "description": "Redis server hostname (default: localhost)"
            },
            "redis_port": {
                "type": "integer",
                "description": "Redis server port (default: 6379)",
                "default": 6379,
                "minimum": 1,
                "maximum": 65535
            },
            "section": {
                "type": "string",
                "description": "Info section to retrieve (default: all sections)",
                "enum": ["server", "clients", "memory", "stats", "replication", "cpu", "keyspace", "all"]
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

    fn build_command(args: &SshRedisInfoArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(RedisCommandBuilder::build_info_command(
            args.redis_host.as_deref(),
            args.redis_port,
            args.section.as_deref(),
        ))
    }
}

/// Handler for the `ssh_redis_info` tool.
pub type SshRedisInfoHandler = StandardToolHandler<RedisInfoTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRedisInfoHandler::new();
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
        let handler = SshRedisInfoHandler::new();
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
        let handler = SshRedisInfoHandler::new();
        assert_eq!(handler.name(), "ssh_redis_info");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_redis_info");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "redis_host": "redis.local",
            "redis_port": 6380,
            "section": "memory",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/redis_info.txt"
        });
        let args: SshRedisInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.redis_host.as_deref(), Some("redis.local"));
        assert_eq!(args.redis_port, Some(6380));
        assert_eq!(args.section.as_deref(), Some("memory"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/redis_info.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshRedisInfoArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.redis_host.is_none());
        assert!(args.redis_port.is_none());
        assert!(args.section.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshRedisInfoHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("redis_host"));
        assert!(properties.contains_key("redis_port"));
        assert!(properties.contains_key("section"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost"});
        let args: SshRedisInfoArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshRedisInfoArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshRedisInfoHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
