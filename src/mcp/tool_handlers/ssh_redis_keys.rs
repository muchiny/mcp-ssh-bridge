//! SSH Redis Keys Tool Handler
//!
//! Scans Redis keys on a remote host using SCAN (non-blocking).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::redis::RedisCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshRedisKeysArgs {
    host: String,
    pattern: Option<String>,
    count: Option<u32>,
    redis_host: Option<String>,
    redis_port: Option<u16>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshRedisKeysArgs);

pub struct RedisKeysTool;

impl StandardTool for RedisKeysTool {
    type Args = SshRedisKeysArgs;

    const NAME: &'static str = "ssh_redis_keys";

    const DESCRIPTION: &'static str = "Scan Redis keys on a remote host using SCAN \
        (non-blocking). Prefer this over ssh_redis_cli with KEYS command as SCAN does not block \
        the server. Finds keys matching a pattern safely in production. Use ssh_redis_cli to \
        read/write specific key values.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "SSH host to connect through"
            },
            "pattern": {
                "type": "string",
                "description": "Key pattern to match (default: *)"
            },
            "count": {
                "type": "integer",
                "description": "Number of keys to return per SCAN iteration"
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

    fn build_command(args: &SshRedisKeysArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(RedisCommandBuilder::build_keys_command(
            args.redis_host.as_deref(),
            args.redis_port,
            args.pattern.as_deref(),
            args.count,
        ))
    }
}

/// Handler for the `ssh_redis_keys` tool.
pub type SshRedisKeysHandler = StandardToolHandler<RedisKeysTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRedisKeysHandler::new();
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
        let handler = SshRedisKeysHandler::new();
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
        let handler = SshRedisKeysHandler::new();
        assert_eq!(handler.name(), "ssh_redis_keys");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_redis_keys");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "pattern": "user:*",
            "count": 100,
            "redis_host": "redis.local",
            "redis_port": 6380,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/keys.txt"
        });
        let args: SshRedisKeysArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.pattern.as_deref(), Some("user:*"));
        assert_eq!(args.count, Some(100));
        assert_eq!(args.redis_host.as_deref(), Some("redis.local"));
        assert_eq!(args.redis_port, Some(6380));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/keys.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost"});
        let args: SshRedisKeysArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert!(args.pattern.is_none());
        assert!(args.count.is_none());
        assert!(args.redis_host.is_none());
        assert!(args.redis_port.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshRedisKeysHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("pattern"));
        assert!(properties.contains_key("count"));
        assert!(properties.contains_key("redis_host"));
        assert!(properties.contains_key("redis_port"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost"});
        let args: SshRedisKeysArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshRedisKeysArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshRedisKeysHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
