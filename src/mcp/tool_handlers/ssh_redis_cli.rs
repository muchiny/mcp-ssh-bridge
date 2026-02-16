//! SSH Redis CLI Tool Handler
//!
//! Executes a Redis CLI command on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::redis::RedisCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshRedisCliArgs {
    host: String,
    command: String,
    redis_host: Option<String>,
    redis_port: Option<u16>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshRedisCliArgs);

pub struct RedisCliTool;

impl StandardTool for RedisCliTool {
    type Args = SshRedisCliArgs;

    const NAME: &'static str = "ssh_redis_cli";

    const DESCRIPTION: &'static str = "Execute a Redis CLI command on a remote host. Prefer \
        this over ssh_exec as it handles authentication and database selection. Runs any \
        redis-cli command (GET, SET, DEL, HGETALL, LRANGE, etc.). Use ssh_redis_info for \
        server stats or ssh_redis_keys to browse keys safely.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "SSH host to connect through"
            },
            "command": {
                "type": "string",
                "description": "Redis command to execute (e.g., 'GET mykey', 'SET key value')"
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
        "required": ["host", "command"]
    }"#;

    fn build_command(args: &SshRedisCliArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(RedisCommandBuilder::build_cli_command(
            args.redis_host.as_deref(),
            args.redis_port,
            &args.command,
        ))
    }

    fn validate(args: &SshRedisCliArgs, _host_config: &HostConfig) -> Result<()> {
        RedisCommandBuilder::validate_redis_command(&args.command)
    }
}

/// Handler for the `ssh_redis_cli` tool.
pub type SshRedisCliHandler = StandardToolHandler<RedisCliTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshRedisCliHandler::new();
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
        let handler = SshRedisCliHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "command": "GET mykey"})),
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
        let handler = SshRedisCliHandler::new();
        assert_eq!(handler.name(), "ssh_redis_cli");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_redis_cli");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "command": "GET mykey",
            "redis_host": "redis.local",
            "redis_port": 6380,
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/redis_cli.txt"
        });
        let args: SshRedisCliArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.command, "GET mykey");
        assert_eq!(args.redis_host.as_deref(), Some("redis.local"));
        assert_eq!(args.redis_port, Some(6380));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/redis_cli.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "command": "PING"});
        let args: SshRedisCliArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.command, "PING");
        assert!(args.redis_host.is_none());
        assert!(args.redis_port.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshRedisCliHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("redis_host"));
        assert!(properties.contains_key("redis_port"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "command": "PING"});
        let args: SshRedisCliArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshRedisCliArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshRedisCliHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "command": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
