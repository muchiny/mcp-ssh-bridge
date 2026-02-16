//! Handler for the `ssh_disk_usage` tool.
//!
//! Shows disk usage and filesystem space on a remote host.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};

use crate::domain::output_truncator::truncate_output_with_cache;
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::ssh::{is_retryable_error, with_retry_if};

/// Shell-escape a string for safe use in shell commands.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Arguments for the `ssh_disk_usage` tool.
#[derive(Debug, Deserialize)]
struct SshDiskUsageArgs {
    /// Target host name from configuration.
    host: String,
    /// Optional path to check disk usage for.
    path: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

/// Handler that shows disk usage and filesystem space on a remote host.
pub struct SshDiskUsageHandler;

#[async_trait]
impl ToolHandler for SshDiskUsageHandler {
    fn name(&self) -> &'static str {
        "ssh_disk_usage"
    }

    fn description(&self) -> &'static str {
        "Show disk usage and filesystem space on a remote host. Without a path, shows all \
         mounted filesystems (df -h). With a path, shows both the directory size (du -sh) \
         and the filesystem it resides on (df -h)."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_disk_usage",
            description: "Show disk usage and filesystem space on a remote host. Without a path, shows all mounted filesystems (df -h). With a path, shows both the directory size (du -sh) and the filesystem it resides on (df -h).",
            input_schema: r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "path": {
                        "type": "string",
                        "description": "Optional path to check disk usage for"
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
            }"#,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshDiskUsageArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        let command = if let Some(ref path) = args.path {
            let escaped_path = shell_escape(path);
            format!("du -sh {escaped_path} && df -h {escaped_path}")
        } else {
            "df -h".to_string()
        };

        if let Err(e) = ctx.execute_use_case.validate_builtin(&command) {
            let reason = match &e {
                BridgeError::CommandDenied { reason } => reason.clone(),
                _ => e.to_string(),
            };
            ctx.execute_use_case
                .log_denied(&args.host, &command, &reason);
            return Err(e);
        }

        if ctx.rate_limiter.check(&args.host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{}'. Please wait before sending more requests.",
                args.host
            )));
        }

        info!(host = %args.host, "Checking disk usage");

        let mut limits = ctx.config.limits.clone();
        if let Some(timeout) = args.timeout_seconds {
            limits.command_timeout_seconds = timeout;
        }
        let retry_config = limits.retry_config();
        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jump_config| (jump_name.as_str(), jump_config))
        });

        let output = with_retry_if(
            &retry_config,
            "ssh_disk_usage",
            async || {
                let mut conn = ctx
                    .connection_pool
                    .get_connection_with_jump(&args.host, host_config, &limits, jump_host)
                    .await?;
                match conn.exec(&command, &limits).await {
                    Ok(output) => Ok(output),
                    Err(e) => {
                        conn.mark_failed();
                        Err(e)
                    }
                }
            },
            is_retryable_error,
        )
        .await;

        let output = output.inspect_err(|e| {
            ctx.execute_use_case
                .log_failure(&args.host, &command, &e.to_string());
        })?;

        let response = ctx
            .execute_use_case
            .process_success(&args.host, &command, &output.into());

        if response.exit_code != 0 {
            warn!(host = %args.host, exit_code = response.exit_code, "ssh_disk_usage failed");
        }

        #[allow(clippy::cast_possible_truncation)]
        let max_chars = args
            .max_output
            .map_or(ctx.config.limits.max_output_chars, |v| v as usize);
        let output_text =
            truncate_output_with_cache(&response.output, max_chars, ctx.output_cache.as_deref())
                .await;

        let mut output_text = output_text;
        if let Some(ref save_path) = args.save_output {
            match crate::mcp::tool_handlers::utils::save_output_to_file(save_path, &response.output)
                .await
            {
                Ok(msg) => output_text = format!("{output_text}\n\n--- {msg} ---"),
                Err(msg) => {
                    output_text = format!("{output_text}\n\n--- save_output error: {msg} ---");
                }
            }
        }

        Ok(ToolCallResult::text(output_text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDiskUsageHandler;
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
        let handler = SshDiskUsageHandler;
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
        let handler = SshDiskUsageHandler;
        assert_eq!(handler.name(), "ssh_disk_usage");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_disk_usage");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/var/log",
            "timeout_seconds": 60,
            "max_output": 5000,
            "save_output": "/tmp/disk.txt"
        });
        let args: SshDiskUsageArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path.as_deref(), Some("/var/log"));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/disk.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshDiskUsageArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.path.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshDiskUsageHandler;
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("path"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshDiskUsageArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshDiskUsageArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshDiskUsageHandler;
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
