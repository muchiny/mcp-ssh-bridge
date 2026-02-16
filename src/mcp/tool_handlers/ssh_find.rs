//! Handler for the `ssh_find` tool.
//!
//! Finds files and directories on a remote host using the `find` command.

use std::fmt::Write;

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

/// Arguments for the `ssh_find` tool.
#[derive(Debug, Deserialize)]
struct SshFindArgs {
    /// Target host name from configuration.
    host: String,
    /// The search root path.
    path: String,
    /// File name pattern (e.g., "*.log").
    name: Option<String>,
    /// File type filter: f (regular file), d (directory), l (symlink).
    #[serde(rename = "type")]
    file_type: Option<String>,
    /// Maximum directory depth (default: 5).
    max_depth: Option<u32>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

/// Handler that finds files and directories on a remote host.
pub struct SshFindHandler;

/// Build the `find` command string from parsed arguments.
fn build_find_command(args: &SshFindArgs) -> String {
    let mut cmd = format!("find {}", shell_escape(&args.path));

    if let Some(depth) = args.max_depth {
        write!(cmd, " -maxdepth {depth}").unwrap();
    } else {
        write!(cmd, " -maxdepth 5").unwrap();
    }

    if let Some(ref name) = args.name {
        write!(cmd, " -name {}", shell_escape(name)).unwrap();
    }

    if let Some(ref ft) = args.file_type {
        write!(cmd, " -type {}", shell_escape(ft)).unwrap();
    }

    cmd.push_str(" 2>/dev/null");
    cmd
}

#[async_trait]
impl ToolHandler for SshFindHandler {
    fn name(&self) -> &'static str {
        "ssh_find"
    }

    fn description(&self) -> &'static str {
        "Find files and directories on a remote host. Wraps the find command with safe \
         escaping and a default max depth of 5 to prevent excessive traversal. Use name \
         for glob patterns (e.g., '*.log') and type for filtering (f=files, d=directories)."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "ssh_find",
            description: "Find files and directories on a remote host. Wraps the find command with safe escaping and a default max depth of 5 to prevent excessive traversal. Use name for glob patterns (e.g., '*.log') and type for filtering (f=files, d=directories).",
            input_schema: r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "path": {
                        "type": "string",
                        "description": "The search root path"
                    },
                    "name": {
                        "type": "string",
                        "description": "File name pattern for -name (e.g., '*.log')"
                    },
                    "type": {
                        "type": "string",
                        "description": "File type filter: f (regular file), d (directory), l (symlink)"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum directory depth (default: 5)",
                        "minimum": 1,
                        "maximum": 20
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
                "required": ["host", "path"]
            }"#,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshFindArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        let command = build_find_command(&args);

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

        info!(host = %args.host, path = %args.path, "Finding files");

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
            "ssh_find",
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
            warn!(host = %args.host, exit_code = response.exit_code, "ssh_find failed");
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
        let handler = SshFindHandler;
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
        let handler = SshFindHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "path": "/var/log"})),
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
        let handler = SshFindHandler;
        assert_eq!(handler.name(), "ssh_find");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_find");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("path")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "path": "/var/log",
            "name": "*.log",
            "type": "f",
            "max_depth": 3,
            "timeout_seconds": 60,
            "max_output": 5000,
            "save_output": "/tmp/find.txt"
        });
        let args: SshFindArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/var/log");
        assert_eq!(args.name.as_deref(), Some("*.log"));
        assert_eq!(args.file_type.as_deref(), Some("f"));
        assert_eq!(args.max_depth, Some(3));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/find.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "path": "/var/log"});
        let args: SshFindArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.path, "/var/log");
        assert!(args.name.is_none());
        assert!(args.file_type.is_none());
        assert!(args.max_depth.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshFindHandler;
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("name"));
        assert!(props.contains_key("type"));
        assert!(props.contains_key("max_depth"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "path": "/var/log"});
        let args: SshFindArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshFindArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshFindHandler;
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "path": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
