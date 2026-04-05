//! SSH File Write Tool Handler
//!
//! Writes or appends content to a file on a remote host.
//! Uses shell commands for small content and SFTP streaming for large content,
//! bypassing shell `ARG_MAX` limits.

use std::fmt::Write;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};

use crate::domain::output_truncator::truncate_output_with_cache;
use crate::domain::use_cases::file_ops::FileOpsCommandBuilder;
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::security::{AuditEvent, CommandResult as AuditCommandResult};
use crate::ssh::{DEFAULT_CHUNK_SIZE, is_retryable_error, with_retry_if};

use super::utils::{connect_with_jump, save_output_to_file, validate_path};

#[derive(Debug, Deserialize)]
struct SshFileWriteArgs {
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

const SCHEMA: &str = r#"{
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
            "description": "Content to write to the file (no size limit — large content is streamed via SFTP)"
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

/// Handler for the `ssh_file_write` tool.
///
/// Implements a hybrid strategy:
/// - Small content (< `sftp_write_threshold_bytes`): fast shell command via connection pool
/// - Large content (>= threshold): SFTP streaming, bypassing shell `ARG_MAX` limits
pub struct SshFileWriteHandler;

#[async_trait]
impl ToolHandler for SshFileWriteHandler {
    fn name(&self) -> &'static str {
        "ssh_file_write"
    }

    fn description(&self) -> &'static str {
        "Write or append content to a file on a remote host. Use append=true to add to \
         existing files. Creates the file if it does not exist. Content of any size is \
         accepted — large content is streamed via SFTP automatically. For uploading \
         binary files, use ssh_upload instead."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: SCHEMA,
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        // Step 1: Parse args
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshFileWriteArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        // Step 2: Host config lookup
        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        // Step 3: Rate limit
        if ctx.rate_limiter.check(&args.host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{}'. Please wait before sending more requests.",
                args.host
            )));
        }

        // Step 4: Validate path
        validate_path(&args.path)?;
        ctx.validate_root_scope(&args.path)?;

        let append = args.append.unwrap_or(false);
        let threshold = ctx.config.limits.sftp_write_threshold_bytes;
        let use_sftp = threshold == 0 || args.content.len() >= threshold;

        info!(
            host = %args.host,
            path = %args.path,
            content_bytes = args.content.len(),
            append,
            method = if use_sftp { "sftp" } else { "shell" },
            "Writing file"
        );

        let output_text = if use_sftp {
            self.execute_sftp(&args, host_config, ctx, append).await?
        } else {
            self.execute_shell(&args, ctx, append).await?
        };

        // Truncate output for display
        #[allow(clippy::cast_possible_truncation)]
        let max_chars = args
            .max_output
            .map_or(ctx.config.limits.max_output_chars, |v| v as usize);
        let truncated =
            truncate_output_with_cache(&output_text, max_chars, ctx.output_cache.as_deref()).await;

        // Save full output if requested
        let mut final_output = truncated;
        if let Some(save_path) = &args.save_output {
            match save_output_to_file(save_path, &output_text).await {
                Ok(msg) => {
                    let mut combined = final_output;
                    let _ = write!(combined, "\n{msg}");
                    final_output = combined;
                }
                Err(e) => {
                    let mut combined = final_output;
                    let _ = write!(combined, "\nsave_output error: {e}");
                    final_output = combined;
                }
            }
        }

        Ok(ToolCallResult::text(final_output))
    }
}

impl SshFileWriteHandler {
    /// Shell-based write for small content (uses connection pool + retry).
    async fn execute_shell(
        &self,
        args: &SshFileWriteArgs,
        ctx: &ToolContext,
        append: bool,
    ) -> Result<String> {
        let command = FileOpsCommandBuilder::build_write_command(&args.path, &args.content, append);

        // Security validation
        if let Err(e) = ctx.execute_use_case.validate_builtin(&command) {
            let reason = match &e {
                BridgeError::CommandDenied { reason } => reason.clone(),
                _ => e.to_string(),
            };
            ctx.execute_use_case
                .log_denied(&args.host, &command, &reason);
            return Err(e);
        }

        // Timeout override
        let mut limits = ctx.config.limits.clone();
        if let Some(timeout) = args.timeout_seconds {
            limits.command_timeout_seconds = timeout;
        }

        let host = args.host.clone();
        let host_config = ctx.config.hosts.get(&host).expect("host checked above");
        let retry_config = limits.retry_config();
        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jump_config| (jump_name.as_str(), jump_config))
        });

        // Execute with retry
        let output = with_retry_if(
            &retry_config,
            "ssh_file_write",
            async || {
                let mut conn = ctx
                    .connection_pool
                    .get_connection_with_jump(&host, host_config, &limits, jump_host)
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
                .log_failure(&host, &command, &e.to_string());
        })?;

        // Process success (audit + history + sanitize)
        let response = ctx
            .execute_use_case
            .process_success(&host, &command, &output.into());

        if response.exit_code != 0 {
            warn!(
                host = %host,
                tool = "ssh_file_write",
                exit_code = response.exit_code,
                "Tool returned non-zero exit code"
            );
        }

        Ok(response.format_for_llm(&response.stdout))
    }

    /// SFTP-based write for large content (streaming, no shell limits).
    async fn execute_sftp(
        &self,
        args: &SshFileWriteArgs,
        host_config: &crate::config::HostConfig,
        ctx: &ToolContext,
        append: bool,
    ) -> Result<String> {
        let client =
            connect_with_jump(&args.host, host_config, &ctx.config.limits, &ctx.config).await?;

        let sftp = client.sftp_session().await?;

        let result = sftp
            .write_bytes(
                args.content.as_bytes(),
                &args.path,
                append,
                DEFAULT_CHUNK_SIZE,
            )
            .await;

        // Audit log
        match &result {
            Ok(transfer_result) => {
                ctx.audit_logger.log(AuditEvent::new(
                    &args.host,
                    &format!("SFTP_WRITE {}", args.path),
                    AuditCommandResult::Success {
                        exit_code: 0,
                        duration_ms: transfer_result.duration_ms,
                    },
                ));
            }
            Err(e) => {
                ctx.audit_logger.log(AuditEvent::new(
                    &args.host,
                    &format!("SFTP_WRITE {}", args.path),
                    AuditCommandResult::Error {
                        message: e.to_string(),
                    },
                ));
            }
        }

        let transfer_result = result?;

        let mut output = String::new();
        let _ = writeln!(output, "File written successfully via SFTP:");
        let _ = writeln!(output, "  Host: {}", args.host);
        let _ = writeln!(output, "  Path: {}", args.path);
        let _ = writeln!(
            output,
            "  Mode: {}",
            if append { "append" } else { "overwrite" }
        );
        let _ = writeln!(
            output,
            "  Size: {} bytes",
            transfer_result.bytes_transferred
        );
        let _ = writeln!(output, "  Duration: {}ms", transfer_result.duration_ms);
        let _ = writeln!(
            output,
            "  Speed: {:.2} MB/s",
            transfer_result.bytes_per_second / 1_000_000.0
        );

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshFileWriteHandler;
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
        let handler = SshFileWriteHandler;
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
        let handler = SshFileWriteHandler;
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
        let handler = SshFileWriteHandler;
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
        let handler = SshFileWriteHandler;
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_path_traversal_rejected() {
        let handler = SshFileWriteHandler;
        // Path validation happens after host lookup, so we need a host.
        let ctx = crate::ports::mock::create_test_context_with_host();
        let result = handler
            .execute(
                Some(json!({"host": "server1", "path": "/tmp/../etc/passwd", "content": "x"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains(".."));
            }
            e => panic!("Expected FileTransfer error, got: {e:?}"),
        }
    }

    // ============== build_command Tests (shell path) ==============

    #[test]
    fn test_build_command_overwrite() {
        let cmd = FileOpsCommandBuilder::build_write_command("/tmp/test.txt", "hello", false);
        assert!(cmd.contains("> "));
        assert!(!cmd.contains(">>"));
    }

    #[test]
    fn test_build_command_append() {
        let cmd = FileOpsCommandBuilder::build_write_command("/tmp/test.txt", "hello", true);
        assert!(cmd.contains(">>"));
    }

    #[test]
    fn test_description_mentions_sftp() {
        let handler = SshFileWriteHandler;
        assert!(handler.description().contains("SFTP"));
    }
}
