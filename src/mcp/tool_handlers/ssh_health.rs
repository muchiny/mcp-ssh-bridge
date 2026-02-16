//! SSH Health Tool Handler
//!
//! Provides diagnostic information about the internal state of the MCP server,
//! including connection pool stats, active sessions, and system health.

use std::fmt::Write;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;
use crate::mcp::protocol::ToolCallResult;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};

/// SSH Health diagnostic tool handler
#[derive(Default)]
pub struct SshHealthHandler;

impl SshHealthHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {},
        "required": []
    }"#;
}

#[async_trait]
impl ToolHandler for SshHealthHandler {
    fn name(&self) -> &'static str {
        "ssh_health"
    }

    fn description(&self) -> &'static str {
        "Get diagnostic information about the SSH bridge internal state. Returns JSON with: \
         connection pool stats per host, active persistent sessions, command history summary, \
         and current configuration. Use this to troubleshoot connection issues or verify \
         bridge health."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, _args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let mut result = String::new();

        // Connection Pool Stats
        result.push_str("=== Connection Pool ===\n");
        let pool_stats = ctx.connection_pool.stats().await;
        let _ = writeln!(
            result,
            "Total pooled connections: {}",
            pool_stats.total_connections
        );
        if pool_stats.connections_by_host.is_empty() {
            result.push_str("  (no connections in pool)\n");
        } else {
            for (host, count) in &pool_stats.connections_by_host {
                let _ = writeln!(result, "  {host}: {count} connection(s)");
            }
        }
        result.push('\n');

        // Active Sessions
        result.push_str("=== Active Sessions ===\n");
        let sessions = ctx.session_manager.list().await;
        let _ = writeln!(result, "Total active sessions: {}", sessions.len());
        if sessions.is_empty() {
            result.push_str("  (no active sessions)\n");
        } else {
            for session in &sessions {
                let _ = writeln!(
                    result,
                    "  {} ({}): cwd={}, age={}s, idle={}s",
                    session.id,
                    session.host,
                    session.cwd,
                    session.created_at_secs_ago,
                    session.last_used_secs_ago
                );
            }
        }
        result.push('\n');

        // Command History Stats
        result.push_str("=== Command History ===\n");
        let history_entries = ctx.history.recent(1000); // Get up to 1000 entries
        let _ = writeln!(result, "Commands in history: {}", history_entries.len());

        // Count by host
        let mut by_host: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut success_count = 0;
        let mut failure_count = 0;
        for entry in &history_entries {
            *by_host.entry(entry.host.clone()).or_insert(0) += 1;
            if entry.exit_code == 0 {
                success_count += 1;
            } else {
                failure_count += 1;
            }
        }
        let _ = writeln!(result, "  Successful: {success_count}");
        let _ = writeln!(result, "  Failed: {failure_count}");
        if !by_host.is_empty() {
            result.push_str("  By host:\n");
            for (host, count) in &by_host {
                let _ = writeln!(result, "    {host}: {count}");
            }
        }
        result.push('\n');

        // Configuration Summary
        result.push_str("=== Configuration ===\n");
        let _ = writeln!(result, "Configured hosts: {}", ctx.config.hosts.len());
        let _ = writeln!(result, "Security mode: {:?}", ctx.config.security.mode);
        let _ = writeln!(
            result,
            "Command timeout: {}s",
            ctx.config.limits.command_timeout_seconds
        );
        let _ = writeln!(
            result,
            "Connection timeout: {}s",
            ctx.config.limits.connection_timeout_seconds
        );
        let _ = writeln!(
            result,
            "Max concurrent commands: {}",
            ctx.config.limits.max_concurrent_commands
        );
        let _ = writeln!(
            result,
            "Rate limit: {} req/s",
            ctx.config.limits.rate_limit_per_second
        );

        Ok(ToolCallResult::text(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::protocol::ToolContent;
    use crate::ports::mock::create_test_context;

    fn get_text_content(result: &ToolCallResult) -> &str {
        match &result.content[0] {
            ToolContent::Text { text } => text,
            _ => panic!("Expected Text content"),
        }
    }

    #[tokio::test]
    async fn test_ssh_health_returns_all_sections() {
        let handler = SshHealthHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await.unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("=== Connection Pool ==="));
        assert!(text.contains("=== Active Sessions ==="));
        assert!(text.contains("=== Command History ==="));
        assert!(text.contains("=== Configuration ==="));
    }

    #[tokio::test]
    async fn test_ssh_health_shows_empty_state() {
        let handler = SshHealthHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await.unwrap();
        let text = get_text_content(&result);

        assert!(text.contains("Total pooled connections: 0"));
        assert!(text.contains("Total active sessions: 0"));
        assert!(text.contains("Commands in history: 0"));
    }

    #[test]
    fn test_schema() {
        let handler = SshHealthHandler;
        assert_eq!(handler.name(), "ssh_health");
        assert!(handler.description().contains("diagnostic"));

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_health");
    }

    #[test]
    fn test_schema_json_valid() {
        let handler = SshHealthHandler;
        let schema = handler.schema();

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[tokio::test]
    async fn test_ssh_health_shows_config_details() {
        let handler = SshHealthHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await.unwrap();
        let text = get_text_content(&result);

        // Verify configuration section shows key settings
        assert!(text.contains("Configured hosts:"));
        assert!(text.contains("Security mode:"));
        assert!(text.contains("Command timeout:"));
        assert!(text.contains("Connection timeout:"));
        assert!(text.contains("Max concurrent commands:"));
        assert!(text.contains("Rate limit:"));
    }

    #[tokio::test]
    async fn test_ssh_health_shows_history_stats() {
        let handler = SshHealthHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await.unwrap();
        let text = get_text_content(&result);

        // Verify history stats
        assert!(text.contains("Successful:"));
        assert!(text.contains("Failed:"));
    }

    #[test]
    fn test_handler_default_impl() {
        let handler = SshHealthHandler;
        assert_eq!(handler.name(), "ssh_health");
    }
}
