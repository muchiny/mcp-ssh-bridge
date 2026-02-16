//! SSH Metrics Tool Handler
//!
//! Collects system metrics from a remote host and returns structured JSON.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

use crate::domain::use_cases::parse_metrics::{self, SECTION_SEPARATOR, SystemMetrics};
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::ssh::{is_retryable_error, with_retry_if};

/// Metric types that can be collected
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum MetricType {
    Cpu,
    Memory,
    Disk,
    Network,
    Load,
}

/// Arguments for `ssh_metrics` tool
#[derive(Debug, Deserialize)]
struct SshMetricsArgs {
    host: String,
    metrics: Vec<MetricType>,
    timeout_seconds: Option<u64>,
}

/// SSH Metrics tool handler
pub struct SshMetricsHandler;

impl SshMetricsHandler {
    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The host alias as defined in the configuration"
            },
            "metrics": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["cpu", "memory", "disk", "network", "load"]
                },
                "description": "Array of metric types to collect",
                "minItems": 1
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            }
        },
        "required": ["host", "metrics"]
    }"#;

    /// Build the compound command that collects all requested metrics.
    /// Each metric section is separated by `SECTION_SEPARATOR`.
    fn build_command(metrics: &[MetricType]) -> String {
        let mut parts = Vec::new();

        for metric in metrics {
            let cmd = match metric {
                MetricType::Cpu => "head -1 /proc/stat; nproc",
                MetricType::Memory => "free -b",
                MetricType::Disk => "df -B1",
                MetricType::Network => "cat /proc/net/dev",
                MetricType::Load => "cat /proc/loadavg; cat /proc/uptime",
            };
            parts.push(cmd.to_string());
        }

        parts.join(&format!("; echo '{SECTION_SEPARATOR}'; "))
    }
}

#[async_trait]
impl ToolHandler for SshMetricsHandler {
    fn name(&self) -> &'static str {
        "ssh_metrics"
    }

    fn description(&self) -> &'static str {
        "Collect system metrics from a single host as structured, parseable JSON. Prefer \
         this over ssh_exec for monitoring as it returns machine-readable data with \
         consistent format. Available metrics: cpu, memory, disk, network, load. For \
         metrics from multiple hosts in parallel, use ssh_metrics_multi instead."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name(),
            description: self.description(),
            input_schema: Self::SCHEMA,
        }
    }

    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        let Some(v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let args: SshMetricsArgs =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        if args.metrics.is_empty() {
            return Err(BridgeError::McpInvalidRequest(
                "metrics array must not be empty".to_string(),
            ));
        }

        // Get host config
        let host_config =
            ctx.config
                .hosts
                .get(&args.host)
                .ok_or_else(|| BridgeError::UnknownHost {
                    host: args.host.clone(),
                })?;

        let command = Self::build_command(&args.metrics);

        // Validate command
        if let Err(e) = ctx.execute_use_case.validate_builtin(&command) {
            let reason = match &e {
                BridgeError::CommandDenied { reason } => reason.clone(),
                _ => e.to_string(),
            };
            ctx.execute_use_case
                .log_denied(&args.host, &command, &reason);
            return Err(e);
        }

        // Check rate limit
        if ctx.rate_limiter.check(&args.host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{}'. Please wait before sending more requests.",
                args.host
            )));
        }

        info!(
            host = %args.host,
            metrics = ?args.metrics,
            "Collecting system metrics"
        );

        // Build limits with optional timeout override
        let mut limits = ctx.config.limits.clone();
        if let Some(timeout) = args.timeout_seconds {
            limits.command_timeout_seconds = timeout;
        }

        let retry_config = limits.retry_config();

        // Resolve jump host
        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jump_config| (jump_name.as_str(), jump_config))
        });

        // Execute with retry
        let output = with_retry_if(
            &retry_config,
            "ssh_metrics",
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

        let system_metrics = parse_sections(&output.stdout, &args.host, &args.metrics);

        // Log in history
        let _ = ctx
            .execute_use_case
            .process_success(&args.host, &command, &output.into());

        // Serialize to JSON and sanitize output
        let json_output = serde_json::to_string_pretty(&system_metrics)
            .unwrap_or_else(|e| format!("Error serializing metrics: {e}"));
        let json_output = ctx.sanitizer.sanitize(&json_output).into_owned();

        Ok(ToolCallResult::text(json_output))
    }
}

/// Parse the raw compound output into structured `SystemMetrics`.
fn parse_sections(stdout: &str, host: &str, metrics: &[MetricType]) -> SystemMetrics {
    let sections: Vec<&str> = stdout.split(SECTION_SEPARATOR).collect();

    let mut sm = SystemMetrics {
        host: host.to_string(),
        cpu: None,
        memory: None,
        disk: None,
        network: None,
        load: None,
    };

    for (i, metric_type) in metrics.iter().enumerate() {
        let section = sections.get(i).unwrap_or(&"").trim();
        match metric_type {
            MetricType::Cpu => sm.cpu = parse_metrics::parse_cpu(section),
            MetricType::Memory => sm.memory = parse_metrics::parse_memory(section),
            MetricType::Disk => sm.disk = parse_metrics::parse_disk(section),
            MetricType::Network => sm.network = parse_metrics::parse_network(section),
            MetricType::Load => sm.load = parse_metrics::parse_load(section),
        }
    }

    sm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[test]
    fn test_schema() {
        let handler = SshMetricsHandler;
        assert_eq!(handler.name(), "ssh_metrics");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("metrics")));
    }

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshMetricsHandler;
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshMetricsHandler;
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "unknown_host",
                    "metrics": ["cpu"]
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "unknown_host");
            }
            e => panic!("Expected UnknownHost error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_builtin_tool_not_denied_in_standard_mode() {
        let handler = SshMetricsHandler;
        let ctx = create_test_context_with_host();

        // In standard mode (default), builtin tools bypass whitelist validation.
        // The command will pass validation but fail at SSH connection (expected).
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "metrics": ["cpu"]
                })),
                &ctx,
            )
            .await;

        // Should NOT be CommandDenied - the builtin tool passes validation
        assert!(result.is_err());
        if let BridgeError::CommandDenied { .. } = result.unwrap_err() {
            panic!("Builtin tool should not be denied in standard mode");
        }
        // Otherwise: SSH connection error is expected in test environment
    }

    #[test]
    fn test_build_command_single_metric() {
        let cmd = SshMetricsHandler::build_command(&[MetricType::Cpu]);
        assert_eq!(cmd, "head -1 /proc/stat; nproc");
    }

    #[test]
    fn test_build_command_multiple_metrics() {
        let cmd = SshMetricsHandler::build_command(&[MetricType::Cpu, MetricType::Memory]);
        assert!(cmd.contains("head -1 /proc/stat; nproc"));
        assert!(cmd.contains(SECTION_SEPARATOR));
        assert!(cmd.contains("free -b"));
    }

    #[test]
    fn test_build_command_all_metrics() {
        let cmd = SshMetricsHandler::build_command(&[
            MetricType::Cpu,
            MetricType::Memory,
            MetricType::Disk,
            MetricType::Network,
            MetricType::Load,
        ]);
        assert!(cmd.contains("head -1 /proc/stat"));
        assert!(cmd.contains("free -b"));
        assert!(cmd.contains("df -B1"));
        assert!(cmd.contains("cat /proc/net/dev"));
        assert!(cmd.contains("cat /proc/loadavg"));
    }
}
