//! SSH Diagnose Tool Handler
//!
//! Comprehensive single-call host diagnostic combining CPU, memory, disk,
//! processes, services, errors, and network in one compound command.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::diagnostics::DiagnosticsCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::mcp_standard_tool;
use crate::ports::ToolContext;
use crate::ports::protocol::{ToolCallResult, ToolContent};

#[derive(Debug, Deserialize)]
pub struct SshDiagnoseArgs {
    host: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
    /// When `true`, ask the MCP client's LLM to summarize the raw
    /// diagnostic output via `sampling/createMessage`. The summary is
    /// appended to the response under a `=== LLM SUMMARY ===` section
    /// — the raw output is always preserved so callers can verify the
    /// LLM's conclusions. Falls back silently to raw-only output when
    /// the client does not advertise the sampling capability.
    #[serde(default)]
    summarize: Option<bool>,
    /// Cap on the LLM summary length, in tokens. Only meaningful when
    /// `summarize=true`. Defaults to 512.
    #[serde(default)]
    summary_max_tokens: Option<u32>,
}

impl_common_args!(SshDiagnoseArgs);

#[mcp_standard_tool(name = "ssh_diagnose", group = "diagnostics", annotation = "read_only")]
pub struct DiagnoseTool;

impl StandardTool for DiagnoseTool {
    type Args = SshDiagnoseArgs;

    const NAME: &'static str = "ssh_diagnose";

    const DESCRIPTION: &'static str = "Run a comprehensive diagnostic on a remote host in a \
        single call. Collects uptime, CPU load, memory, disk usage, top processes, failed \
        services, recent errors, OOM kills, and network listeners. Much faster than running \
        individual commands sequentially.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Timeout in seconds (default: 60, recommended for diagnostics)",
                "minimum": 1,
                "maximum": 300
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from config)",
                "minimum": 0
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to local file"
            },
            "summarize": {
                "type": "boolean",
                "description": "When true, append an LLM-side summary of the diagnostic output to the response. Requires the client to advertise the sampling capability; falls back to raw-only output otherwise."
            },
            "summary_max_tokens": {
                "type": "integer",
                "description": "Maximum tokens for the LLM summary (default: 512). Only meaningful with summarize=true.",
                "minimum": 32,
                "maximum": 4096
            }
        },
        "required": ["host"]
    }"#;

    fn build_command(_args: &SshDiagnoseArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(DiagnosticsCommandBuilder::build_diagnose_command())
    }

    /// When the user opted in via `summarize=true`, ask the client's
    /// LLM to identify the top anomalies in the diagnostic output and
    /// append the summary under a `=== LLM SUMMARY ===` section. The
    /// raw output is always preserved so downstream automation can
    /// verify the LLM's conclusions.
    async fn enrich(
        result: ToolCallResult,
        args: &SshDiagnoseArgs,
        output: &str,
        ctx: &ToolContext,
    ) -> Result<ToolCallResult> {
        if !args.summarize.unwrap_or(false) {
            return Ok(result);
        }
        let max_tokens = args.summary_max_tokens.unwrap_or(512);
        let prompt = "You are a Linux SRE. Identify the top 3 anomalies in \
                      the diagnostic output below. Be terse — bullet points \
                      only, one line each, no preamble. Focus on disk \
                      pressure, failed services, OOM kills, and unexpected \
                      listeners.";
        let Some(summary) = ctx.sample(prompt, output, max_tokens).await? else {
            // Sampling unavailable — return raw result unchanged so the
            // user still gets the full diagnostic.
            return Ok(result);
        };

        // Concatenate the raw text content with the summary so both are
        // visible in the response. App content / structured fields on
        // the existing result are preserved by reusing the input as a
        // base and only mutating the text body.
        let mut text = String::new();
        for content in &result.content {
            if let ToolContent::Text { text: t } = content {
                text.push_str(t);
            }
        }
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str("\n=== LLM SUMMARY ===\n");
        text.push_str(&summary);
        let mut enriched = ToolCallResult::text(text);
        enriched.structured_content = result.structured_content;
        enriched.is_error = result.is_error;
        Ok(enriched)
    }
}

pub type SshDiagnoseHandler = StandardToolHandler<DiagnoseTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshDiagnoseHandler::new();
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
        let handler = SshDiagnoseHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshDiagnoseHandler::new();
        assert_eq!(handler.name(), "ssh_diagnose");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "server1", "timeout_seconds": 120});
        let args: SshDiagnoseArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.timeout_seconds, Some(120));
    }

    #[test]
    fn test_args_minimal() {
        let json = json!({"host": "server1"});
        let args: SshDiagnoseArgs = serde_json::from_value(json).unwrap();
        assert!(args.timeout_seconds.is_none());
    }

    #[test]
    fn test_build_command() {
        use crate::config::{HostConfig, HostKeyVerification, OsType};
        let host_config = HostConfig {
            hostname: "test".to_string(),
            port: 22,
            user: "test".to_string(),
            auth: crate::config::AuthConfig::Agent,
            description: None,
            host_key_verification: HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: OsType::default(),
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),

            #[cfg(feature = "winrm")]
            winrm_use_tls: None,

            #[cfg(feature = "winrm")]
            winrm_accept_invalid_certs: None,

            #[cfg(feature = "winrm")]
            winrm_operation_timeout_secs: None,

            #[cfg(feature = "winrm")]
            winrm_max_envelope_size: None,
        };
        let args = SshDiagnoseArgs {
            host: "server1".to_string(),
            timeout_seconds: None,
            max_output: None,
            save_output: None,
            summarize: None,
            summary_max_tokens: None,
        };
        let cmd = DiagnoseTool::build_command(&args, &host_config).unwrap();
        assert!(cmd.contains("free -m"));
        assert!(cmd.contains("df -h"));
        assert!(cmd.contains("systemctl --failed"));
    }
}
