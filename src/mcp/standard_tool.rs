//! Standard Tool Handler
//!
//! Generic handler that implements the common 16-step execution pipeline
//! shared by ~170 of the 337 tool handlers. Each standard tool only needs
//! to define its args struct, schema, and `build_command` function.

use std::marker::PhantomData;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tracing::{info, warn};

use crate::config::{HostConfig, OsType};
use crate::domain::output_truncator::truncate_output_with_cache;
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::ToolCallResult;
use crate::ports::{ToolContext, ToolHandler, ToolSchema};
use crate::ssh::{is_retryable_error, with_retry_if};

/// Trait for accessing common fields present in all standard tool args.
pub trait CommonArgs {
    /// The SSH host alias.
    fn host(&self) -> &str;
    /// Optional timeout override in seconds.
    fn timeout_seconds(&self) -> Option<u64>;
    /// Optional max output characters override.
    fn max_output(&self) -> Option<u64>;
    /// Optional file path to save full output.
    fn save_output(&self) -> Option<&str>;
}

/// Implement [`CommonArgs`] for a struct that has the standard fields:
/// `host: String`, `timeout_seconds: Option<u64>`,
/// `max_output: Option<u64>`, `save_output: Option<String>`.
macro_rules! impl_common_args {
    ($type:ty) => {
        impl $crate::mcp::standard_tool::CommonArgs for $type {
            fn host(&self) -> &str {
                &self.host
            }
            fn timeout_seconds(&self) -> Option<u64> {
                self.timeout_seconds
            }
            fn max_output(&self) -> Option<u64> {
                self.max_output
            }
            fn save_output(&self) -> Option<&str> {
                self.save_output.as_deref()
            }
        }
    };
}
pub(crate) use impl_common_args;

/// Trait for tools that follow the standard execution pipeline.
///
/// The pipeline is: parse args → host lookup → OS guard → validate →
/// build command → `validate_builtin` → rate limit → execute with retry →
/// process success → truncate → save output → return.
pub trait StandardTool: Send + Sync + 'static {
    /// The deserialized arguments type.
    type Args: DeserializeOwned + Send + CommonArgs;

    /// Tool name (used for routing and logging).
    const NAME: &'static str;
    /// Tool description shown to MCP clients.
    const DESCRIPTION: &'static str;
    /// JSON schema string for the tool's input.
    const SCHEMA: &'static str;

    /// Optional OS restriction. `None` = no restriction.
    /// `Some(OsType::Linux)` = reject Windows hosts.
    /// `Some(OsType::Windows)` = reject non-Windows hosts.
    const OS_GUARD: Option<OsType> = None;

    /// Expected output format. Controls which data-reduction params are
    /// advertised in the schema and which reduction pipeline runs at runtime.
    const OUTPUT_KIND: crate::domain::output_kind::OutputKind =
        crate::domain::output_kind::OutputKind::RawText;

    /// Build the shell command from parsed arguments.
    ///
    /// This is the only method that MUST be implemented per tool.
    /// Return `Ok(command_string)` for the command to execute via SSH.
    fn build_command(args: &Self::Args, host_config: &HostConfig) -> Result<String>;

    /// Optional extra validation before command execution.
    ///
    /// Override this to add domain-specific input validation
    /// (e.g., `validate_service_name`, `validate_port`).
    /// Default: no-op (always succeeds).
    fn validate(_args: &Self::Args, _host_config: &HostConfig) -> Result<()> {
        Ok(())
    }

    /// Paths to validate against workspace root scope.
    ///
    /// Override for file-operation tools to enforce path scoping.
    /// Default: empty (no scoping).
    fn scoped_paths(_args: &Self::Args) -> Vec<&str> {
        Vec::new()
    }

    /// Optional post-processing to enrich the result with App content.
    ///
    /// Override this to add dashboard, table, or chart components
    /// to the tool result. The default is a no-op (returns result as-is).
    /// `output` is the raw (unsanitized) command output text.
    /// `dr` contains data-reduction params (e.g. `columns` for column filtering).
    fn post_process(
        result: ToolCallResult,
        _args: &Self::Args,
        _output: &str,
        _dr: &crate::domain::data_reduction::DataReductionArgs,
    ) -> ToolCallResult {
        result
    }
}

/// Generic handler that wraps a [`StandardTool`] and implements [`ToolHandler`].
///
/// The 16-step execution pipeline is implemented once here and reused
/// for every `StandardTool` implementation via monomorphization.
pub struct StandardToolHandler<T: StandardTool>(PhantomData<T>);

impl<T: StandardTool> Default for StandardToolHandler<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: StandardTool> StandardToolHandler<T> {
    /// Create a new handler instance.
    #[must_use]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

#[async_trait]
impl<T: StandardTool> ToolHandler for StandardToolHandler<T> {
    fn name(&self) -> &'static str {
        T::NAME
    }

    fn description(&self) -> &'static str {
        T::DESCRIPTION
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: T::NAME,
            description: T::DESCRIPTION,
            input_schema: T::SCHEMA,
        }
    }

    fn output_kind(&self) -> crate::domain::output_kind::OutputKind {
        T::OUTPUT_KIND
    }

    #[allow(clippy::too_many_lines)]
    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult> {
        // Step 0: Extract universal data reduction params before tool-specific parsing
        let Some(mut v) = args else {
            return Err(BridgeError::McpMissingParam {
                param: "arguments".to_string(),
            });
        };
        let dr = crate::domain::data_reduction::DataReductionArgs::extract(&mut v);

        // Step 1: Parse args
        let args: T::Args =
            serde_json::from_value(v).map_err(|e| BridgeError::McpInvalidRequest(e.to_string()))?;

        // Step 2: Host config lookup
        let host = args.host().to_string();
        let host_config = ctx
            .config
            .hosts
            .get(&host)
            .ok_or_else(|| BridgeError::UnknownHost { host: host.clone() })?;

        // Step 3: OS guard
        if let Some(required_os) = T::OS_GUARD {
            match required_os {
                OsType::Windows => {
                    if host_config.os_type != OsType::Windows {
                        return Ok(ToolCallResult::error(format!(
                            "Tool '{}' is only available on Windows hosts. \
                             Use Linux-specific tools instead.",
                            T::NAME
                        )));
                    }
                }
                OsType::Linux => {
                    if host_config.os_type == OsType::Windows {
                        return Ok(ToolCallResult::error(format!(
                            "Tool '{}' is not available on Windows hosts. \
                             Use Windows-specific tools instead.",
                            T::NAME
                        )));
                    }
                }
            }
        }

        // Step 4: Domain validation (optional)
        T::validate(&args, host_config)?;

        // Step 4b: Root scope validation for file-operation tools
        for path in T::scoped_paths(&args) {
            ctx.validate_root_scope(path)?;
        }

        // Step 5: Build command
        let command = T::build_command(&args, host_config)?;

        // Step 6: Validate against security policy
        if let Err(e) = ctx.execute_use_case.validate_builtin(&command) {
            let reason = match &e {
                BridgeError::CommandDenied { reason } => reason.clone(),
                _ => e.to_string(),
            };
            ctx.execute_use_case.log_denied(&host, &command, &reason);
            return Err(e);
        }

        // Step 7: Rate limit
        if ctx.rate_limiter.check(&host).is_err() {
            return Ok(ToolCallResult::error(format!(
                "Rate limit exceeded for host '{host}'. Please wait before sending more requests.",
            )));
        }

        // Step 8: Log intent
        info!(host = %host, tool = T::NAME, "Executing tool");

        // Step 9: Timeout override
        let mut limits = ctx.config.limits.clone();
        if let Some(timeout) = args.timeout_seconds() {
            limits.command_timeout_seconds = timeout;
        }

        // Step 10: Retry config + jump host
        let retry_config = limits.retry_config();
        let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
            ctx.config
                .hosts
                .get(jump_name)
                .map(|jump_config| (jump_name.as_str(), jump_config))
        });

        // Step 10b: Force C locale for consistent columnar output parsing.
        // Only StandardToolHandler commands are prefixed — ssh_exec and
        // other custom handlers preserve the user's native locale.
        let command = format!("LC_ALL=C {command}");

        // Step 11: Execute with retry
        let output = with_retry_if(
            &retry_config,
            T::NAME,
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

        // Step 12: Log failure
        let output = output.inspect_err(|e| {
            ctx.execute_use_case
                .log_failure(&host, &command, &e.to_string());
        })?;

        // Step 13: Process success (audit + history + sanitize)
        let mut response = ctx
            .execute_use_case
            .process_success(&host, &command, &output.into());
        let raw_chars = response.stdout.len();

        // Step 14: Warn on non-zero exit
        if response.exit_code != 0 {
            warn!(
                host = %host,
                tool = T::NAME,
                exit_code = response.exit_code,
                "Tool returned non-zero exit code"
            );
        }

        // Step 14: Typed data reduction pipeline (applied before truncation)
        // Save raw output for post_process (which needs the original for App content)
        let raw_output = response.stdout.clone();
        if response.exit_code == 0 && !dr.is_empty() {
            apply_typed_reduction(&mut response.stdout, &dr, T::OUTPUT_KIND)?;
        }

        let post_reduction_chars = response.stdout.len();

        // Step 15: Truncate stdout for display
        #[allow(clippy::cast_possible_truncation)]
        let max_chars = args
            .max_output()
            .map_or(ctx.config.limits.max_output_chars, |v| v as usize);
        let truncated_stdout =
            truncate_output_with_cache(&response.stdout, max_chars, ctx.output_cache.as_deref())
                .await;

        // Step 16: Save full output to file if requested
        let mut save_info: Option<String> = None;
        if let Some(save_path) = args.save_output() {
            match crate::mcp::tool_handlers::utils::save_output_to_file(save_path, &response.output)
                .await
            {
                Ok(msg) => save_info = Some(msg),
                Err(msg) => save_info = Some(format!("save_output error: {msg}")),
            }
        }

        // Step 17: Format for LLM (raw text on success, [exit:N] on error)
        let mut output_text = response.format_for_llm(&truncated_stdout);
        if let Some(info) = save_info {
            output_text = format!("{output_text}\n{info}");
        }

        // Record pipeline stats for token consumption analytics
        if let Some(ref metrics) = ctx.metrics {
            let truncated = truncated_stdout.len() < post_reduction_chars;
            metrics.record_pipeline_stats(
                raw_chars as u64,
                post_reduction_chars as u64,
                truncated,
                &format!("{:?}", T::OUTPUT_KIND),
            );
        }

        // Step 18: Post-process + auto-populate structuredContent from AppContent
        let result = ToolCallResult::text(output_text);
        let result = T::post_process(result, &args, &raw_output, &dr);
        Ok(auto_populate_structured_content(result))
    }
}

/// Apply typed data reduction based on [`OutputKind`].
///
/// - `Json` → apply `jq_filter` if present
/// - `Tabular` → apply `columns` filter if present (parse columnar → select → TSV)
/// - `Auto` → try JSON+jq first, fall back to tabular+columns
/// - `RawText` → no-op
#[allow(clippy::unnecessary_wraps)]
fn apply_typed_reduction(
    stdout: &mut String,
    dr: &crate::domain::data_reduction::DataReductionArgs,
    kind: crate::domain::output_kind::OutputKind,
) -> Result<()> {
    use crate::domain::output_kind::OutputKind;

    match kind {
        OutputKind::Json => {
            try_apply_jq(stdout, dr)?;
        }
        OutputKind::Tabular => {
            try_apply_columns(stdout, dr);
        }
        OutputKind::Auto => {
            // Try JSON + jq first (if jq_filter is present and output parses as JSON)
            if !try_apply_jq(stdout, dr)? {
                // Fall back to tabular + columns
                try_apply_columns(stdout, dr);
            }
        }
        OutputKind::RawText => {}
    }

    Ok(())
}

/// Try to apply a `jq_filter` to stdout. Returns `true` if applied.
#[allow(clippy::unnecessary_wraps)]
fn try_apply_jq(
    stdout: &mut String,
    dr: &crate::domain::data_reduction::DataReductionArgs,
) -> Result<bool> {
    let _ = &(&stdout, &dr);

    #[cfg(feature = "jq")]
    if let Some(ref filter) = dr.jq_filter {
        *stdout = crate::domain::jq_filter::apply_jq_filter(stdout, filter)?;
        return Ok(true);
    }

    Ok(false)
}

/// Try to apply a `columns` filter to stdout (columnar text → filtered TSV).
fn try_apply_columns(
    stdout: &mut String,
    dr: &crate::domain::data_reduction::DataReductionArgs,
) {
    if let Some(ref cols) = dr.columns
        && let Some(table) =
            crate::mcp::tool_handlers::utils::parse_columnar_output(stdout)
    {
        *stdout = table.select_columns(cols).to_tsv();
    }
}

/// Auto-populate `structuredContent` from `AppContent` data.
///
/// If the result contains an App component (table, dashboard, chart),
/// extract its data into `structured_content` for MCP clients that
/// support structured output (MCP 2025-06-18+).
fn auto_populate_structured_content(mut result: ToolCallResult) -> ToolCallResult {
    use crate::mcp::protocol::ToolContent;

    // Only populate if not already set
    if result.structured_content.is_some() {
        return result;
    }

    // Find the first App content and extract its data
    for content in &result.content {
        if let ToolContent::App { app } = content {
            result.structured_content = Some(app.data.clone());
            break;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde::Deserialize;
    use serde_json::json;

    // ---- Mock tool for testing the generic pipeline ----

    #[derive(Debug, Deserialize)]
    struct MockArgs {
        host: String,
        timeout_seconds: Option<u64>,
        max_output: Option<u64>,
        save_output: Option<String>,
    }

    impl_common_args!(MockArgs);

    struct MockTool;

    impl StandardTool for MockTool {
        type Args = MockArgs;
        const NAME: &'static str = "mock_tool";
        const DESCRIPTION: &'static str = "A mock tool for testing";
        const SCHEMA: &'static str = r#"{
            "type": "object",
            "properties": {
                "host": { "type": "string" }
            },
            "required": ["host"]
        }"#;

        fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
            Ok("echo hello".to_string())
        }
    }

    // ---- Mock tool with OS guard for testing ----

    struct MockWindowsTool;

    impl StandardTool for MockWindowsTool {
        type Args = MockArgs;
        const NAME: &'static str = "mock_windows_tool";
        const DESCRIPTION: &'static str = "A mock Windows tool";
        const SCHEMA: &'static str = r#"{
            "type": "object",
            "properties": { "host": { "type": "string" } },
            "required": ["host"]
        }"#;
        const OS_GUARD: Option<OsType> = Some(OsType::Windows);

        fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
            Ok("Get-Process".to_string())
        }
    }

    struct MockLinuxTool;

    impl StandardTool for MockLinuxTool {
        type Args = MockArgs;
        const NAME: &'static str = "mock_linux_tool";
        const DESCRIPTION: &'static str = "A mock Linux tool";
        const SCHEMA: &'static str = r#"{
            "type": "object",
            "properties": { "host": { "type": "string" } },
            "required": ["host"]
        }"#;
        const OS_GUARD: Option<OsType> = Some(OsType::Linux);

        fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
            Ok("ps aux".to_string())
        }
    }

    // ---- Mock tool with validation ----

    struct MockValidatingTool;

    impl StandardTool for MockValidatingTool {
        type Args = MockArgs;
        const NAME: &'static str = "mock_validating_tool";
        const DESCRIPTION: &'static str = "A mock tool with validation";
        const SCHEMA: &'static str = r#"{
            "type": "object",
            "properties": { "host": { "type": "string" } },
            "required": ["host"]
        }"#;

        fn build_command(_args: &MockArgs, _host_config: &HostConfig) -> Result<String> {
            Ok("echo validated".to_string())
        }

        fn validate(_args: &MockArgs, _host_config: &HostConfig) -> Result<()> {
            Err(BridgeError::Config("validation failed".to_string()))
        }
    }

    // ---- Pipeline tests ----

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = StandardToolHandler::<MockTool>::new();
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
        let handler = StandardToolHandler::<MockTool>::new();
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

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = StandardToolHandler::<MockTool>::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = StandardToolHandler::<MockTool>::new();
        assert_eq!(handler.name(), "mock_tool");
        assert_eq!(handler.description(), "A mock tool for testing");
        let schema = handler.schema();
        assert_eq!(schema.name, "mock_tool");
        let schema_json: Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[tokio::test]
    async fn test_os_guard_windows_rejects_linux_host() {
        let handler = StandardToolHandler::<MockWindowsTool>::new();
        let ctx = create_test_context_with_host(); // server1 is Linux
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        assert!(text.contains("only available on Windows"));
    }

    #[tokio::test]
    async fn test_validation_failure() {
        let handler = StandardToolHandler::<MockValidatingTool>::new();
        let ctx = create_test_context_with_host();
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rate_limit() {
        use crate::security::RateLimiter;
        use std::sync::Arc;

        let handler = StandardToolHandler::<MockLinuxTool>::new();
        let mut ctx = create_test_context_with_host();
        ctx.rate_limiter = Arc::new(RateLimiter::new(1));

        // Exhaust the single token
        assert!(ctx.rate_limiter.check("server1").is_ok());

        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        let crate::ports::protocol::ToolContent::Text { text } = &result.content[0] else {
            panic!("Expected text content")
        };
        assert!(text.contains("Rate limit exceeded"));
    }
}
