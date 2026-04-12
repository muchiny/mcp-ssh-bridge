# Contract: PSRP Adapter

**Module**: `src/psrp/`
**Feature Gate**: `#[cfg(feature = "psrp")]`

## PsrpConnection Interface

```rust
/// An active PSRP connection wrapping psrp_rs::RunspacePool.
///
/// Each PsrpConnection holds a live PowerShell session (RunspacePool)
/// that persists across multiple command executions. This avoids the
/// shell creation/teardown overhead of WinRM's per-command model.
pub struct PsrpConnection {
    pool: RunspacePool<WinrmPsrpTransport<'static>>,
    host_name: String,
    failed: bool,
}

impl PsrpConnection {
    /// Wrap a pre-opened RunspacePool for a specific host.
    pub fn from_parts(
        host_name: &str,
        pool: RunspacePool<WinrmPsrpTransport<'static>>,
    ) -> Self;

    /// Execute a PowerShell script via PSRP.
    ///
    /// Uses RunspacePool::run_script(). Converts Vec<PsValue> to
    /// CommandOutput string representation.
    pub async fn exec(
        &mut self,
        command: &str,
        limits: &LimitsConfig,
    ) -> Result<CommandOutput>;

    /// Execute with cancellation and full stream capture.
    pub async fn exec_with_cancel(
        &mut self,
        command: &str,
        limits: &LimitsConfig,
        token: Option<CancellationToken>,
    ) -> Result<CommandOutput>;

    /// Mark as failed — triggers RunspacePool close + pool eviction.
    pub fn mark_failed(&mut self);

    pub fn host_name(&self) -> &str;
}
```

## PsrpPool Interface

```rust
/// Cache of PSRP RunspacePool instances keyed by host name.
///
/// Longer TTL than WinRM (300s vs 120s) because RunspacePool
/// is designed for session reuse and creation is expensive
/// (TLS + auth + PSRP handshake + runspace initialization).
pub struct PsrpPool {
    inner: Arc<RwLock<HashMap<String, PooledRunspace>>>,
    config: PsrpPoolConfig,
}

impl PsrpPool {
    pub fn new() -> Self;                          // Default 300s TTL
    pub fn with_config(config: PsrpPoolConfig) -> Self;

    /// Get or create a PSRP connection for the given host.
    ///
    /// Cold path: build WinrmClient -> open WinrmPsrpTransport ->
    ///            open RunspacePool -> cache -> return.
    pub async fn get_connection(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<PsrpConnection>;

    pub async fn evict(&self, host_name: &str);
    pub async fn cleanup(&self);
    pub async fn close_all(&self);
    pub fn size(&self) -> usize;
}
```

## Output Conversion

```rust
/// Convert PSRP typed output to bridge CommandOutput.
///
/// Phase 1-2: Simple string serialization of PsValue.
/// Phase 3: Handlers can opt into PipelineResult directly.
fn psrp_to_command_output(
    values: Vec<PsValue>,
    duration_ms: u64,
) -> CommandOutput {
    let stdout = values
        .iter()
        .map(|v| format!("{v}"))
        .collect::<Vec<_>>()
        .join("\n");
    CommandOutput {
        stdout,
        stderr: String::new(),
        exit_code: 0,
        duration_ms,
    }
}

/// Convert full PipelineResult (7 streams) to CommandOutput.
fn pipeline_result_to_command_output(
    result: PipelineResult,
    duration_ms: u64,
) -> CommandOutput {
    let stdout = result.output.iter().map(|v| format!("{v}")).collect::<Vec<_>>().join("\n");
    let mut stderr_parts = Vec::new();
    for err in &result.errors {
        stderr_parts.push(format!("ERROR: {err}"));
    }
    for warn in &result.warnings {
        stderr_parts.push(format!("WARNING: {warn}"));
    }
    let exit_code = match result.state {
        PipelineState::Completed => 0,
        PipelineState::Failed => 1,
        PipelineState::Stopped => 2,
        _ => 1,
    };
    CommandOutput {
        stdout,
        stderr: stderr_parts.join("\n"),
        exit_code,
        duration_ms,
    }
}
```

## Error Mapping

```rust
impl From<PsrpError> for BridgeError {
    fn from(e: PsrpError) -> Self {
        match e {
            PsrpError::Winrm(we) => BridgeError::from(we),  // Delegate to WinRM mapping
            PsrpError::Cancelled => BridgeError::Cancelled,
            PsrpError::Protocol(msg) => BridgeError::SshExec {
                reason: format!("PSRP protocol error: {msg}"),
            },
            _ => BridgeError::SshExec { reason: e.to_string() },
        }
    }
}
```
