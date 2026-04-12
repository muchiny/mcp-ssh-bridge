# Contract: WinRM Adapter

**Module**: `src/winrm/`
**Feature Gate**: `#[cfg(feature = "winrm")]`

## WinRmConnection Interface

```rust
/// An active WinRM connection wrapping winrm_rs::WinrmClient.
///
/// Unlike the previous implementation (cmd.exe + regex XML),
/// this adapter delegates to winrm-rs for proper SOAP/WS-Man,
/// NTLMv2 auth, and PowerShell execution.
pub struct WinRmConnection {
    client: Arc<WinrmClient>,
    host_name: String,
    failed: bool,
}

impl WinRmConnection {
    /// Wrap a cached WinrmClient for a specific host.
    pub fn from_parts(host_name: &str, client: Arc<WinrmClient>) -> Self;

    /// Execute a PowerShell command via WinRM.
    ///
    /// Uses `WinrmClient::run_powershell()` — NOT cmd.exe.
    /// Converts winrm_rs::CommandOutput (Vec<u8>) to bridge CommandOutput (String).
    pub async fn exec(
        &mut self,
        command: &str,
        limits: &LimitsConfig,
    ) -> Result<CommandOutput>;

    /// Execute with cancellation token propagation.
    pub async fn exec_with_cancel(
        &mut self,
        command: &str,
        limits: &LimitsConfig,
        token: Option<CancellationToken>,
    ) -> Result<CommandOutput>;

    /// Mark connection as failed (triggers pool eviction).
    pub fn mark_failed(&mut self);

    /// Host name for logging/eviction.
    pub fn host_name(&self) -> &str;
}
```

## WinRmPool Interface

```rust
/// Cache of WinrmClient instances keyed by host name.
///
/// Follows the same pattern as WinRM pool (RwLock + HashMap)
/// but caches WinrmClient instead of reqwest::Client.
pub struct WinRmPool {
    inner: Arc<RwLock<HashMap<String, PooledWinrmClient>>>,
    config: WinRmPoolConfig,
}

impl WinRmPool {
    pub fn new() -> Self;                          // Default 120s TTL
    pub fn with_config(config: WinRmPoolConfig) -> Self;

    /// Get or create a WinRM connection for the given host.
    ///
    /// Fast path: return cached client if fresh.
    /// Cold path: build WinrmConfig + WinrmCredentials from HostConfig,
    ///            create WinrmClient::new(), cache, return.
    pub async fn get_connection(
        &self,
        host_name: &str,
        host_config: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<WinRmConnection>;

    pub async fn evict(&self, host_name: &str);
    pub async fn cleanup(&self);
    pub async fn close_all(&self);
    pub fn size(&self) -> usize;
}
```

## Config Mapping Function

```rust
/// Build winrm_rs types from bridge config.
///
/// This is the single point of translation between the bridge's
/// HostConfig/AuthConfig and winrm-rs's WinrmConfig/WinrmCredentials.
fn build_winrm_config(
    host_config: &HostConfig,
) -> Result<(WinrmConfig, WinrmCredentials)>;
```

**Mapping rules**:
- `host_config.port` -> `WinrmConfig.port`
- `host_config.winrm_use_tls` (or auto-detect from port) -> `WinrmConfig.use_tls`
- `host_config.winrm_accept_invalid_certs` -> `WinrmConfig.accept_invalid_certs`
- `host_config.winrm_operation_timeout_secs` -> `WinrmConfig.operation_timeout_secs`
- `host_config.auth` -> `WinrmConfig.auth_method` + `WinrmCredentials`
- `host_config.user` -> `WinrmCredentials.username`

## Error Mapping

```rust
/// Map winrm_rs errors to bridge errors.
impl From<WinrmError> for BridgeError {
    fn from(e: WinrmError) -> Self {
        match e {
            WinrmError::Auth(_) => BridgeError::Auth { reason: ... },
            WinrmError::Timeout(_) => BridgeError::Timeout { reason: ... },
            WinrmError::Soap(soap) => BridgeError::SshExec { reason: soap.to_string() },
            _ => BridgeError::SshExec { reason: e.to_string() },
        }
    }
}
```
