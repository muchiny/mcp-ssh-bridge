# Data Model: WinRM/PSRP Protocol Integration

**Branch**: `001-winrm-psrp-integration` | **Date**: 2026-04-12

## Entity Definitions

### 1. AuthConfig (Extended)

**Location**: `src/config/types.rs`
**Change**: Add 3 WinRM-specific variants (feature-gated)

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    // --- Existing (SSH) ---
    Key {
        path: String,
        #[serde(default)]
        passphrase: Option<Zeroizing<String>>,
    },
    Agent,
    Password {
        password: Zeroizing<String>,
    },

    // --- New (WinRM) ---
    #[cfg(feature = "winrm")]
    Ntlm {
        password: Zeroizing<String>,
        #[serde(default)]
        domain: Option<String>,
    },
    #[cfg(feature = "winrm")]
    Certificate {
        cert_path: String,
        key_path: String,
    },
    #[cfg(feature = "winrm")]
    Kerberos,
}
```

**Validation Rules**:

- `Ntlm.password` must not be empty
- `Certificate.cert_path` and `key_path` must be valid file paths
- `Kerberos` requires a valid TGT at runtime (not config-time)
- `Key` and `Agent` are rejected at config validation when `protocol: winrm` or `protocol: psrp`

**Mapping to winrm-rs**:

| AuthConfig | winrm_rs::AuthMethod | WinrmCredentials |
|---|---|---|
| `Password { pw }` | `Basic` | `(user, pw, "")` |
| `Ntlm { pw, domain }` | `Ntlm` | `(user, pw, domain.unwrap_or(""))` |
| `Certificate { .. }` | `Certificate` | N/A (cert paths in WinrmConfig) |
| `Kerberos` | `Kerberos` | `(user, "", "")` |

---

### 2. HostConfig (Extended)

**Location**: `src/config/types.rs`
**Change**: Add optional WinRM-specific fields

```rust
pub struct HostConfig {
    // --- Existing fields (unchanged) ---
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthConfig,
    pub description: Option<String>,
    pub host_key_verification: HostKeyVerification,
    pub proxy_jump: Option<String>,
    pub socks_proxy: Option<SocksProxyConfig>,
    pub sudo_password: Option<String>,
    pub tags: Vec<String>,
    pub os_type: OsType,
    pub shell: Option<ShellType>,
    pub retry: Option<HostRetryConfig>,
    pub protocol: Protocol,

    // --- New WinRM fields ---
    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_use_tls: Option<bool>,

    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_accept_invalid_certs: Option<bool>,

    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_operation_timeout_secs: Option<u64>,

    #[cfg(feature = "winrm")]
    #[serde(default)]
    pub winrm_max_envelope_size: Option<u32>,
}
```

**Validation Rules**:

- `winrm_*` fields ignored when `protocol != WinRm && protocol != Psrp`
- `winrm_use_tls` defaults to `true` when port is 5986, `false` when 5985
- `winrm_accept_invalid_certs` defaults to `false`
- `winrm_operation_timeout_secs` defaults to 60
- `winrm_max_envelope_size` defaults to 153600 (150 KB)
- `proxy_jump` must be `None` when protocol is WinRM/PSRP (not supported)

---

### 3. Protocol (Extended)

**Location**: `src/config/types.rs`
**Change**: Add `Psrp` variant

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Ssh,
    #[cfg(feature = "winrm")]
    #[serde(alias = "WinRM")]
    WinRm,
    #[cfg(feature = "psrp")]
    #[serde(alias = "PSRP")]
    Psrp,                            // NEW
    // ... other variants unchanged
}
```

---

### 4. WinRmConnection (Replaced)

**Location**: `src/winrm/mod.rs`
**Change**: Complete rewrite wrapping `winrm_rs::WinrmClient`

```rust
pub struct WinRmConnection {
    client: Arc<WinrmClient>,
    host_name: String,
    failed: bool,
}

impl WinRmConnection {
    /// Build from cached client + host config
    pub fn from_parts(host_name: &str, client: Arc<WinrmClient>) -> Self;

    /// Execute PowerShell command (replaces cmd.exe)
    pub async fn exec(&mut self, command: &str, limits: &LimitsConfig) -> Result<CommandOutput>;

    /// Execute with cancellation support
    pub async fn exec_with_cancel(
        &mut self, command: &str, limits: &LimitsConfig,
        token: Option<CancellationToken>,
    ) -> Result<CommandOutput>;

    pub fn mark_failed(&mut self);
    pub fn host_name(&self) -> &str;
}
```

**exec() flow**:

1. Call `client.run_powershell_with_cancel(host, command, token)` (was: `cmd.exe /c`)
2. Map `CommandOutput { stdout: Vec<u8>, stderr: Vec<u8>, exit_code: u32 }`
   to bridge `CommandOutput { stdout: String, stderr: String, exit_code: i32, duration_ms: u64 }`
3. Return result

---

### 5. WinRmPool (Replaced)

**Location**: `src/winrm/pool.rs`
**Change**: Cache `Arc<WinrmClient>` instead of `reqwest::Client`

```rust
pub struct WinRmPool {
    inner: Arc<RwLock<HashMap<String, PooledWinrmClient>>>,
    config: WinRmPoolConfig,
}

struct PooledWinrmClient {
    client: Arc<WinrmClient>,
    last_used: Instant,
}

pub struct WinRmPoolConfig {
    pub max_idle: Duration,  // Default: 120s
}
```

**API** (unchanged surface):

- `get_connection(host_name, host_config, limits) -> Result<WinRmConnection>`
- `evict(host_name)`
- `cleanup()`
- `close_all()`

**Cold path**: Build `WinrmConfig` + `WinrmCredentials` from `HostConfig`, create
`WinrmClient::new(config, creds)`, wrap in `Arc`, cache.

---

### 6. PsrpConnection (New)

**Location**: `src/psrp/mod.rs`

```rust
pub struct PsrpConnection {
    pool: RunspacePool<WinrmPsrpTransport<'static>>,
    host_name: String,
    failed: bool,
}

impl PsrpConnection {
    pub fn from_parts(
        host_name: &str,
        pool: RunspacePool<WinrmPsrpTransport<'static>>,
    ) -> Self;

    pub async fn exec(&mut self, command: &str, limits: &LimitsConfig) -> Result<CommandOutput>;

    pub async fn exec_with_cancel(
        &mut self, command: &str, limits: &LimitsConfig,
        token: Option<CancellationToken>,
    ) -> Result<CommandOutput>;

    pub fn mark_failed(&mut self);
    pub fn host_name(&self) -> &str;
}
```

**exec() flow**:

1. Call `pool.run_script_with_cancel(command, token)`
2. Convert `Vec<PsValue>` to stdout string (Debug or Display format)
3. Return `CommandOutput { stdout, stderr: "", exit_code: 0, duration_ms }`

---

### 7. PsrpPool (New)

**Location**: `src/psrp/pool.rs`

```rust
pub struct PsrpPool {
    inner: Arc<RwLock<HashMap<String, PooledRunspace>>>,
    config: PsrpPoolConfig,
}

struct PooledRunspace {
    connection: PsrpConnection,
    last_used: Instant,
}

pub struct PsrpPoolConfig {
    pub max_idle: Duration,  // Default: 300s
}
```

**API**: Same surface as WinRmPool.

**Cold path**: Build `WinrmClient`, open `WinrmPsrpTransport`, open `RunspacePool`,
cache the assembled `PsrpConnection`.

---

### 8. ConnectionGuard (Extended)

**Location**: `src/ports/executor_router.rs`
**Change**: Add `Psrp` variant

```rust
pub enum ConnectionGuard<'a> {
    Ssh(PooledConnectionGuard<'a>),
    #[cfg(feature = "winrm")]
    WinRm(WinRmConnection),
    #[cfg(feature = "psrp")]
    Psrp(PsrpConnection),               // NEW
    // ... other variants unchanged
}
```

**exec() dispatch**: New match arm routes to `PsrpConnection::exec()`.
**mark_failed() dispatch**: Routes to `PsrpConnection::mark_failed()`.

---

### 9. ExecutorRouter (Extended)

**Location**: `src/ports/executor_router.rs`
**Change**: Add `psrp_pool` field and dispatch arm

```rust
pub struct ExecutorRouter {
    ssh_pool: ConnectionPool,
    #[cfg(feature = "winrm")]
    winrm_pool: WinRmPool,
    #[cfg(feature = "psrp")]
    psrp_pool: PsrpPool,               // NEW
    // ... other pools unchanged
}
```

**Dispatch**: `Protocol::Psrp => self.psrp_pool.get_connection(...)`.
**cleanup()/close_all()**: Forward to `psrp_pool`.

---

## State Transitions

### WinRM Connection Lifecycle

```
[Pool Miss] --> WinrmClient::new(config, creds) --> [Cached in Pool]
[Pool Hit]  --> from_parts(client) --> [WinRmConnection]
[exec()]    --> run_powershell() --> [CommandOutput]
[Failure]   --> mark_failed() --> evict from pool --> [Pool Miss next call]
[Idle TTL]  --> cleanup() --> [Removed from pool]
```

### PSRP Connection Lifecycle

```
[Pool Miss] --> WinrmClient::new() --> WinrmPsrpTransport::open()
           --> RunspacePool::open_with_transport() --> [Cached in Pool]
[Pool Hit]  --> from_parts(pool) --> [PsrpConnection]
[exec()]    --> run_script() --> [Vec<PsValue>] --> [CommandOutput]
[Failure]   --> mark_failed() --> pool.close() --> evict --> [Pool Miss next call]
[Idle TTL]  --> cleanup() --> pool.close() --> [Removed from pool]
```

## Relationships

```
HostConfig ──has── AuthConfig
    │                  │
    │                  └── maps to ── WinrmConfig + WinrmCredentials
    │
    ├── protocol: WinRm ──→ ExecutorRouter ──→ WinRmPool ──→ WinRmConnection
    │                                                              │
    │                                                     wraps WinrmClient
    │
    └── protocol: Psrp ──→ ExecutorRouter ──→ PsrpPool ──→ PsrpConnection
                                                                   │
                                                          wraps RunspacePool
                                                                   │
                                                          uses WinrmPsrpTransport
                                                                   │
                                                          uses WinrmClient (shared)
```
