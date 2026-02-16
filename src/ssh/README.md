# 🔑 SSH Module

This module implements the SSH client based on `russh`, with connection pooling, automatic retry, and host key verification.

## 📁 Module Structure

```
ssh/
├── 📄 mod.rs          -> Public exports (SshClient, ConnectionPool, RealSshConnector, etc.)
├── 📄 client.rs       -> SshClient wrapper around russh
├── 📄 connector.rs    -> RealSshConnector (SshConnector + SshClientTrait implementations)
├── 📄 pool.rs         -> ConnectionPool + PooledConnectionGuard
├── 📄 retry.rs        -> RetryConfig + with_retry() + with_retry_if()
├── 📄 known_hosts.rs  -> Host key verification
├── 📄 session.rs      -> SessionManager + persistent sessions
├── 📄 sftp.rs         -> Streaming SFTP transfer
```

## 🏗️ Architecture

```mermaid
graph TB
    subgraph SSH["SSH Module"]
        CLIENT["SshClient<br/><i>client.rs</i>"]
        CONN["RealSshConnector<br/><i>connector.rs</i>"]
        POOL["ConnectionPool<br/><i>pool.rs</i>"]
        RETRY["RetryConfig<br/><i>retry.rs</i>"]
        KH["known_hosts<br/><i>known_hosts.rs</i>"]
        SESSION["SessionManager<br/><i>session.rs</i>"]
        SFTP["SftpClient<br/><i>sftp.rs</i>"]
    end

    subgraph External["External Dependencies"]
        RUSSH["russh crate"]
        SOCKS["tokio-socks crate"]
        FILE["~/.ssh/known_hosts"]
        AGENT["ssh-agent"]
    end

    CONN -.->|"impl SshConnector"| CLIENT
    POOL -->|"get_connection()"| CLIENT
    CLIENT -->|"check_server_key()"| KH
    KH --> FILE
    CLIENT --> RUSSH
    CLIENT -->|"SOCKS tunnel"| SOCKS
    CLIENT -->|"Agent auth"| AGENT
    RETRY -->|"wraps"| POOL
    SESSION --> CLIENT
    SFTP --> CLIENT
```

## 🔑 SshClient (`client.rs`)

SSH client wrapper that handles connection, authentication, and execution.

### 📋 Structure

```mermaid
classDiagram
    class SshClient {
        -handle: Handle~ClientHandler~
        -host_name: String
        -jump_client: Option~Box~SshClient~~
        +connect(host_name, config, limits) Result~Self~
        +connect_via_jump(host_name, config, jump_config, limits) Result~Self~
        +exec(command, limits) Result~CommandOutput~
        +is_connected() bool
        +host_name() &str
        +close() Result~()~
    }

    class CommandOutput {
        +stdout: String
        +stderr: String
        +exit_code: u32
        +duration_ms: u64
    }

    class ClientHandler {
        -hostname: String
        -port: u16
        -verification_mode: HostKeyVerification
        +check_server_key(key) Result~bool~
    }

    SshClient --> ClientHandler
    SshClient ..> CommandOutput : returns
```

### 🔧 API

```rust
impl SshClient {
    /// Connects to a host with authentication
    /// # Errors
    /// - `SshConnection`: TCP/SSH connection failure
    /// - `SshHostKeyMismatch`: host key doesn't match
    /// - `SshHostKeyUnknown`: unknown host (strict mode)
    /// - `SshAuth`: authentication failure
    pub async fn connect(host_name: &str, config: &HostConfig, limits: &LimitsConfig)
        -> Result<Self>

    /// Connects to a host via a jump host (bastion)
    /// Uses channel_open_direct_tcpip for the tunnel
    /// # Errors
    /// Same errors as connect(), plus jump host errors
    pub async fn connect_via_jump(
        host_name: &str,
        config: &HostConfig,
        jump_config: &HostConfig,
        limits: &LimitsConfig,
    ) -> Result<Self>

    /// Executes a command
    /// # Errors
    /// - `SshExec`: execution failure
    /// - `SshTimeout`: timeout exceeded
    /// - `SshOutputTooLarge`: output too large
    pub async fn exec(&self, command: &str, limits: &LimitsConfig)
        -> Result<CommandOutput>

    /// Checks if the connection is active
    pub async fn is_connected(&self) -> bool

    /// Returns the host name
    #[must_use]
    pub fn host_name(&self) -> &str

    /// Closes the connection properly
    /// # Errors
    /// If the disconnect message cannot be sent
    pub async fn close(self) -> Result<()>
}
```

### 🔄 Lifecycle

```mermaid
sequenceDiagram
    participant App
    participant Client as SshClient
    participant Handler as ClientHandler
    participant KH as known_hosts
    participant Host as Remote Host

    Note over App,Host: 1. Connection
    App->>Client: connect(host, config, limits)
    Client->>Host: TCP Connect (with timeout)
    Host-->>Client: SSH Handshake

    Note over App,Host: 2. Key Verification
    Client->>Handler: check_server_key(key)
    Handler->>KH: verify_host_key(mode)
    alt Key OK
        KH-->>Handler: Ok(())
        Handler-->>Client: Ok(true)
    else Invalid key
        KH-->>Handler: Err
        Handler-->>Client: Ok(false)
        Client-->>App: Err(SshHostKey...)
    end

    Note over App,Host: 3. Authentication
    alt Key Auth
        Client->>Client: load_secret_key(path)
        Client->>Host: authenticate_publickey
    else Agent Auth
        Client->>Client: AgentClient::connect_env()
        Client->>Host: authenticate_publickey_with (try each key)
    else Password Auth
        Client->>Host: authenticate_password
    end
    Host-->>Client: auth_result

    Note over App,Host: 4. Usage
    loop Commands
        App->>Client: exec(command, limits)
        Client->>Host: channel_open_session()
        Client->>Host: exec(command)
        Host-->>Client: stdout/stderr/exit_code
        Client-->>App: CommandOutput
    end

    Note over App,Host: 5. Close
    App->>Client: close()
    Client->>Host: disconnect(ByApplication)
```

### 🔐 Authentication

| Mode | YAML Config | Description |
|------|-------------|-------------|
| **Key** | `type: key` | SSH key with optional passphrase |
| **Agent** | `type: agent` | Via `ssh-agent` (Unix only) |
| **Password** | `type: password` | Password (not recommended) |

```mermaid
flowchart TD
    AUTH{AuthConfig?}

    AUTH -->|"Key"| KEY["load_secret_key(path, passphrase?)"]
    KEY --> HASH["best_supported_rsa_hash()"]
    HASH --> PUBKEY["authenticate_publickey()"]

    AUTH -->|"Agent"| AGENT["AgentClient::connect_env()"]
    AGENT --> LIST["request_identities()"]
    LIST --> LOOP["For each identity:"]
    LOOP --> TRY["authenticate_publickey_with()"]
    TRY -->|"Success"| DONE["Connected"]
    TRY -->|"Fail"| NEXT["Try next"]
    NEXT --> LOOP

    AUTH -->|"Password"| PASS["authenticate_password()"]
    PASS --> DONE
    PUBKEY --> DONE
```

## 🔌 RealSshConnector (`connector.rs`)

Concrete implementation of the `SshConnector` and `SshClientTrait` ports using `SshClient`.

This adapter was moved from `src/ports/connector.rs` to keep the ports layer pure (traits only).

### 📋 Structure

- `RealSshConnector`: Zero-sized type implementing `SshConnector` trait
- `impl SshClientTrait for SshClient`: Delegates to `SshClient` methods

### 🔧 API

```rust
impl SshConnector for RealSshConnector {
    type Client = SshClient;
    async fn connect(&self, host_name: &str, host: &HostConfig, limits: &LimitsConfig) -> Result<SshClient>
    async fn connect_via_jump(&self, host_name: &str, host: &HostConfig, jump_host_name: &str, jump_host: &HostConfig, limits: &LimitsConfig) -> Result<SshClient>
}
```

## 🔄 ConnectionPool (`pool.rs`)

Connection pool for reusing established SSH connections.

### 📋 Structure

```mermaid
classDiagram
    class ConnectionPool {
        -connections: Arc~Mutex~HashMap~~
        -config: PoolConfig
        +new(config) Self
        +with_defaults() Self
        +get_connection(host, config, limits) Result~Guard~
        +cleanup() void
        +stats() PoolStats
        +close_all() void
    }

    class PooledConnectionGuard {
        -pool: &ConnectionPool
        -host_name: String
        -connection: Option~PooledConnection~
        +exec(command, limits) Result~CommandOutput~
        +mark_failed() void
    }

    class PoolConfig {
        +max_connections_per_host: usize = 5
        +max_idle_seconds: u64 = 300
        +max_age_seconds: u64 = 3600
    }

    class PoolStats {
        +total_connections: usize
        +connections_by_host: HashMap~String, usize~
    }

    ConnectionPool --> PooledConnectionGuard
    ConnectionPool --> PoolConfig
    ConnectionPool --> PoolStats
```

### 🛡️ Guard Behavior (RAII)

```mermaid
sequenceDiagram
    participant App
    participant Pool as ConnectionPool
    participant Guard as PooledConnectionGuard
    participant Conn as PooledConnection

    App->>Pool: get_connection(host, config, limits)

    alt Existing valid connection
        Pool->>Pool: try_get_existing()
        Note over Pool: Check idle_time < max_idle<br/>Check age < max_age<br/>Check is_connected()
        Pool-->>Guard: Guard(existing_conn)
    else New connection
        Pool->>Conn: SshClient::connect()
        Pool-->>Guard: Guard(new_conn)
    end

    App->>Guard: exec(command, limits)
    Guard->>Conn: client.exec(command)
    Conn-->>Guard: CommandOutput
    Guard-->>App: Result

    Note over Guard: Guard dropped

    alt Connection OK
        Guard->>Pool: Return to pool (if < max_per_host)
    else mark_failed() called
        Guard->>Conn: close() in background
        Note over Guard: Connection not returned
    end
```

### ⚙️ Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_connections_per_host` | 5 | Max connections per host |
| `max_idle_seconds` | 300 (5 min) | Max inactivity |
| `max_age_seconds` | 3600 (1 hour) | Max connection age |

## 🔄 Retry Logic (`retry.rs`)

Retry with exponential backoff for transient errors.

### 📋 Structure

```mermaid
classDiagram
    class RetryConfig {
        +max_attempts: u32 = 3
        +initial_delay_ms: u64 = 100
        +max_delay_ms: u64 = 5000
        +backoff_multiplier: f64 = 2.0
        +jitter: f64 = 0.1
        +no_retry() Self
        +with_max_attempts(n) Self
    }
```

### ⏱️ Delay Calculation

```
delay = min(initial_delay * multiplier^(attempt-1), max_delay) +/- jitter
```

```mermaid
flowchart LR
    A1["Attempt 1<br/>0ms"] --> A2["Attempt 2<br/>100ms"]
    A2 --> A3["Attempt 3<br/>200ms"]
    A3 --> A4["Attempt 4<br/>400ms"]
    A4 --> A5["Attempt 5<br/>800ms"]
    A5 --> MAX["...capped at 5000ms"]
```

### ❌ Retryable Errors

```rust
pub fn is_retryable_error(error: &BridgeError) -> bool {
    match error {
        SshConnection { .. } => true,  // Connection lost
        SshTimeout { .. } => true,      // Timeout
        SshExec { reason } if reason.contains("channel") => true,
        SshExec { reason } if reason.contains("connection") => true,
        _ => false,  // Permanent errors (auth, config, etc.)
    }
}
```

### 🔧 API

```rust
/// Automatic retry of all errors
/// # Panics
/// If max_attempts == 0
pub async fn with_retry<T, E, F, Fut>(
    config: &RetryConfig,
    operation_name: &str,
    operation: F,
) -> Result<T, E>

/// Retry with custom predicate
/// # Panics
/// If max_attempts == 0
pub async fn with_retry_if<T, E, F, Fut, P>(
    config: &RetryConfig,
    operation_name: &str,
    operation: F,
    should_retry: P,  // |&E| -> bool
) -> Result<T, E>
```

### Usage Example

```rust
let output = with_retry_if(
    &config.limits.retry_config(),
    "ssh_exec",
    || async {
        let mut conn = pool.get_connection(&host, config, limits).await?;
        conn.exec(&command, limits).await
    },
    is_retryable_error,
).await?;
```

## 🏠 Known Hosts (`known_hosts.rs`)

Host key verification against `~/.ssh/known_hosts`.

### 🔧 API

```rust
/// Verifies a key against known_hosts
/// # Errors
/// If the file cannot be read
pub fn verify(hostname: &str, port: u16, key: &PublicKey) -> Result<VerifyResult>

/// Adds a key to known_hosts
/// # Errors
/// If the file cannot be written
pub fn add_key(hostname: &str, port: u16, key: &PublicKey) -> Result<()>

/// Returns the SHA256 fingerprint of a key
#[must_use]
pub fn fingerprint(key: &PublicKey) -> String

/// Verifies according to the configured mode
/// # Errors
/// If verification fails according to the mode
pub fn verify_host_key(hostname, port, key, mode: HostKeyVerification) -> Result<()>
```

### 🔒 Verification Modes

```mermaid
flowchart TD
    KEY["Server key"] --> MODE{HostKeyVerification?}

    MODE -->|"Off"| OFF["Accepted without verification"]

    MODE -->|"Strict"| STRICT_CHECK{"verify()?"}
    STRICT_CHECK -->|"Match"| OK1["OK"]
    STRICT_CHECK -->|"Mismatch"| ERR1["SshHostKeyMismatch<br/>(possible MITM!)"]
    STRICT_CHECK -->|"Unknown"| ERR2["SshHostKeyUnknown"]

    MODE -->|"AcceptNew"| ACCEPT_CHECK{"verify()?"}
    ACCEPT_CHECK -->|"Match"| OK2["OK"]
    ACCEPT_CHECK -->|"Mismatch"| ERR3["SshHostKeyMismatch<br/>(possible MITM!)"]
    ACCEPT_CHECK -->|"Unknown"| ADD["add_key()"]
    ADD --> OK3["OK"]
```

### 🔧 Troubleshooting

```bash
# "Unknown host key" in Strict mode
ssh-keyscan hostname >> ~/.ssh/known_hosts

# "Host key mismatch" (verify MITM first!)
ssh-keygen -R hostname
ssh-keyscan hostname >> ~/.ssh/known_hosts
```

## 🧪 Tests

```bash
# All SSH tests
cargo test ssh::

# By module
cargo test ssh::pool::tests
cargo test ssh::retry::tests
cargo test ssh::known_hosts::tests
```

### 📋 Available Tests

| Module | Tests |
|--------|-------|
| **pool** | `test_pool_config_default`, `test_pool_stats_empty`, `test_pool_cleanup_empty`, `test_pool_close_all_empty` |
| **retry** | `test_retry_config_default`, `test_retry_config_no_retry`, `test_delay_calculation`, `test_is_retryable_error`, `test_with_retry_*` |
| **known_hosts** | `test_verify_result_*`, `test_host_key_verification_*` |
| **session** | `test_session_manager_creation`, `test_parse_exec_output_*`, `test_list_empty`, `test_close_nonexistent`, `test_exec_nonexistent`, `test_cleanup_empty`, `test_close_all_empty` |

## 🎨 Design Patterns

| Pattern | Application |
|---------|-------------|
| 🏊 **Object Pool** | `ConnectionPool` reuses connections |
| 🛡️ **RAII Guard** | `PooledConnectionGuard` auto-returns to pool |
| 🔄 **Retry** | Exponential backoff with jitter |
| 🏭 **Factory** | `SshClient::connect()` |
| 🎯 **Strategy** | Key verification modes |

## 🏰 Jump Hosts (Bastion)

Support for SSH connections via a bastion server (jump host).

### ⚙️ Configuration

```yaml
hosts:
  bastion:
    hostname: bastion.example.com
    port: 22
    user: admin
    auth:
      type: agent

  prod-db:
    hostname: 10.0.0.5  # Private IP
    port: 22
    user: deploy
    proxy_jump: bastion  # Go through bastion
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

### How It Works

```mermaid
sequenceDiagram
    participant App
    participant Pool as ConnectionPool
    participant Jump as Bastion
    participant Target as Target

    App->>Pool: get_connection("prod-db", config, limits)
    Note over Pool: proxy_jump = "bastion"

    Pool->>Jump: 1. SshClient::connect(bastion)
    Jump-->>Pool: Bastion connection

    Pool->>Jump: 2. channel_open_direct_tcpip(10.0.0.5:22)
    Jump->>Target: TCP Tunnel
    Target-->>Jump: Tunnel established

    Pool->>Target: 3. SSH handshake via tunnel
    Target-->>Pool: SSH Session

    Pool-->>App: Guard(connection)

    App->>Target: exec("hostname")
    Target-->>App: "prod-db"
```

### Notes

- The `jump_client` is kept in `SshClient` to maintain the tunnel
- Connection uses `ChannelStream` which implements `AsyncRead`/`AsyncWrite`
- The pool automatically resolves jump host chains

## 📦 SessionManager (`session.rs`)

Manager for persistent interactive shell sessions on remote hosts.

### Principle

Sessions maintain state between commands: working directory (cwd), environment variables.
Each command is wrapped with markers to parse the exit code and cwd:

```rust
let wrapped = format!(
    "{command}\n__sshb_rc=$?\necho \"{begin_marker}\"\necho $__sshb_rc\npwd\necho \"{end_marker}\"\n"
);
```

### 🔧 API

```rust
impl SessionManager {
    /// Creates a new SessionManager
    #[must_use]
    pub fn new() -> Self

    /// Creates an interactive session on a remote host
    pub async fn create(&self, host: &str, config: &HostConfig, limits: &LimitsConfig)
        -> Result<SessionInfo>

    /// Executes a command in an existing session
    pub async fn exec(&self, session_id: &str, command: &str)
        -> Result<SessionExecResult>

    /// Lists all active sessions
    pub fn list(&self) -> Vec<SessionInfo>

    /// Closes a session
    pub async fn close(&self, session_id: &str) -> Result<()>

    /// Cleans up expired sessions (idle/age)
    pub async fn cleanup(&self)

    /// Closes all sessions
    pub async fn close_all(&self)
}
```

### 🔄 Lifecycle

```mermaid
sequenceDiagram
    participant App
    participant SM as SessionManager
    participant SSH as SshClient
    participant Host as Remote

    App->>SM: create(host)
    SM->>SSH: connect + request_shell()
    SSH->>Host: Interactive shell
    SM-->>App: SessionInfo {id, host, cwd}

    loop Commands
        App->>SM: exec(id, command)
        SM->>Host: wrapped command via shell
        Host-->>SM: output + markers
        SM->>SM: parse(output, exit_code, cwd)
        SM-->>App: SessionExecResult
    end

    App->>SM: close(id)
    SM->>Host: close channel
    SM-->>App: Ok
```

### Behavior

- **Thread-safe**: Uses `Arc<Mutex<...>>` for concurrent sharing
- **Automatic cleanup**: Expired sessions are closed (configurable `max_idle`, `max_age`)
- **Marker parsing**: Exit code and cwd are extracted from wrapped output
- **Non-persistent**: Sessions are lost on server restart

## 🧦 SOCKS Proxy

Support for SSH connections through a SOCKS4/5 proxy server (alternative to jump hosts).

### ⚙️ Configuration

```yaml
hosts:
  remote-via-proxy:
    hostname: 10.0.0.5
    port: 22
    user: deploy
    socks_proxy:
      hostname: proxy.example.com
      port: 1080          # Default
      version: socks5     # socks5 (default) or socks4
      username: proxyuser # Optional (SOCKS5 only)
      password: proxypass # Optional (SOCKS5 only)
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

### How It Works

```mermaid
sequenceDiagram
    participant App
    participant Pool as ConnectionPool
    participant Proxy as SOCKS Proxy
    participant Target as Target

    App->>Pool: get_connection("remote-via-proxy", config, limits)
    Note over Pool: socks_proxy configured

    Pool->>Proxy: 1. SOCKS CONNECT (tokio-socks)
    Proxy->>Target: TCP Tunnel to 10.0.0.5:22
    Target-->>Proxy: Tunnel established

    Pool->>Target: 2. SSH handshake via tunnel (connect_stream)
    Target-->>Pool: SSH Session

    Pool-->>App: Guard(connection)

    App->>Target: exec("hostname")
    Target-->>App: "remote-via-proxy"
```

### Notes

- Uses `tokio-socks` crate for async SOCKS4/5 implementation
- The TCP stream from `Socks5Stream::into_inner()` is passed to russh's `connect_stream()`
- SOCKS5 supports optional username/password authentication
- `proxy_jump` and `socks_proxy` are mutually exclusive (validated at config load)

## ⚠️ Important Notes

> [!IMPORTANT]
> **Thread-safety**: `ConnectionPool` uses `Arc<Mutex<...>>` for sharing.

> [!IMPORTANT]
> **SSH Agent**: Works only on Unix via `SSH_AUTH_SOCK`.

> [!NOTE]
> **Timeout**: Configured via `LimitsConfig.connection_timeout_seconds` and `command_timeout_seconds`.

> [!NOTE]
> **Keepalive**: Automatically enabled via `keepalive_interval_seconds`.

> [!NOTE]
> **Jump Hosts**: Configured via `proxy_jump` in the target host config.

> [!NOTE]
> **SOCKS Proxy**: Configured via `socks_proxy` in the target host config. Mutually exclusive with `proxy_jump`.

> [!IMPORTANT]
> **Exit Code**: `read_command_output()` waits for `None` (channel close) and not `Eof` to correctly capture the SSH exit code.
