# 🔒 Security Module

This module implements security components: command validation, output sanitization, audit logging, and rate limiting.

## 📁 Module Structure

```
security/
📄 mod.rs          -> Public exports
📄 validator.rs    -> CommandValidator (whitelist/blacklist)
📄 sanitizer.rs    -> Sanitizer (secret masking)
📄 audit.rs        -> AuditLogger + AuditWriterTask (async)
📄 rate_limiter.rs -> RateLimiter (Token Bucket)
```

## 🔄 Security Flow

```mermaid
flowchart LR
    subgraph Input["Input"]
        CMD["Command"]
    end

    subgraph Validation["CommandValidator"]
        BL{"Blacklist?"}
        WL{"Whitelist?"}
    end

    subgraph Execution["Execution"]
        SSH["SSH"]
    end

    subgraph Output["Output"]
        SAN["Sanitizer"]
        CLEAN["Cleaned output"]
    end

    subgraph Audit["AuditLogger"]
        LOG["audit.log"]
    end

    CMD --> BL
    BL -->|"Match"| DENY["Denied"]
    BL -->|"No match"| WL
    WL -->|"Strict + No match"| DENY
    WL -->|"OK"| SSH
    SSH --> SAN
    SAN --> CLEAN

    DENY --> LOG
    SSH --> LOG
```

## ✅ CommandValidator

Validates commands against security rules with pre-compiled regex.

### 📋 Structure

```mermaid
classDiagram
    class CommandValidator {
        -mode: SecurityMode
        -whitelist: Vec~Regex~
        -blacklist: Vec~Regex~
        +new(config: &SecurityConfig) Self
        +validate(command: &str) Result~()~
    }

    class SecurityMode {
        <<enum>>
        Strict
        Permissive
    }

    CommandValidator --> SecurityMode
```

### 🔍 Validation Algorithm

```mermaid
flowchart TD
    START["validate(command)"] --> TRIM["command.trim()"]
    TRIM --> BLACKLIST{"Blacklist match?"}

    BLACKLIST -->|"Yes"| ERR1["Err(CommandDenied)<br/>'Matches blacklist pattern'"]
    BLACKLIST -->|"No"| MODE{"Mode?"}

    MODE -->|"Permissive"| OK["Ok(())"]
    MODE -->|"Strict"| WHITELIST{"Whitelist match?"}

    WHITELIST -->|"Yes"| OK
    WHITELIST -->|"No"| ERR2["Err(CommandDenied)<br/>'Not in whitelist (strict mode)'"]
```

### 🔧 API

```rust
impl CommandValidator {
    /// Creates a validator with pre-compiled regex
    pub fn new(config: &SecurityConfig) -> Self

    /// Reloads security rules (hot-reload)
    pub fn reload(&self, config: &SecurityConfig)

    /// Validates a command
    /// # Errors
    /// Returns `CommandDenied` if the command is blacklisted
    /// or not whitelisted in strict mode.
    pub fn validate(&self, command: &str) -> Result<()>
}
```

### 🔄 Hot-Reload

The `CommandValidator` supports hot-reloading of security rules via the `reload()` method. This feature is used by the `ConfigWatcher` to automatically update whitelist/blacklist patterns when the configuration file changes.

```mermaid
flowchart LR
    FS["config.yaml modified"] --> W["ConfigWatcher"]
    W --> LOAD["Load new config"]
    LOAD --> V["CommandValidator.reload()"]
    V --> COMPILE["Re-compile regex"]
    COMPILE --> SWAP["Atomic swap (RwLock)"]
```

### 🚫 Default Blacklist

| Pattern | Description | Blocked Example |
|---------|-------------|-----------------|
| `rm\s+-rf\s+/` | Root deletion | `rm -rf /` |
| `mkfs\.` | Disk formatting | `mkfs.ext4 /dev/sda` |
| `dd\s+if=` | Dangerous dd | `dd if=/dev/zero of=/dev/sda` |
| `>\s*/dev/` | Device write | `echo x > /dev/sda` |
| `chmod\s+777` | Dangerous permissions | `chmod 777 /etc` |
| `curl.*\|.*sh` | Remote execution | `curl url \| sh` |
| `wget.*\|.*sh` | Remote execution | `wget url \| sh` |

### 🔐 Security Modes

| Mode | Behavior |
|------|----------|
| **Strict** | Blacklist applied + Whitelist required |
| **Permissive** | Blacklist applied only |

```rust
// Strict mode: empty whitelist = ALL blocked
let config = SecurityConfig {
    mode: SecurityMode::Strict,
    whitelist: vec![],  // No command allowed
    ..Default::default()
};
validator.validate("ls")?;  // Err(CommandDenied)

// Permissive mode: blacklist only
let config = SecurityConfig {
    mode: SecurityMode::Permissive,
    blacklist: vec![r"rm\s+-rf"],
    ..Default::default()
};
validator.validate("ls")?;      // Ok
validator.validate("rm -rf")?;  // Err
```

## 🧹 Sanitizer (v1.0.0 - High Performance)

Masks sensitive information in outputs with an optimized multi-tier architecture.

### 🏗️ Architecture

```mermaid
flowchart LR
    subgraph Input["Input"]
        TEXT["Raw text"]
    end

    subgraph Tier1["Tier 1: Aho-Corasick"]
        AC["Keywords detection<br/>O(n) single-pass"]
    end

    subgraph Tier2["Tier 2: RegexSet"]
        RS["Pattern detection<br/>O(n) single-pass"]
    end

    subgraph Tier3["Tier 3: Processing"]
        SEQ["Sequential<br/>< 512KB"]
        PAR["Parallel (Rayon)<br/>> 512KB"]
    end

    subgraph Output["Output"]
        COW["Cow<str><br/>Zero-copy if no match"]
    end

    TEXT --> AC
    AC -->|"No keywords"| COW
    AC -->|"Keywords found"| RS
    RS -->|"No matches"| COW
    RS -->|"Matches"| SEQ
    RS -->|"Matches + Large"| PAR
    SEQ --> COW
    PAR --> COW
```

### 📋 Structure

```mermaid
classDiagram
    class Sanitizer {
        -patterns: Vec~SanitizePattern~
        -detection_set: RegexSet
        -literal_detector: AhoCorasick
        +new(patterns: &[String]) Self
        +with_defaults() Self
        +sanitize(text: &str) Cow~str~
        +sanitize_to_string(text: &str) String
        +pattern_count() usize
    }

    class SanitizePattern {
        +regex: Regex
        +replacement: String
        +description: &'static str
    }

    Sanitizer --> SanitizePattern
```

### 📋 Patterns (56 patterns in 5 tiers)

| Tier | Category | Examples |
|------|----------|----------|
| 1 | **Unique signatures** | `ghp_*`, `sk-*`, `xoxb-*`, `K10*`, JWT (`eyJ*`) |
| 2 | **Certificates/Keys** | PEM (RSA, OpenSSH, EC, PGP), Ansible Vault |
| 3 | **Specific tools** | Kubeconfig, Docker auth, connection strings |
| 4 | **Named variables** | `AWS_*`, `MYSQL_PASSWORD`, `GITLAB_TOKEN` |
| 5 | **Generic** | `password=`, `secret=`, `api_key=` |

### 🔍 Detailed Patterns

| Category | Pattern | Replacement |
|----------|---------|-------------|
| **GitHub** | `ghp_[A-Za-z0-9]{36}` | `[GITHUB_PAT_REDACTED]` |
| **OpenAI** | `sk-[A-Za-z0-9]{20,}` | `[OPENAI_API_KEY_REDACTED]` |
| **Slack** | `xox[baprs]-...` | `[SLACK_TOKEN_REDACTED]` |
| **K3s** | `K10[A-Za-z0-9]{48,}` | `[K3S_TOKEN_REDACTED]` |
| **JWT** | `eyJ...(3 parts)` | `[JWT_TOKEN_REDACTED]` |
| **AWS** | `AKIA[0-9A-Z]{16}` | `[AWS_ACCESS_KEY_REDACTED]` |
| **Private Keys** | `-----BEGIN...PRIVATE KEY-----` | `[PRIVATE_KEY_REDACTED]` |
| **Connection Strings** | `mysql://user:pass@host` | `mysql://[CREDENTIALS]@host` |
| **Passwords** | `password=xxx` | `password=[REDACTED]` |

### 📝 Examples

| Input | Output |
|-------|--------|
| `ghp_ABCDEFghijklmnopqrstuvwxyz123456` | `[GITHUB_PAT_REDACTED]` |
| `sk-proj-abcdefghij1234567890` | `[OPENAI_API_KEY_REDACTED]` |
| `xoxb-1234567890-abcdefghij` | `[SLACK_TOKEN_REDACTED]` |
| `K10abc123...` (50+ chars) | `[K3S_TOKEN_REDACTED]` |
| `mysql://root:pass@localhost` | `mysql://[CREDENTIALS]@localhost` |
| `-----BEGIN RSA PRIVATE KEY-----...` | `[PRIVATE_KEY_REDACTED]` |
| `MYSQL_ROOT_PASSWORD=secret` | `MYSQL_ROOT_PASSWORD=[REDACTED]` |

### ⚡ Performance

| Scenario | Before (v0.9) | After (v1.0) |
|----------|---------------|--------------|
| No secrets | O(n x 7 patterns) | **Zero-copy** |
| With secrets (<512KB) | O(n x 7) | O(n x matched patterns) |
| Large output (>512KB) | Sequential | **Parallel (Rayon)** |

### ⚙️ Configuration (v1.0.1+)

The sanitizer can be configured via `security.sanitize` in the YAML config:

```yaml
security:
  sanitize:
    # Enable/disable sanitization (default: true)
    enabled: true

    # Disable specific builtin pattern categories
    disable_builtin:
      - "gitlab"    # Disable GitLab token detection
      - "discord"   # Disable Discord webhook detection

    # Add custom patterns
    custom_patterns:
      - pattern: "INTERNAL_TOKEN_[A-Z0-9]{32}"
        replacement: "[INTERNAL_TOKEN_REDACTED]"
        description: "Internal service tokens"
```

### 📂 Pattern Categories

| Category | Patterns | Examples |
|----------|----------|----------|
| `github` | 5 | `ghp_*`, `gho_*`, `ghu_*`, `ghs_*`, `ghr_*` |
| `gitlab` | 1 | `glpat-*` |
| `slack` | 2 | `xox[baprs]-*`, webhooks |
| `discord` | 1 | Discord webhooks |
| `openai` | 1 | `sk-*` |
| `aws` | 3 | `AKIA*`, session tokens, env vars |
| `k3s` | 1 | `K10*` |
| `jwt` | 1 | `eyJ*.*.*` |
| `certificates` | 4 | RSA, OpenSSH, EC, PGP keys |
| `kubeconfig` | 4 | cert-data, token, client-key |
| `docker` | 2 | Registry auth, login |
| `database` | 4 | Connection strings, env passwords |
| `ansible` | 2 | Vault, become password |
| `azure` | 1 | Azure credentials |
| `gcp` | 1 | Google Cloud credentials |
| `hashicorp` | 2 | Vault, Consul tokens |
| `generic` | ~18 | `password=`, `secret=`, `api_key=`, etc. |

### 🔧 API

```rust
impl Sanitizer {
    /// Creates with custom patterns + defaults
    #[must_use]
    pub fn new(patterns: &[String]) -> Self

    /// Creates with only default patterns (56 patterns)
    #[must_use]
    pub fn with_defaults() -> Self

    /// Creates from SanitizeConfig with optional legacy patterns
    #[must_use]
    pub fn from_config_with_legacy(config: &SanitizeConfig, legacy: &[String]) -> Self

    /// Creates a disabled sanitizer (passthrough)
    #[must_use]
    pub fn disabled() -> Self

    /// Sanitizes text - returns Cow for zero-copy
    #[must_use]
    pub fn sanitize<'a>(&self, text: &'a str) -> Cow<'a, str>

    /// Sanitizes and returns String (compatibility)
    #[must_use]
    pub fn sanitize_to_string(&self, text: &str) -> String

    /// Number of active patterns
    #[must_use]
    pub fn pattern_count(&self) -> usize
}
```

## 📝 AuditLogger (Async)

Records all command events for security auditing.

Since v0.2.0, uses async channels for non-blocking writes.

### 📋 Structure

```mermaid
classDiagram
    class AuditLogger {
        -config: AuditConfig
        -sender: Option~UnboundedSender~AuditEvent~~
        +new(config) io::Result~(Self, Option~AuditWriterTask~)~
        +disabled() Self
        +log(event: AuditEvent) void
        +needs_rotation() bool
        +rotate() io::Result~()~
    }

    class AuditWriterTask {
        -rx: UnboundedReceiver~AuditEvent~
        -file: File
        +run() async
    }

    class AuditEvent {
        +timestamp: DateTime~Utc~
        +event_type: String
        +host: String
        +command: String
        +result: CommandResult
        +new(host, command, result) Self
        +denied(host, command, reason) Self
    }

    class CommandResult {
        <<enum>>
        Success: exit_code, duration_ms
        Error: message
        Denied: reason
    }

    AuditLogger --> AuditWriterTask : sends via mpsc
    AuditWriterTask --> AuditEvent : receives
    AuditEvent --> CommandResult
```

### 🏗️ Async Architecture

```mermaid
flowchart LR
    subgraph Request["Request"]
        EXEC["Execution"]
    end

    subgraph Logger["AuditLogger"]
        LOG["log()"]
        TRACE["tracing::info"]
        SEND["mpsc::send"]
    end

    subgraph Writer["AuditWriterTask"]
        RECV["recv()"]
        JSON["serde_json"]
        WRITE["spawn_blocking<br/>file.write()"]
    end

    EXEC --> LOG
    LOG --> TRACE
    LOG --> SEND
    SEND -.->|"async channel"| RECV
    RECV --> JSON
    JSON --> WRITE
```

### 📋 Log Format (JSON Lines)

```json
{"timestamp":"2024-01-15T10:30:45.123Z","event_type":"ssh_exec","host":"server1","command":"docker ps","result":{"Success":{"exit_code":0,"duration_ms":150}}}
{"timestamp":"2024-01-15T10:30:50.456Z","event_type":"command_denied","host":"server1","command":"rm -rf /","result":{"Denied":{"reason":"Matches blacklist pattern"}}}
```

### 📊 Event Types

| `event_type` | When | `CommandResult` |
|--------------|------|-----------------|
| `ssh_exec` | Command executed | `Success` or `Error` |
| `command_denied` | Command denied | `Denied` |

### 🔄 Log Rotation

```mermaid
flowchart TD
    CHECK["needs_rotation()"] --> SIZE{"file_size > max_size_mb?"}
    SIZE -->|"No"| CONTINUE["No rotation"]
    SIZE -->|"Yes"| ROTATE["rotate()"]

    ROTATE --> RENAME["audit.log -> audit.log.20240115_103045"]
    RENAME --> CLEANUP["Delete files > retain_days"]
    CLEANUP --> NEW["New audit.log created on next log()"]
```

### 🔧 API

```rust
impl AuditLogger {
    /// Creates a logger with file and background writer task
    /// # Errors
    /// If the file cannot be created/opened
    /// # Returns
    /// Tuple (logger, Option<writer_task>) - the task must be spawned
    pub fn new(config: &AuditConfig) -> io::Result<(Self, Option<AuditWriterTask>)>

    /// Creates a disabled logger (for tests)
    #[must_use]
    pub fn disabled() -> Self

    /// Logs an event (non-blocking: tracing + async send)
    pub fn log(&self, event: AuditEvent)

    /// Checks if rotation is needed
    pub fn needs_rotation(&self) -> bool

    /// Performs rotation
    /// # Errors
    /// If the file cannot be renamed
    pub fn rotate(&self) -> io::Result<()>
}

impl AuditWriterTask {
    /// Runs the write task (spawn with tokio::spawn)
    pub async fn run(self)
}

impl AuditEvent {
    /// Creates an execution event
    #[must_use]
    pub fn new(host: &str, command: &str, result: CommandResult) -> Self

    /// Creates a denial event
    #[must_use]
    pub fn denied(host: &str, command: &str, reason: &str) -> Self
}
```

### 💻 Usage

```rust
// Create logger and task
let (audit_logger, audit_task) = AuditLogger::new(&config.audit)?;
let audit_logger = Arc::new(audit_logger);

// Spawn the writer task (MCP server mode)
if let Some(task) = audit_task {
    tokio::spawn(task.run());
}

// Log (non-blocking)
audit_logger.log(AuditEvent::new("host", "cmd", result));
```

## ⏱️ RateLimiter

Limits request rate per host using the Token Bucket algorithm.

### 📋 Structure

```mermaid
classDiagram
    class RateLimiter {
        -rate_per_second: u32
        -buckets: RwLock~HashMap~String, TokenBucket~~
        +new(rate_per_second: u32) Self
        +check(host: &str) Result~()~
    }

    class TokenBucket {
        -tokens: f64
        -last_update: Instant
        -max_tokens: f64
        -refill_rate: f64
        +new(max_tokens, refill_rate) Self
        +try_consume() bool
    }

    RateLimiter --> TokenBucket : per host
```

### 🪣 Token Bucket Algorithm

```mermaid
flowchart TD
    REQ["check(host)"] --> RATE{"rate_per_second > 0?"}
    RATE -->|"No"| OK["Ok (disabled)"]
    RATE -->|"Yes"| BUCKET["get/create bucket"]

    BUCKET --> REFILL["refill tokens<br/>(elapsed x rate)"]
    REFILL --> CHECK{"tokens >= 1.0?"}

    CHECK -->|"Yes"| CONSUME["tokens -= 1.0"]
    CONSUME --> OK

    CHECK -->|"No"| ERR["RateLimitExceeded"]
```

### ⚙️ Configuration

```yaml
limits:
  rate_limit_per_second: 10  # 0 = disabled
```

### 🔧 API

```rust
impl RateLimiter {
    /// Creates a rate limiter (0 = disabled)
    #[must_use]
    pub fn new(rate_per_second: u32) -> Self

    /// Checks if the request is allowed for this host
    /// # Errors
    /// Returns `RateLimitExceeded` if rate is exceeded
    pub fn check(&self, host: &str) -> Result<()>
}
```

### Behavior

| Parameter | Value | Description |
|-----------|-------|-------------|
| `rate_per_second` | configurable | Tokens refill per second |
| `max_tokens` | = rate | Max burst = 1 second of requests |
| Initial bucket | full | First request always OK |

## 🧪 Tests

```bash
# All security tests
cargo test security::

# By module
cargo test security::validator::tests
cargo test security::sanitizer::tests
cargo test security::audit::tests
cargo test security::rate_limiter::tests
```

### ✅ Validator Tests

| Test | Description |
|------|-------------|
| `test_blacklist_blocks_dangerous_commands` | Blacklist blocks `rm -rf /` |
| `test_whitelist_in_strict_mode` | Strict mode: whitelist only |
| `test_permissive_mode_allows_unlisted` | Permissive: non-blacklisted = OK |
| `test_blacklist_overrides_whitelist` | Blacklist priority over whitelist |
| `test_invalid_whitelist_regex_is_skipped` | Invalid regex = skipped (logged) |
| `test_empty_whitelist_strict_mode_denies_all` | Strict + empty = all denied |
| `test_command_trimming` | Surrounding spaces = trimmed |

### 🧹 Sanitizer Tests

| Test | Description |
|------|-------------|
| `test_sanitize_password` | `password=xxx` -> `[REDACTED]` |
| `test_sanitize_api_key` | `API_KEY=xxx` -> `[REDACTED]` |
| `test_sanitize_private_key` | Private keys masked |
| `test_sanitize_connection_string` | URLs with creds masked |
| `test_custom_patterns` | Custom patterns work |
| `test_no_false_positives` | Normal text not modified |

### 📝 Audit Tests

| Test | Description |
|------|-------------|
| `test_audit_event_creation` | Success event creation |
| `test_audit_event_denied` | Denied event creation |
| `test_audit_event_serialization` | Correct JSON |
| `test_disabled_logger` | Disabled logger doesn't crash |
| `test_valid_audit_path` | Audit path validation |

### ⏱️ RateLimiter Tests

| Test | Description |
|------|-------------|
| `test_rate_limiter_disabled` | Rate = 0 allows all |
| `test_rate_limiter_allows_within_limit` | Requests within limit OK |
| `test_rate_limiter_blocks_over_limit` | Exceeded = `RateLimitExceeded` |
| `test_rate_limiter_refills_over_time` | Tokens refill |
| `test_rate_limiter_per_host` | Independent limits per host |

## 🎨 Design Patterns

| Pattern | Application |
|---------|-------------|
| **Strategy** | `CommandValidator` - configurable validation |
| **Chain of Responsibility** | `Sanitizer` - pattern chain |
| **Observer** | `AuditLogger` - observes events |
| **Factory** | `AuditLogger::new()`, `Sanitizer::with_defaults()` |
| **Producer/Consumer** | `AuditLogger` + `AuditWriterTask` via mpsc channel |
| **Token Bucket** | `RateLimiter` - rate control |
| **Per-Key State** | `RateLimiter` - bucket per host |

## ⚠️ Security Notes

> [!WARNING]
> **Blacklist is not sufficient**: In production, use `Strict` mode with an explicit whitelist.

> [!NOTE]
> **Invalid regex**: Invalid patterns are logged and skipped - the server doesn't crash.

> [!CAUTION]
> **Sanitization is not perfect**: It's a defense layer, not an absolute guarantee.

> [!NOTE]
> **Audit = detection**: Audit allows detecting abuse, not preventing it.
