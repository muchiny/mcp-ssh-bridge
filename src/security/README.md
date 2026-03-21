# 🔒 Security Module

This module implements security components: command validation, output sanitization, entropy-based secret detection, audit logging, session recording, and rate limiting.

## 📁 Module Structure

```
security/
📄 mod.rs          -> Public exports
📄 validator.rs    -> CommandValidator (whitelist/blacklist)
📄 sanitizer.rs    -> Sanitizer (secret masking)
📄 entropy.rs      -> EntropyDetector (Shannon entropy, Tier 4)
📄 audit.rs        -> AuditLogger + AuditWriterTask (async)
📄 recording.rs    -> SessionRecorder (asciinema v2 + HMAC hash chain)
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
        SAN["Sanitizer<br/>(Tiers 1-3)"]
        ENT["EntropyDetector<br/>(Tier 4)"]
        CLEAN["Cleaned output"]
    end

    subgraph Audit["AuditLogger"]
        LOG["audit.log"]
    end

    subgraph Recording["SessionRecorder"]
        REC["session.cast<br/>(asciinema v2)"]
    end

    CMD --> BL
    BL -->|"Match"| DENY["Denied"]
    BL -->|"No match"| WL
    WL -->|"Strict + No match"| DENY
    WL -->|"OK"| SSH
    SSH --> SAN
    SAN --> ENT
    ENT --> CLEAN

    DENY --> LOG
    SSH --> LOG
    SSH --> REC
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

### 📋 Patterns (56 regex patterns in 5 tiers + Tier 4 entropy detection)

| Tier | Category | Examples |
|------|----------|----------|
| 1 | **Unique signatures** | `ghp_*`, `sk-*`, `xoxb-*`, `K10*`, JWT (`eyJ*`) |
| 2 | **Certificates/Keys** | PEM (RSA, OpenSSH, EC, PGP), Ansible Vault |
| 3 | **Specific tools** | Kubeconfig, Docker auth, connection strings |
| 4 | **Named variables** | `AWS_*`, `MYSQL_PASSWORD`, `GITLAB_TOKEN` |
| 5 | **Generic** | `password=`, `secret=`, `api_key=` |

> 💡 **Beyond regex**: The `EntropyDetector` (see [below](#-entropydetector-tier-4---shannon-entropy)) adds a **Tier 4** catch-all layer that detects high-entropy strings (API keys, tokens, passwords) that don't match any of the 56 regex patterns above.

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

    /// Creates with only default regex patterns (56 patterns)
    /// Note: pair with EntropyDetector for Tier 4 coverage
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

## 🔬 EntropyDetector (Tier 4 — Shannon Entropy)

Catches secrets that slip past all 56 regex patterns by detecting high-entropy strings — the last line of defense in the sanitizer pipeline.

### 🏗️ Architecture

```mermaid
flowchart LR
    subgraph Pipeline["Sanitizer Pipeline"]
        direction LR
        T1["Tier 1<br/>Aho-Corasick<br/>Keywords"]
        T2["Tier 2<br/>RegexSet<br/>Patterns"]
        T3["Tier 3<br/>Processing<br/>Sequential/Parallel"]
        T4["🆕 Tier 4<br/>EntropyDetector<br/>Shannon entropy"]
    end

    INPUT["Raw output"] --> T1 --> T2 --> T3 --> T4 --> OUTPUT["Clean output"]

    style T4 fill:#f9e79f,stroke:#f39c12,stroke-width:2px
```

### 📊 Shannon Entropy Ranges

| Content Type | Entropy (bits/char) | Detected? |
|-------------|---------------------|-----------|
| English text | 3.5 – 4.5 | ❌ No |
| Hex secrets | 3.7 – 4.0 | ⚠️ Depends on threshold |
| Base64 API keys | 5.0 – 6.0 | ✅ Yes |
| Random bytes (base64) | ~5.95 | ✅ Yes |
| Single repeated char | 0.0 | ❌ No |

### 📋 Structure

```mermaid
classDiagram
    class EntropyDetector {
        -threshold: f64
        -min_length: usize
        -whitelist: Vec~String~
        -enabled: bool
        +new(threshold, min_length, whitelist, enabled) Self
        +disabled() Self
        +is_enabled() bool
        +shannon_entropy(s: &str) f64$
        +redact(text: &str) String
    }
```

### 🔍 Detection Algorithm

```mermaid
flowchart TD
    START["redact(text)"] --> ENABLED{"enabled?"}
    ENABLED -->|"No"| PASS["Return text unchanged"]
    ENABLED -->|"Yes"| TOKENS["Extract tokens<br/>(split on whitespace, =, :, quotes, commas)"]

    TOKENS --> SORT["Sort by length desc<br/>(avoid partial replacements)"]
    SORT --> LOOP["For each token"]

    LOOP --> LEN{"len >= min_length?"}
    LEN -->|"No"| SKIP["Skip"]
    LEN -->|"Yes"| WL{"In whitelist?"}

    WL -->|"Yes"| SKIP
    WL -->|"No"| SAFE{"Safe token?<br/>(path, URL, UUID,<br/>version, env name)"}

    SAFE -->|"Yes"| SKIP
    SAFE -->|"No"| CALC["Calculate Shannon entropy"]

    CALC --> THRESH{"entropy >= threshold?"}
    THRESH -->|"No"| SKIP
    THRESH -->|"Yes"| REDACT["Replace with<br/>[HIGH_ENTROPY_REDACTED]"]

    SKIP --> LOOP
    REDACT --> LOOP
```

### 🛡️ Safe Token Heuristics

The detector automatically skips common non-secret patterns to avoid false positives:

| Pattern | Example | Why Safe |
|---------|---------|----------|
| File paths | `/usr/local/bin/app` | Starts with `/`, `./`, `~/` |
| URLs | `https://api.example.com` | Starts with `http://`/`https://` |
| Hex colors | `#FF5733` | Starts with `#`, ≤7 chars |
| Version strings | `v12.34.56-beta-rc1` | Digits + dots + hyphens |
| Package names | `my-cool-package` | All lowercase + hyphens |
| Env var names | `MY_SECRET_KEY_NAME` | All uppercase + underscores |
| UUIDs | `550e8400-e29b-41d4-a716-446655440000` | 8-4-4-4-12 hex format |

### ⚙️ Configuration

```yaml
security:
  entropy:
    enabled: true          # Enable/disable (default: true)
    threshold: 4.5         # Min entropy to flag (default: 4.5 bits/char)
    min_length: 16         # Min token length to analyze (default: 16)
    whitelist:             # Known-safe high-entropy strings
      - "aBcDeFgHiJkLmNoP1234567890abcdef"
```

### 🔧 API

```rust
impl EntropyDetector {
    /// Creates a new detector with full configuration
    #[must_use]
    pub fn new(threshold: f64, min_length: usize, whitelist: Vec<String>, enabled: bool) -> Self

    /// Creates a disabled detector (pass-through)
    #[must_use]
    pub fn disabled() -> Self

    /// Check if entropy detection is enabled
    #[must_use]
    pub fn is_enabled(&self) -> bool

    /// Calculate Shannon entropy of a string (bits per character)
    /// Returns 0.0 (uniform) to ~6.5 (random base64)
    #[must_use]
    pub fn shannon_entropy(s: &str) -> f64

    /// Scan text and replace high-entropy tokens with [HIGH_ENTROPY_REDACTED]
    #[must_use]
    pub fn redact(&self, text: &str) -> String
}
```

### 📐 Default Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `threshold` | 4.5 | Bits per character to trigger redaction |
| `min_length` | 16 | Tokens shorter than this are skipped |
| `whitelist` | `[]` | Known-safe strings to never flag |
| `enabled` | `true` | Global on/off switch |

## 🎬 SessionRecorder (Asciinema v2 + HMAC Hash Chain)

Records SSH command sessions in [asciinema v2](https://docs.asciinema.org/manual/asciicast/v2/) format with an HMAC-SHA256 hash chain for tamper-proof compliance auditing. Designed for **SOC2**, **HIPAA**, and **PCI-DSS** audit trails.

### 🏗️ Architecture

```mermaid
flowchart TD
    subgraph MCP["MCP Server"]
        EXEC["Command Execution"]
    end

    subgraph Recorder["SessionRecorder"]
        START["start_session()"]
        REC_I["record_event('i', command)"]
        REC_O["record_event('o', output)"]
        STOP["stop_session()"]
    end

    subgraph Storage["Storage (.cast files)"]
        HEADER["Header (JSON)"]
        EVENTS["Events (JSON lines)"]
        HASH["HMAC-SHA256 hash chain"]
    end

    subgraph Operations["Operations"]
        LIST["list_recordings()"]
        REPLAY["replay_recording()"]
        VERIFY["verify_recording()"]
    end

    EXEC --> REC_I
    EXEC --> REC_O
    START --> HEADER
    REC_I --> EVENTS
    REC_O --> EVENTS
    EVENTS -.->|"each event"| HASH

    LIST --> Storage
    REPLAY --> Storage
    VERIFY --> HASH
```

### 🔗 HMAC-SHA256 Hash Chain

Each event is cryptographically linked to the previous one, making any tampering detectable:

```mermaid
flowchart LR
    G["genesis<br/>(seed)"] -->|"H₀ = HMAC(key, genesis, '')"| E0["Event 0<br/>hash: H₀"]
    E0 -->|"H₁ = HMAC(key, H₀, data₁)"| E1["Event 1<br/>hash: H₁"]
    E1 -->|"H₂ = HMAC(key, H₁, data₂)"| E2["Event 2<br/>hash: H₂"]
    E2 -->|"..."| EN["Event N<br/>hash: Hₙ"]

    style G fill:#d5f5e3,stroke:#27ae60
    style EN fill:#fadbd8,stroke:#e74c3c
```

**Hash computation**: `SHA256(key || previous_hash || "{time:.6}:{event_type}:{data}")`

If any event is modified, all subsequent hashes become invalid — `verify_recording()` pinpoints the exact tampered event index.

### 📋 Structure

```mermaid
classDiagram
    class SessionRecorder {
        -recordings_dir: PathBuf
        -sessions: Mutex~HashMap~String, ActiveSession~~
        -hash_chain_enabled: bool
        -hash_key: Vec~u8~
        -auto_mask_secrets: bool
        +new(dir, hash_chain, key, auto_mask) Self
        +start_session(host, title) Result~String~
        +record_event(session_id, type, data) Result~()~
        +stop_session(session_id) Result~RecordingInfo~
        +list_recordings() Result~Vec~RecordingInfo~~
        +replay_recording(path) Result~(Header, Vec~Event~)~$
        +verify_recording(path, key) Result~VerifyResult~$
    }

    class RecordingHeader {
        +version: u32
        +width: u32
        +height: u32
        +timestamp: i64
        +title: Option~String~
        +env: HashMap~String, String~
    }

    class RecordingEvent {
        +time: f64
        +event_type: String
        +data: String
        +hash: Option~String~
    }

    class RecordingInfo {
        +id: String
        +host: String
        +started_at: DateTime~Utc~
        +ended_at: Option~DateTime~Utc~~
        +event_count: usize
        +file_path: String
        +hash_chain_enabled: bool
    }

    class VerifyResult {
        +valid: bool
        +total_events: usize
        +verified_events: usize
        +first_invalid_index: Option~usize~
    }

    SessionRecorder --> RecordingHeader
    SessionRecorder --> RecordingEvent
    SessionRecorder --> RecordingInfo
    SessionRecorder --> VerifyResult
```

### 📄 Asciinema v2 File Format

Each `.cast` file consists of a JSON header line followed by JSON array event lines:

```json
{"version":2,"width":120,"height":40,"timestamp":1705312245,"title":"audit session","env":{"SHELL":"/bin/bash","TERM":"xterm-256color","MCP_HOST":"prod-server"}}
[0.000000, "i", "ls -la\r\n", "a1b2c3..."]
[0.150000, "o", "total 42\r\n", "d4e5f6..."]
[0.200000, "o", "-rw-r--r-- 1 root root 1234 file.txt\r\n", "g7h8i9..."]
```

| Field | Description |
|-------|-------------|
| `time` | Seconds elapsed since session start |
| `event_type` | `"i"` (input/command), `"o"` (output), `"m"` (marker) |
| `data` | Event content |
| `hash` | HMAC-SHA256 chain link (optional, 4th element) |

### 🔧 API

```rust
impl SessionRecorder {
    /// Create a new session recorder
    pub fn new(
        recordings_dir: PathBuf,
        hash_chain_enabled: bool,
        hash_key: Vec<u8>,
        auto_mask_secrets: bool,
    ) -> Self

    /// Whether auto secret masking is enabled
    #[must_use]
    pub fn auto_mask_secrets(&self) -> bool

    /// Start a new recording session
    /// Returns session ID (format: rec_{host}_{timestamp})
    pub fn start_session(&self, host: &str, title: Option<&str>) -> Result<String, String>

    /// Record an event to an active session
    pub fn record_event(
        &self, session_id: &str, event_type: &str, data: &str,
    ) -> Result<(), String>

    /// Stop a recording session and finalize the .cast file
    pub fn stop_session(&self, session_id: &str) -> Result<RecordingInfo, String>

    /// List all recordings (active + completed from filesystem)
    pub fn list_recordings(&self) -> Result<Vec<RecordingInfo>, String>

    /// Replay a recording file (returns header + all events)
    pub fn replay_recording(path: &Path) -> Result<(RecordingHeader, Vec<RecordingEvent>), String>

    /// Verify hash chain integrity — detects any tampering
    pub fn verify_recording(path: &Path, key: &[u8]) -> Result<VerifyResult, String>
}
```

### 🏛️ Compliance Use Cases

| Framework | How SessionRecorder Helps |
|-----------|--------------------------|
| **SOC2** | Complete audit trail of all SSH commands with tamper-proof hash chain |
| **HIPAA** | Session recordings prove who accessed what data and when |
| **PCI-DSS** | Verifiable, immutable logs of all actions on cardholder data environments |

### ⚙️ Configuration

```yaml
recording:
  enabled: true
  recordings_dir: "~/.config/mcp-ssh-bridge/recordings"
  hash_chain:
    enabled: true                    # Enable HMAC-SHA256 hash chain
    key: "your-secret-hmac-key"      # HMAC signing key
  auto_mask_secrets: true            # Sanitize secrets before recording
```

### 💻 Usage

```rust
// Create recorder with hash chain enabled
let recorder = SessionRecorder::new(
    PathBuf::from("/var/log/mcp-recordings"),
    true,                          // hash chain enabled
    b"my-secret-hmac-key".to_vec(),
    true,                          // auto-mask secrets
);

// Record a session
let session_id = recorder.start_session("prod-server", Some("deploy audit"))?;
recorder.record_event(&session_id, "i", "kubectl get pods")?;
recorder.record_event(&session_id, "o", "NAME     READY   STATUS\npod-1    1/1     Running")?;
let info = recorder.stop_session(&session_id)?;

// Verify integrity later
let result = SessionRecorder::verify_recording(
    Path::new(&info.file_path),
    b"my-secret-hmac-key",
)?;
assert!(result.valid);
println!("✅ All {} events verified", result.verified_events);
```

## 🧪 Tests

```bash
# All security tests
cargo test security::

# By module
cargo test security::validator::tests
cargo test security::sanitizer::tests
cargo test security::entropy::tests
cargo test security::audit::tests
cargo test security::recording::tests
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
