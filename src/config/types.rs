use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub hosts: HashMap<String, HostConfig>,

    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub limits: LimitsConfig,

    #[serde(default)]
    pub audit: AuditConfig,

    #[serde(default)]
    pub sessions: SessionConfig,

    #[serde(default)]
    pub tool_groups: ToolGroupsConfig,

    #[serde(default)]
    pub ssh_config: SshConfigDiscovery,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostConfig {
    pub hostname: String,

    #[serde(default = "default_port")]
    pub port: u16,

    pub user: String,

    pub auth: AuthConfig,

    /// Optional description for this host
    #[serde(default)]
    pub description: Option<String>,

    /// Host key verification mode for this host
    #[serde(default)]
    pub host_key_verification: HostKeyVerification,

    /// Optional jump host (bastion) alias to connect through
    ///
    /// When set, the connection to this host will be tunneled through
    /// the specified jump host using SSH port forwarding.
    #[serde(default)]
    pub proxy_jump: Option<String>,

    /// Optional SOCKS proxy to connect through (alternative to `proxy_jump`).
    ///
    /// When set, the SSH connection will be tunneled through the specified
    /// SOCKS proxy. Mutually exclusive with `proxy_jump`.
    #[serde(default)]
    pub socks_proxy: Option<SocksProxyConfig>,

    /// Optional sudo password for this host (used with sudo commands)
    #[serde(default)]
    pub sudo_password: Option<String>,

    /// Remote operating system type (default: linux).
    ///
    /// Affects shell escaping, session initialization, and available tool groups.
    #[serde(default)]
    pub os_type: OsType,

    /// Shell type used on the remote host.
    ///
    /// If not set, inferred from `os_type`: Linux -> posix, Windows -> cmd.
    /// Override to `powershell` if the Windows host has `PowerShell` as default shell.
    #[serde(default)]
    pub shell: Option<ShellType>,
}

impl HostConfig {
    /// Resolve the effective shell type for this host.
    ///
    /// If `shell` is explicitly set, use that. Otherwise, infer from `os_type`.
    #[must_use]
    pub fn effective_shell(&self) -> ShellType {
        self.shell.unwrap_or(match self.os_type {
            OsType::Linux => ShellType::Posix,
            OsType::Windows => ShellType::Cmd,
        })
    }
}

/// Host key verification mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HostKeyVerification {
    /// Strict: reject unknown hosts, reject mismatched keys (most secure, default)
    #[default]
    Strict,
    /// Accept new: add unknown hosts to `known_hosts`, reject mismatched keys
    AcceptNew,
    /// Off: accept all keys (insecure, for testing only)
    Off,
}

/// Remote operating system type.
///
/// Determines shell escaping rules, session initialization, and which
/// tool groups are available. Defaults to `Linux` for backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    /// Linux/Unix host (default)
    #[default]
    Linux,
    /// Windows host via `OpenSSH` for Windows
    Windows,
}

/// Shell type used on the remote host.
///
/// Controls argument escaping and session initialization.
/// Inferred from `OsType` if not explicitly set:
/// `Linux` -> `Posix`, `Windows` -> `Cmd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellType {
    /// POSIX shell (bash, sh, zsh) -- single-quote escaping
    Posix,
    /// Windows `cmd.exe` -- caret escaping, double-quote wrapping
    Cmd,
    /// `PowerShell` (`pwsh` / `powershell.exe`) -- single-quote with doubling
    #[serde(alias = "pwsh")]
    PowerShell,
}

const fn default_port() -> u16 {
    22
}

/// SOCKS proxy configuration for tunneling SSH connections
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SocksProxyConfig {
    /// Proxy hostname or IP
    pub hostname: String,

    /// Proxy port (default: 1080)
    #[serde(default = "default_socks_port")]
    pub port: u16,

    /// SOCKS version: `socks5` (default) or `socks4`
    #[serde(default)]
    pub version: SocksVersion,

    /// Optional username for SOCKS5 authentication
    #[serde(default)]
    pub username: Option<String>,

    /// Optional password for SOCKS5 authentication
    #[serde(default)]
    pub password: Option<String>,
}

/// SOCKS protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SocksVersion {
    /// SOCKS5 (default) - supports authentication and UDP
    #[default]
    Socks5,
    /// SOCKS4 - simpler, no authentication support
    Socks4,
}

const fn default_socks_port() -> u16 {
    1080
}

/// SSH authentication configuration.
///
/// Sensitive fields (`password`, `passphrase`) are wrapped in [`Zeroizing`]
/// so they are securely erased from memory when the config is dropped
/// (e.g. on hot-reload or process exit).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    Key {
        path: String,
        #[serde(default)]
        passphrase: Option<Zeroizing<String>>,
    },
    Agent,
    Password {
        password: Zeroizing<String>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    #[serde(default = "default_security_mode")]
    pub mode: SecurityMode,

    #[serde(default)]
    pub whitelist: Vec<String>,

    #[serde(default = "default_blacklist")]
    pub blacklist: Vec<String>,

    /// Legacy field for backward compatibility (use `sanitize` instead)
    #[serde(default)]
    pub sanitize_patterns: Vec<String>,

    /// Advanced sanitizer configuration
    #[serde(default)]
    pub sanitize: SanitizeConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            mode: default_security_mode(),
            whitelist: Vec::new(),
            blacklist: default_blacklist(),
            sanitize_patterns: Vec::new(),
            sanitize: SanitizeConfig::default(),
        }
    }
}

/// Advanced sanitizer configuration
///
/// Allows fine-grained control over output sanitization:
/// - Enable/disable sanitization
/// - Disable specific builtin pattern categories
/// - Add custom patterns with custom replacement text
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SanitizeConfig {
    /// Enable/disable sanitization entirely (default: true)
    #[serde(default = "default_sanitize_enabled")]
    pub enabled: bool,

    /// Builtin pattern categories to disable.
    ///
    /// Available categories:
    /// - `"github"` - GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
    /// - `"gitlab"` - GitLab tokens (glpat-)
    /// - `"slack"` - Slack tokens and webhooks
    /// - `"discord"` - Discord webhooks
    /// - `"openai"` - `OpenAI` API keys (sk-)
    /// - `"aws"` - AWS credentials (AKIA, access keys, session tokens)
    /// - `"k3s"` - K3s/Kubernetes tokens
    /// - `"jwt"` - JWT tokens (eyJ...)
    /// - `"certificates"` - Private keys (RSA, OpenSSH, EC, PGP)
    /// - `"kubeconfig"` - Kubeconfig credentials
    /// - `"docker"` - Docker registry auth and login
    /// - `"database"` - Database connection strings and passwords
    /// - `"ansible"` - Ansible vault and become passwords
    /// - `"azure"` - Azure credentials
    /// - `"gcp"` - Google Cloud credentials
    /// - `"hashicorp"` - Vault and Consul tokens
    /// - `"generic"` - Generic password/secret/token patterns
    #[serde(default)]
    pub disable_builtin: Vec<String>,

    /// Custom patterns with custom replacements
    #[serde(default)]
    pub custom_patterns: Vec<CustomSanitizePattern>,
}

impl Default for SanitizeConfig {
    fn default() -> Self {
        Self {
            enabled: default_sanitize_enabled(),
            disable_builtin: Vec::new(),
            custom_patterns: Vec::new(),
        }
    }
}

const fn default_sanitize_enabled() -> bool {
    true
}

/// Custom sanitization pattern with configurable replacement
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomSanitizePattern {
    /// Regex pattern to match sensitive data
    pub pattern: String,

    /// Replacement text (default: `[REDACTED]`)
    /// Supports capture groups: $1, $2, etc.
    #[serde(default = "default_replacement")]
    pub replacement: String,

    /// Optional description for documentation/debugging
    #[serde(default)]
    pub description: Option<String>,
}

fn default_replacement() -> String {
    "[REDACTED]".to_string()
}

const fn default_security_mode() -> SecurityMode {
    SecurityMode::Standard
}

fn default_blacklist() -> Vec<String> {
    vec![
        r"(?i)rm\s+-rf\s+/".to_string(),
        r"(?i)mkfs\.".to_string(),
        r"(?i)dd\s+if=".to_string(),
        r"(?i)>\s*/dev/".to_string(),
        r"(?i)chmod\s+777".to_string(),
        r"(?i)curl.*\|.*sh".to_string(),
        r"(?i)wget.*\|.*sh".to_string(),
        r"(?i)\breboot\b".to_string(),
        r"(?i)\bpoweroff\b".to_string(),
        r"(?i)\bhalt\b".to_string(),
        r"(?i)\bshutdown\b".to_string(),
        r"(?i)\biptables\s+-F\b".to_string(),
        // Redis destructive commands
        r"(?i)\bredis-cli\b.*\b(FLUSHALL|FLUSHDB|SHUTDOWN)\b".to_string(),
        // Terraform destructive commands
        r"(?i)\bterraform\s+destroy\b".to_string(),
        r"(?i)\bterraform\s+state\s+rm\b".to_string(),
        // Vault destructive commands
        r"(?i)\bvault\s+(delete|kv\s+delete)\b".to_string(),
        // Systemd service disruption
        r"(?i)\bsystemctl\s+(stop|disable|isolate)\b".to_string(),
        // Cron wipe
        r"(?i)\bcrontab\s+-r\b".to_string(),
        // Firewall disable
        r"(?i)\bufw\s+disable\b".to_string(),
        // Nginx stop
        r"(?i)\bnginx\s+-s\s+stop\b".to_string(),
        // === Windows dangerous commands ===
        // Recursive deletion (rd /s, Remove-Item -Recurse)
        r"(?i)\brd\s+/s".to_string(),
        r"(?i)\bRemove-Item\b.*-Recurse".to_string(),
        // Disk formatting
        r"(?i)\bformat\s+[a-z]:".to_string(),
        r"(?i)\bdiskpart\b".to_string(),
        // System shutdown/restart
        r"(?i)\bRestart-Computer\b".to_string(),
        r"(?i)\bStop-Computer\b".to_string(),
        // Dangerous code execution via PowerShell
        r"(?i)\bInvoke-Expression\b".to_string(),
        r"(?i)\biex\b".to_string(),
        r"(?i)Invoke-WebRequest.*\|.*Invoke-Expression".to_string(),
        // Firewall disable
        r"(?i)\bnetsh\s+advfirewall\s+set\b.*\boff\b".to_string(),
        r"(?i)\bSet-NetFirewallProfile\b.*\bFalse\b".to_string(),
        // Service deletion
        r"(?i)\bsc\s+delete\b".to_string(),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityMode {
    Strict,
    #[serde(alias = "normal")]
    Standard,
    Permissive,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsConfig {
    #[serde(default = "default_command_timeout")]
    pub command_timeout_seconds: u64,

    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: usize,

    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_commands: usize,

    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_seconds: u64,

    #[serde(default = "default_keepalive")]
    pub keepalive_interval_seconds: u64,

    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,

    #[serde(default = "default_retry_initial_delay_ms")]
    pub retry_initial_delay_ms: u64,

    /// Rate limit: maximum requests per second per host (0 = disabled)
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_second: u32,

    /// Maximum output characters returned by tool calls (default: 20000).
    /// Individual tool calls can override this with their `max_output` parameter.
    /// At ~3-4 chars/token, 20000 chars ≈ 5-7K tokens — a conservative default that
    /// works with all AI models. Use `client_overrides` to raise for larger-context models.
    /// Set to 0 to disable truncation.
    #[serde(default = "default_max_output_chars")]
    pub max_output_chars: usize,

    /// Per-client overrides for `max_output_chars`, matched by MCP client name.
    /// Detected automatically during MCP `initialize` handshake.
    #[serde(default)]
    pub client_overrides: Vec<ClientOverride>,

    /// TTL in seconds for cached full outputs used by `ssh_output_fetch` pagination
    /// (default: 300 = 5 minutes)
    #[serde(default = "default_output_cache_ttl")]
    pub output_cache_ttl_seconds: u64,

    /// Maximum number of cached output entries kept in memory (default: 100)
    #[serde(default = "default_output_cache_max_entries")]
    pub output_cache_max_entries: usize,

    /// Maximum number of concurrent async tasks (default: 50).
    /// When the limit is reached, new task-augmented requests are rejected.
    #[serde(default = "default_max_tasks")]
    pub max_tasks: usize,

    /// Maximum TTL for async tasks in milliseconds (default: 3600000 = 1 hour).
    /// Client-requested TTLs are capped to this value.
    #[serde(default = "default_max_task_ttl_ms")]
    pub max_task_ttl_ms: u64,

    /// Default poll interval hint for async tasks in milliseconds (default: 2000).
    /// Clients use this to determine how often to poll `tasks/get`.
    #[serde(default = "default_task_poll_interval_ms")]
    pub task_poll_interval_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            command_timeout_seconds: default_command_timeout(),
            max_output_bytes: default_max_output_bytes(),
            max_concurrent_commands: default_max_concurrent(),
            connection_timeout_seconds: default_connection_timeout(),
            keepalive_interval_seconds: default_keepalive(),
            retry_attempts: default_retry_attempts(),
            retry_initial_delay_ms: default_retry_initial_delay_ms(),
            rate_limit_per_second: default_rate_limit(),
            max_output_chars: default_max_output_chars(),
            client_overrides: Vec::new(),
            output_cache_ttl_seconds: default_output_cache_ttl(),
            output_cache_max_entries: default_output_cache_max_entries(),
            max_tasks: default_max_tasks(),
            max_task_ttl_ms: default_max_task_ttl_ms(),
            task_poll_interval_ms: default_task_poll_interval_ms(),
        }
    }
}

impl LimitsConfig {
    /// Create a `RetryConfig` from these limits settings
    #[must_use]
    pub fn retry_config(&self) -> crate::ssh::RetryConfig {
        crate::ssh::RetryConfig {
            max_attempts: self.retry_attempts,
            initial_delay_ms: self.retry_initial_delay_ms,
            ..Default::default()
        }
    }

    /// Resolve the effective `max_output_chars` for a given MCP client.
    ///
    /// Resolution order:
    /// 1. First matching `client_overrides` entry (case-insensitive, using `match_mode`)
    /// 2. `self.max_output_chars` (YAML config or default)
    #[must_use]
    pub fn effective_max_output_chars(&self, client_name: Option<&str>) -> usize {
        if let Some(name) = client_name {
            let name_lower = name.to_lowercase();
            for ov in &self.client_overrides {
                let pattern = ov.name_contains.to_lowercase();
                let matched = match ov.match_mode {
                    MatchMode::Exact => name_lower == pattern,
                    MatchMode::Prefix => name_lower.starts_with(&pattern),
                    MatchMode::Contains => name_lower.contains(&pattern),
                };
                if matched && let Some(max) = ov.max_output_chars {
                    return max;
                }
            }
        }
        self.max_output_chars
    }
}

/// How to match the `name_contains` pattern against the MCP client name.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    /// Exact match (case-insensitive): `"claude-code"` matches `"Claude-Code"`
    Exact,
    /// Prefix match (case-insensitive): `"claude"` matches `"claude-code"` but not `"not-claude"`
    #[default]
    Prefix,
    /// Substring match (case-insensitive): `"claude"` matches `"not-claude"` (legacy behavior)
    Contains,
}

/// Per-client override for output limits, matched by MCP client name.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientOverride {
    /// Pattern to match against the MCP client name (case-insensitive)
    pub name_contains: String,

    /// How to match the pattern against the client name (default: prefix)
    #[serde(default)]
    pub match_mode: MatchMode,

    /// Override for `max_output_chars` when this client is detected
    #[serde(default)]
    pub max_output_chars: Option<usize>,
}

const fn default_command_timeout() -> u64 {
    1800 // 30 minutes - supports long-running tasks like Molecule tests
}

const fn default_max_output_bytes() -> usize {
    10 * 1024 * 1024 // 10MB
}

const fn default_max_concurrent() -> usize {
    5
}

const fn default_connection_timeout() -> u64 {
    10
}

const fn default_keepalive() -> u64 {
    30
}

const fn default_retry_attempts() -> u32 {
    3
}

const fn default_retry_initial_delay_ms() -> u64 {
    100
}

const fn default_rate_limit() -> u32 {
    0 // Disabled by default
}

const fn default_max_output_chars() -> usize {
    20_000 // ~5-7K tokens, conservative default compatible with all AI models
}

const fn default_output_cache_ttl() -> u64 {
    300 // 5 minutes
}

const fn default_output_cache_max_entries() -> usize {
    100
}

const fn default_max_tasks() -> usize {
    50
}

const fn default_max_task_ttl_ms() -> u64 {
    3_600_000 // 1 hour
}

const fn default_task_poll_interval_ms() -> u64 {
    2_000 // 2 seconds
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditConfig {
    #[serde(default = "default_audit_enabled")]
    pub enabled: bool,

    #[serde(default = "default_audit_path")]
    pub path: PathBuf,

    #[serde(default = "default_audit_max_size")]
    pub max_size_mb: u64,

    #[serde(default = "default_audit_retain")]
    pub retain_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: default_audit_enabled(),
            path: default_audit_path(),
            max_size_mb: default_audit_max_size(),
            retain_days: default_audit_retain(),
        }
    }
}

const fn default_audit_enabled() -> bool {
    true
}

fn default_audit_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mcp-ssh-bridge")
        .join("audit.log")
}

const fn default_audit_max_size() -> u64 {
    100
}

const fn default_audit_retain() -> u32 {
    30
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    /// Maximum number of concurrent sessions
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,

    /// Idle timeout in seconds before a session is closed
    #[serde(default = "default_session_idle_timeout")]
    pub idle_timeout_seconds: u64,

    /// Maximum session age in seconds before forced closure
    #[serde(default = "default_session_max_age")]
    pub max_age_seconds: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_sessions: default_max_sessions(),
            idle_timeout_seconds: default_session_idle_timeout(),
            max_age_seconds: default_session_max_age(),
        }
    }
}

const fn default_max_sessions() -> usize {
    10
}

const fn default_session_idle_timeout() -> u64 {
    300 // 5 minutes
}

const fn default_session_max_age() -> u64 {
    3600 // 1 hour
}

/// SSH config auto-discovery configuration
///
/// When enabled, the bridge will parse `~/.ssh/config` and automatically
/// discover hosts. YAML-defined hosts take precedence over discovered ones.
/// Enabled by default to reduce time-to-first-command.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SshConfigDiscovery {
    /// Enable SSH config auto-discovery (default: true)
    #[serde(default = "default_ssh_config_enabled")]
    pub enabled: bool,

    /// Path to the SSH config file (default: `~/.ssh/config`)
    #[serde(default = "default_ssh_config_path")]
    pub path: String,

    /// Host aliases to exclude from discovery
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl Default for SshConfigDiscovery {
    fn default() -> Self {
        Self {
            enabled: default_ssh_config_enabled(),
            path: default_ssh_config_path(),
            exclude: Vec::new(),
        }
    }
}

const fn default_ssh_config_enabled() -> bool {
    true
}

fn default_ssh_config_path() -> String {
    "~/.ssh/config".to_string()
}

/// Tool group activation configuration
///
/// Allows enabling or disabling groups of tools to reduce the MCP context
/// sent to the LLM. By default, all groups are enabled.
///
/// Available groups (38 groups, 197 tools):
/// - `core`: `ssh_exec`, `ssh_exec_multi`, `ssh_status`, `ssh_health`, `ssh_history`,
///   `ssh_output_fetch`
/// - `config`: `ssh_config_get`, `ssh_config_set`
/// - `file_transfer`: `ssh_upload`, `ssh_download`, `ssh_sync`
/// - `sessions`: `ssh_session_create`, `ssh_session_exec`, `ssh_session_list`, `ssh_session_close`
/// - `monitoring`: `ssh_metrics`, `ssh_metrics_multi`, `ssh_tail`, `ssh_disk_usage`
/// - `tunnels`: `ssh_tunnel_create`, `ssh_tunnel_list`, `ssh_tunnel_close`
/// - `directory`: `ssh_ls`, `ssh_find`
/// - `database`: `ssh_db_query`, `ssh_db_dump`, `ssh_db_restore`
/// - `backup`: `ssh_backup_create`, `ssh_backup_list`, `ssh_backup_restore`
/// - `docker`: `ssh_docker_ps`, `ssh_docker_logs`, `ssh_docker_inspect`, `ssh_docker_exec`,
///   `ssh_docker_compose`, `ssh_docker_images`, `ssh_docker_stats`, `ssh_docker_volume_ls`,
///   `ssh_docker_network_ls`, `ssh_docker_volume_inspect`, `ssh_docker_network_inspect`
/// - `esxi`: `ssh_esxi_vm_list`, `ssh_esxi_vm_info`, `ssh_esxi_vm_power`, `ssh_esxi_snapshot`,
///   `ssh_esxi_host_info`, `ssh_esxi_datastore_list`, `ssh_esxi_network_list`
/// - `git`: `ssh_git_status`, `ssh_git_log`, `ssh_git_diff`, `ssh_git_pull`, `ssh_git_clone`,
///   `ssh_git_branch`, `ssh_git_checkout`
/// - `kubernetes`: `ssh_k8s_get`, `ssh_k8s_logs`, `ssh_k8s_describe`, `ssh_k8s_apply`,
///   `ssh_k8s_delete`, `ssh_k8s_rollout`, `ssh_k8s_scale`, `ssh_k8s_exec`, `ssh_k8s_top`,
///   `ssh_helm_list`, `ssh_helm_status`, `ssh_helm_upgrade`, `ssh_helm_install`,
///   `ssh_helm_rollback`, `ssh_helm_history`, `ssh_helm_uninstall`
/// - `ansible`: `ssh_ansible_playbook`, `ssh_ansible_inventory`, `ssh_ansible_adhoc`
/// - `systemd`: `ssh_service_status`, `ssh_service_start`, `ssh_service_stop`,
///   `ssh_service_restart`, `ssh_service_list`, `ssh_service_logs`, `ssh_service_enable`,
///   `ssh_service_disable`, `ssh_service_daemon_reload`
/// - `network`: `ssh_net_connections`, `ssh_net_interfaces`, `ssh_net_routes`, `ssh_net_ping`,
///   `ssh_net_traceroute`, `ssh_net_dns`
/// - `process`: `ssh_process_list`, `ssh_process_kill`, `ssh_process_top`
/// - `package`: `ssh_pkg_list`, `ssh_pkg_search`, `ssh_pkg_install`, `ssh_pkg_update`,
///   `ssh_pkg_remove`
/// - `firewall`: `ssh_firewall_status`, `ssh_firewall_list`, `ssh_firewall_allow`,
///   `ssh_firewall_deny`
/// - `cron`: `ssh_cron_list`, `ssh_cron_add`, `ssh_cron_remove`
/// - `certificates`: `ssh_cert_check`, `ssh_cert_info`, `ssh_cert_expiry`
/// - `nginx`: `ssh_nginx_status`, `ssh_nginx_test`, `ssh_nginx_reload`, `ssh_nginx_list_sites`
/// - `redis`: `ssh_redis_info`, `ssh_redis_cli`, `ssh_redis_keys`
/// - `terraform`: `ssh_terraform_init`, `ssh_terraform_plan`, `ssh_terraform_apply`,
///   `ssh_terraform_state`, `ssh_terraform_output`
/// - `vault`: `ssh_vault_status`, `ssh_vault_read`, `ssh_vault_list`, `ssh_vault_write`
/// - `windows_services`: `ssh_win_service_status`, `ssh_win_service_start`,
///   `ssh_win_service_stop`, `ssh_win_service_restart`, `ssh_win_service_list`,
///   `ssh_win_service_enable`, `ssh_win_service_disable`, `ssh_win_service_config`,
///   `ssh_win_event_logs`
/// - `windows_events`: `ssh_win_event_query`, `ssh_win_event_sources`, `ssh_win_event_tail`,
///   `ssh_win_event_export`
/// - `active_directory`: `ssh_ad_user_list`, `ssh_ad_user_info`, `ssh_ad_group_list`,
///   `ssh_ad_group_members`, `ssh_ad_computer_list`, `ssh_ad_domain_info`
/// - `scheduled_tasks`: `ssh_schtask_list`, `ssh_schtask_info`, `ssh_schtask_run`,
///   `ssh_schtask_enable`, `ssh_schtask_disable`
/// - `windows_firewall`: `ssh_win_firewall_status`, `ssh_win_firewall_list`,
///   `ssh_win_firewall_allow`, `ssh_win_firewall_deny`, `ssh_win_firewall_remove`
/// - `iis`: `ssh_iis_status`, `ssh_iis_list_sites`, `ssh_iis_list_pools`, `ssh_iis_start`,
///   `ssh_iis_stop`, `ssh_iis_restart`
/// - `windows_updates`: `ssh_win_update_list`, `ssh_win_update_history`,
///   `ssh_win_update_install`, `ssh_win_update_search`, `ssh_win_update_reboot`
/// - `windows_perf`: `ssh_win_perf_cpu`, `ssh_win_perf_memory`, `ssh_win_perf_disk`,
///   `ssh_win_perf_network`, `ssh_win_perf_overview`
/// - `hyperv`: `ssh_hyperv_vm_list`, `ssh_hyperv_vm_info`, `ssh_hyperv_vm_start`,
///   `ssh_hyperv_vm_stop`, `ssh_hyperv_snapshot_list`, `ssh_hyperv_snapshot_create`,
///   `ssh_hyperv_host_info`, `ssh_hyperv_switch_list`
/// - `windows_registry`: `ssh_reg_query`, `ssh_reg_set`, `ssh_reg_list`, `ssh_reg_export`,
///   `ssh_reg_delete`
/// - `windows_features`: `ssh_win_feature_list`, `ssh_win_feature_info`,
///   `ssh_win_feature_install`, `ssh_win_feature_remove`
/// - `windows_network`: `ssh_win_net_adapters`, `ssh_win_net_ip`, `ssh_win_net_routes`,
///   `ssh_win_net_connections`, `ssh_win_net_ping`, `ssh_win_net_dns`
/// - `windows_process`: `ssh_win_process_list`, `ssh_win_process_info`,
///   `ssh_win_process_kill`, `ssh_win_process_top`, `ssh_win_process_by_name`,
///   `ssh_win_disk_usage`
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ToolGroupsConfig {
    /// Map of group name to enabled status.
    /// Groups not listed are enabled by default.
    #[serde(default)]
    pub groups: HashMap<String, bool>,
}

impl ToolGroupsConfig {
    /// Check if a given tool group is enabled.
    /// Groups not explicitly listed default to enabled.
    #[must_use]
    pub fn is_group_enabled(&self, group: &str) -> bool {
        self.groups.get(group).copied().unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== SecurityConfig Tests ==============

    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert_eq!(config.mode, SecurityMode::Standard);
        assert!(config.whitelist.is_empty());
        assert!(!config.blacklist.is_empty()); // Has default blacklist
        assert!(config.sanitize_patterns.is_empty());
        assert!(config.sanitize.enabled);
    }

    #[test]
    fn test_security_mode_serialization() {
        let strict = SecurityMode::Strict;
        let standard = SecurityMode::Standard;
        let permissive = SecurityMode::Permissive;

        assert_eq!(serde_json::to_string(&strict).unwrap(), "\"strict\"");
        assert_eq!(serde_json::to_string(&standard).unwrap(), "\"standard\"");
        assert_eq!(
            serde_json::to_string(&permissive).unwrap(),
            "\"permissive\""
        );
    }

    #[test]
    fn test_security_mode_deserialization() {
        let strict: SecurityMode = serde_json::from_str("\"strict\"").unwrap();
        let standard: SecurityMode = serde_json::from_str("\"standard\"").unwrap();
        let normal: SecurityMode = serde_json::from_str("\"normal\"").unwrap();
        let permissive: SecurityMode = serde_json::from_str("\"permissive\"").unwrap();

        assert_eq!(strict, SecurityMode::Strict);
        assert_eq!(standard, SecurityMode::Standard);
        assert_eq!(normal, SecurityMode::Standard); // "normal" is alias for "standard"
        assert_eq!(permissive, SecurityMode::Permissive);
    }

    #[test]
    fn test_default_blacklist_patterns() {
        let blacklist = default_blacklist();
        assert!(blacklist.iter().any(|p| p.contains("rm")));
        assert!(blacklist.iter().any(|p| p.contains("mkfs")));
        assert!(blacklist.iter().any(|p| p.contains("dd")));
        assert!(blacklist.iter().any(|p| p.contains("chmod")));
        assert!(blacklist.iter().any(|p| p.contains("curl")));
        assert!(blacklist.iter().any(|p| p.contains("reboot")));
        assert!(blacklist.iter().any(|p| p.contains("poweroff")));
        assert!(blacklist.iter().any(|p| p.contains("shutdown")));
        assert!(blacklist.iter().any(|p| p.contains("iptables")));
    }

    // ============== HostKeyVerification Tests ==============

    #[test]
    fn test_host_key_verification_default() {
        let default = HostKeyVerification::default();
        assert_eq!(default, HostKeyVerification::Strict);
    }

    #[test]
    fn test_host_key_verification_serialization() {
        let strict = HostKeyVerification::Strict;
        let acceptnew = HostKeyVerification::AcceptNew;
        let off = HostKeyVerification::Off;

        assert_eq!(serde_json::to_string(&strict).unwrap(), "\"strict\"");
        assert_eq!(serde_json::to_string(&acceptnew).unwrap(), "\"acceptnew\"");
        assert_eq!(serde_json::to_string(&off).unwrap(), "\"off\"");
    }

    #[test]
    fn test_host_key_verification_deserialization() {
        let strict: HostKeyVerification = serde_json::from_str("\"strict\"").unwrap();
        let acceptnew: HostKeyVerification = serde_json::from_str("\"acceptnew\"").unwrap();
        let off: HostKeyVerification = serde_json::from_str("\"off\"").unwrap();

        assert_eq!(strict, HostKeyVerification::Strict);
        assert_eq!(acceptnew, HostKeyVerification::AcceptNew);
        assert_eq!(off, HostKeyVerification::Off);
    }

    // ============== AuthConfig Tests ==============

    #[test]
    fn test_auth_config_key_serialization() {
        let auth = AuthConfig::Key {
            path: "/path/to/key".to_string(),
            passphrase: Some(Zeroizing::new("secret".to_string())),
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"key\""));
        assert!(json.contains("\"/path/to/key\""));
    }

    #[test]
    fn test_auth_config_agent_serialization() {
        let auth = AuthConfig::Agent;
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"agent\""));
    }

    #[test]
    fn test_auth_config_password_serialization() {
        let auth = AuthConfig::Password {
            password: Zeroizing::new("secret123".to_string()),
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"password\""));
        assert!(json.contains("\"secret123\""));
    }

    #[test]
    fn test_auth_config_deserialization() {
        let key_json = r#"{"type":"key","path":"/path/to/key"}"#;
        let agent_json = r#"{"type":"agent"}"#;
        let password_json = r#"{"type":"password","password":"secret"}"#;

        let key: AuthConfig = serde_json::from_str(key_json).unwrap();
        let agent: AuthConfig = serde_json::from_str(agent_json).unwrap();
        let password: AuthConfig = serde_json::from_str(password_json).unwrap();

        assert!(matches!(key, AuthConfig::Key { path, .. } if path == "/path/to/key"));
        assert!(matches!(agent, AuthConfig::Agent));
        assert!(matches!(password, AuthConfig::Password { password } if *password == "secret"));
    }

    // ============== LimitsConfig Tests ==============

    #[test]
    fn test_limits_config_default() {
        let config = LimitsConfig::default();
        assert_eq!(config.command_timeout_seconds, 1800);
        assert_eq!(config.max_output_bytes, 10 * 1024 * 1024);
        assert_eq!(config.max_concurrent_commands, 5);
        assert_eq!(config.connection_timeout_seconds, 10);
        assert_eq!(config.keepalive_interval_seconds, 30);
        assert_eq!(config.retry_attempts, 3);
        assert_eq!(config.retry_initial_delay_ms, 100);
        assert_eq!(config.rate_limit_per_second, 0); // Disabled by default
        assert_eq!(config.max_output_chars, 20_000);
        assert_eq!(config.output_cache_ttl_seconds, 300);
        assert_eq!(config.output_cache_max_entries, 100);
    }

    #[test]
    fn test_limits_config_retry_config() {
        let limits = LimitsConfig {
            retry_attempts: 5,
            retry_initial_delay_ms: 200,
            ..Default::default()
        };

        let retry_config = limits.retry_config();
        assert_eq!(retry_config.max_attempts, 5);
        assert_eq!(retry_config.initial_delay_ms, 200);
    }

    // ============== AuditConfig Tests ==============

    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_size_mb, 100);
        assert_eq!(config.retain_days, 30);
        assert!(config.path.to_string_lossy().contains("audit.log"));
    }

    // ============== SessionConfig Tests ==============

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.max_sessions, 10);
        assert_eq!(config.idle_timeout_seconds, 300);
        assert_eq!(config.max_age_seconds, 3600);
    }

    // ============== SanitizeConfig Tests ==============

    #[test]
    fn test_sanitize_config_default() {
        let config = SanitizeConfig::default();
        assert!(config.enabled);
        assert!(config.disable_builtin.is_empty());
        assert!(config.custom_patterns.is_empty());
    }

    #[test]
    fn test_custom_sanitize_pattern_default_replacement() {
        let pattern: CustomSanitizePattern =
            serde_json::from_str(r#"{"pattern": "secret_\\w+"}"#).unwrap();
        assert_eq!(pattern.replacement, "[REDACTED]");
        assert!(pattern.description.is_none());
    }

    #[test]
    fn test_custom_sanitize_pattern_with_all_fields() {
        let pattern: CustomSanitizePattern = serde_json::from_str(
            r#"{"pattern": "api_key=\\w+", "replacement": "[API_KEY]", "description": "API key pattern"}"#
        ).unwrap();
        assert_eq!(pattern.pattern, "api_key=\\w+");
        assert_eq!(pattern.replacement, "[API_KEY]");
        assert_eq!(pattern.description, Some("API key pattern".to_string()));
    }

    // ============== HostConfig Tests ==============

    #[test]
    fn test_host_config_default_port() {
        let json = r#"{
            "hostname": "example.com",
            "user": "admin",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.port, 22);
    }

    #[test]
    fn test_host_config_custom_port() {
        let json = r#"{
            "hostname": "example.com",
            "port": 2222,
            "user": "admin",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.port, 2222);
    }

    #[test]
    fn test_host_config_with_description() {
        let json = r#"{
            "hostname": "example.com",
            "user": "admin",
            "description": "Production server",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.description, Some("Production server".to_string()));
    }

    #[test]
    fn test_host_config_with_proxy_jump() {
        let json = r#"{
            "hostname": "internal.example.com",
            "user": "admin",
            "proxy_jump": "bastion",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert_eq!(host.proxy_jump, Some("bastion".to_string()));
    }

    // ============== SocksProxyConfig Tests ==============

    #[test]
    fn test_socks_proxy_config_defaults() {
        let json = r#"{"hostname": "proxy.example.com"}"#;
        let config: SocksProxyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.hostname, "proxy.example.com");
        assert_eq!(config.port, 1080);
        assert_eq!(config.version, SocksVersion::Socks5);
        assert!(config.username.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_socks_proxy_config_full() {
        let json = r#"{
            "hostname": "proxy.corp.com",
            "port": 9050,
            "version": "socks4",
            "username": "user",
            "password": "pass"
        }"#;
        let config: SocksProxyConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.hostname, "proxy.corp.com");
        assert_eq!(config.port, 9050);
        assert_eq!(config.version, SocksVersion::Socks4);
        assert_eq!(config.username, Some("user".to_string()));
        assert_eq!(config.password, Some("pass".to_string()));
    }

    #[test]
    fn test_socks_version_default_is_socks5() {
        let default = SocksVersion::default();
        assert_eq!(default, SocksVersion::Socks5);
    }

    #[test]
    fn test_socks_version_serialization() {
        assert_eq!(
            serde_json::to_string(&SocksVersion::Socks5).unwrap(),
            "\"socks5\""
        );
        assert_eq!(
            serde_json::to_string(&SocksVersion::Socks4).unwrap(),
            "\"socks4\""
        );
    }

    #[test]
    fn test_socks_version_deserialization() {
        let socks5: SocksVersion = serde_json::from_str("\"socks5\"").unwrap();
        let socks4: SocksVersion = serde_json::from_str("\"socks4\"").unwrap();
        assert_eq!(socks5, SocksVersion::Socks5);
        assert_eq!(socks4, SocksVersion::Socks4);
    }

    #[test]
    fn test_host_config_with_socks_proxy() {
        let json = r#"{
            "hostname": "10.0.0.50",
            "user": "deploy",
            "auth": {"type": "agent"},
            "socks_proxy": {
                "hostname": "proxy.corp.com",
                "port": 1080,
                "version": "socks5"
            }
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert!(host.socks_proxy.is_some());
        let socks = host.socks_proxy.unwrap();
        assert_eq!(socks.hostname, "proxy.corp.com");
        assert_eq!(socks.port, 1080);
        assert_eq!(socks.version, SocksVersion::Socks5);
        assert!(host.proxy_jump.is_none());
    }

    #[test]
    fn test_host_config_socks_proxy_default_none() {
        let json = r#"{
            "hostname": "example.com",
            "user": "admin",
            "auth": {"type": "agent"}
        }"#;
        let host: HostConfig = serde_json::from_str(json).unwrap();
        assert!(host.socks_proxy.is_none());
    }

    #[test]
    fn test_socks_proxy_config_clone_and_debug() {
        let config = SocksProxyConfig {
            hostname: "proxy.test".to_string(),
            port: 1080,
            version: SocksVersion::Socks5,
            username: None,
            password: None,
        };
        let cloned = config.clone();
        assert_eq!(config.hostname, cloned.hostname);

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("SocksProxyConfig"));
    }

    // ============== Config Clone and Debug Tests ==============

    #[test]
    fn test_security_config_clone_and_debug() {
        let config = SecurityConfig::default();
        let cloned = config.clone();
        assert_eq!(config.mode, cloned.mode);

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("SecurityConfig"));
    }

    #[test]
    fn test_limits_config_clone_and_debug() {
        let config = LimitsConfig::default();
        let cloned = config.clone();
        assert_eq!(
            config.command_timeout_seconds,
            cloned.command_timeout_seconds
        );

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("LimitsConfig"));
    }

    #[test]
    fn test_audit_config_clone_and_debug() {
        let config = AuditConfig::default();
        let cloned = config.clone();
        assert_eq!(config.enabled, cloned.enabled);

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("AuditConfig"));
    }

    #[test]
    fn test_session_config_clone_and_debug() {
        let config = SessionConfig::default();
        let cloned = config.clone();
        assert_eq!(config.max_sessions, cloned.max_sessions);

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("SessionConfig"));
    }

    // ============== ToolGroupsConfig Tests ==============

    #[test]
    fn test_tool_groups_config_default() {
        let config = ToolGroupsConfig::default();
        assert!(config.groups.is_empty());
    }

    #[test]
    fn test_tool_groups_config_unlisted_group_is_enabled() {
        let config = ToolGroupsConfig::default();
        assert!(config.is_group_enabled("core"));
        assert!(config.is_group_enabled("sessions"));
        assert!(config.is_group_enabled("anything"));
    }

    #[test]
    fn test_tool_groups_config_explicit_disable() {
        let mut groups = HashMap::new();
        groups.insert("sessions".to_string(), false);
        let config = ToolGroupsConfig { groups };

        assert!(!config.is_group_enabled("sessions"));
        assert!(config.is_group_enabled("core"));
    }

    #[test]
    fn test_tool_groups_config_explicit_enable() {
        let mut groups = HashMap::new();
        groups.insert("core".to_string(), true);
        let config = ToolGroupsConfig { groups };

        assert!(config.is_group_enabled("core"));
    }

    #[test]
    fn test_tool_groups_config_deserialization() {
        let yaml = r"
            groups:
              sessions: false
              monitoring: false
              core: true
        ";
        let config: ToolGroupsConfig = serde_saphyr::from_str(yaml).unwrap();
        assert!(!config.is_group_enabled("sessions"));
        assert!(!config.is_group_enabled("monitoring"));
        assert!(config.is_group_enabled("core"));
        assert!(config.is_group_enabled("file_transfer")); // Unlisted = enabled
    }

    #[test]
    fn test_tool_groups_config_empty_deserialization() {
        let yaml = "{}";
        let config: ToolGroupsConfig = serde_saphyr::from_str(yaml).unwrap();
        assert!(config.groups.is_empty());
        assert!(config.is_group_enabled("core"));
    }

    #[test]
    fn test_tool_groups_config_clone_and_debug() {
        let mut groups = HashMap::new();
        groups.insert("sessions".to_string(), false);
        let config = ToolGroupsConfig { groups };
        let cloned = config.clone();
        assert_eq!(
            config.is_group_enabled("sessions"),
            cloned.is_group_enabled("sessions")
        );

        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("ToolGroupsConfig"));
    }

    // ============== ClientOverride Tests ==============

    #[test]
    fn test_effective_max_output_chars_default() {
        let config = LimitsConfig::default();
        assert_eq!(config.effective_max_output_chars(None), 20_000);
        assert_eq!(
            config.effective_max_output_chars(Some("unknown-client")),
            20_000
        );
    }

    #[test]
    fn test_effective_max_output_chars_with_override() {
        let config = LimitsConfig {
            client_overrides: vec![
                ClientOverride {
                    name_contains: "claude".to_string(),
                    match_mode: MatchMode::default(),
                    max_output_chars: Some(80_000),
                },
                ClientOverride {
                    name_contains: "cursor".to_string(),
                    match_mode: MatchMode::default(),
                    max_output_chars: Some(50_000),
                },
            ],
            ..Default::default()
        };

        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(config.effective_max_output_chars(Some("Cursor")), 50_000);
        assert_eq!(config.effective_max_output_chars(Some("unknown")), 20_000);
        assert_eq!(config.effective_max_output_chars(None), 20_000);
    }

    #[test]
    fn test_effective_max_output_chars_case_insensitive() {
        let config = LimitsConfig {
            client_overrides: vec![ClientOverride {
                name_contains: "Claude".to_string(),
                match_mode: MatchMode::default(),
                max_output_chars: Some(80_000),
            }],
            ..Default::default()
        };

        assert_eq!(
            config.effective_max_output_chars(Some("CLAUDE-CODE")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
    }

    #[test]
    fn test_client_override_deserialization() {
        let yaml = r"
            name_contains: claude
            max_output_chars: 80000
        ";
        let ov: ClientOverride = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(ov.name_contains, "claude");
        assert_eq!(ov.max_output_chars, Some(80_000));
        assert_eq!(ov.match_mode, MatchMode::Prefix); // default
    }

    #[test]
    fn test_client_override_deserialization_with_match_mode() {
        let yaml = r"
            name_contains: claude
            match_mode: exact
            max_output_chars: 80000
        ";
        let ov: ClientOverride = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(ov.match_mode, MatchMode::Exact);

        let yaml_contains = r"
            name_contains: claude
            match_mode: contains
        ";
        let ov2: ClientOverride = serde_saphyr::from_str(yaml_contains).unwrap();
        assert_eq!(ov2.match_mode, MatchMode::Contains);
        assert_eq!(ov2.max_output_chars, None);
    }

    #[test]
    fn test_limits_with_client_overrides_deserialization() {
        let yaml = r"
            client_overrides:
              - name_contains: claude
                max_output_chars: 80000
              - name_contains: gemini
                max_output_chars: 200000
        ";
        let config: LimitsConfig = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(config.client_overrides.len(), 2);
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("gemini-client")),
            200_000
        );
    }

    #[test]
    fn test_match_mode_default_is_prefix() {
        let config = LimitsConfig {
            client_overrides: vec![ClientOverride {
                name_contains: "claude".to_string(),
                match_mode: MatchMode::default(),
                max_output_chars: Some(80_000),
            }],
            ..Default::default()
        };

        // Prefix: "claude" matches "claude-code" but NOT "not-claude"
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("not-claude")),
            20_000
        );
    }

    #[test]
    fn test_match_mode_exact() {
        let config = LimitsConfig {
            client_overrides: vec![ClientOverride {
                name_contains: "claude-code".to_string(),
                match_mode: MatchMode::Exact,
                max_output_chars: Some(80_000),
            }],
            ..Default::default()
        };

        // Exact: "claude-code" matches "Claude-Code" but NOT "claude-code-v2"
        assert_eq!(
            config.effective_max_output_chars(Some("Claude-Code")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code-v2")),
            20_000
        );
        assert_eq!(config.effective_max_output_chars(Some("claude")), 20_000);
    }

    #[test]
    fn test_match_mode_prefix() {
        let config = LimitsConfig {
            client_overrides: vec![ClientOverride {
                name_contains: "claude".to_string(),
                match_mode: MatchMode::Prefix,
                max_output_chars: Some(80_000),
            }],
            ..Default::default()
        };

        // Prefix: "claude" matches "claude-code" but NOT "not-claude"
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(config.effective_max_output_chars(Some("claude")), 80_000);
        assert_eq!(
            config.effective_max_output_chars(Some("not-claude")),
            20_000
        );
    }

    #[test]
    fn test_match_mode_contains() {
        let config = LimitsConfig {
            client_overrides: vec![ClientOverride {
                name_contains: "claude".to_string(),
                match_mode: MatchMode::Contains,
                max_output_chars: Some(80_000),
            }],
            ..Default::default()
        };

        // Contains: "claude" matches both "claude-code" AND "not-claude"
        assert_eq!(
            config.effective_max_output_chars(Some("claude-code")),
            80_000
        );
        assert_eq!(
            config.effective_max_output_chars(Some("not-claude")),
            80_000
        );
        assert_eq!(config.effective_max_output_chars(Some("cursor")), 20_000);
    }
}
