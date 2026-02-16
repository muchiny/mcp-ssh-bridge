//! CLI runner functions
//!
//! These functions execute CLI commands by reusing the existing
//! domain logic and tool handlers.

use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use tracing::{info, warn};

use crate::config::Config;
use crate::domain::ExecuteCommandUseCase;
use crate::error::{BridgeError, Result};
use crate::mcp::CommandHistory;
use crate::mcp::history::HistoryConfig;
use crate::ports::ToolContext;
use crate::security::{
    AuditEvent, AuditLogger, CommandResult, CommandValidator, RateLimiter, Sanitizer,
};
use crate::ssh::{
    ConnectionPool, SessionManager, SshClient, TransferMode, TransferOptions, TransferProgress,
    is_retryable_error, with_retry_if,
};

/// Shell escape a string for safe use in shell commands
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Create a `ToolContext` from configuration
fn create_context(config: Arc<Config>) -> ToolContext {
    let validator = Arc::new(CommandValidator::new(&config.security));
    let sanitizer = Arc::new(Sanitizer::from_config_with_legacy(
        &config.security.sanitize,
        &config.security.sanitize_patterns,
    ));
    // For CLI mode, we don't spawn the audit writer task (short-lived process)
    let (audit_logger, _audit_task) =
        AuditLogger::new(&config.audit).unwrap_or_else(|_| (AuditLogger::disabled(), None));
    let audit_logger = Arc::new(audit_logger);
    let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));
    let connection_pool = Arc::new(ConnectionPool::with_defaults());
    let rate_limiter = Arc::new(RateLimiter::new(config.limits.rate_limit_per_second));

    let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
        Arc::clone(&validator),
        Arc::clone(&sanitizer),
        Arc::clone(&audit_logger),
        Arc::clone(&history),
    ));

    let session_manager = Arc::new(SessionManager::new(config.sessions.clone()));

    ToolContext::new(
        config,
        validator,
        sanitizer,
        audit_logger,
        history,
        connection_pool,
        execute_use_case,
        rate_limiter,
        session_manager,
    )
}

/// Execute a command on a remote host
///
/// # Errors
///
/// Returns an error if:
/// - The specified host is not found in the configuration
/// - The command is denied by security rules (whitelist/blacklist)
/// - SSH connection to the host fails
/// - Command execution fails or times out
pub async fn run_exec(
    config: Arc<Config>,
    host: &str,
    command: &str,
    timeout: u64,
    working_dir: Option<&str>,
) -> Result<()> {
    let ctx = create_context(Arc::clone(&config));

    // Get host config
    let host_config = config
        .hosts
        .get(host)
        .ok_or_else(|| BridgeError::UnknownHost {
            host: host.to_string(),
        })?;

    // Validate command
    if let Err(e) = ctx.execute_use_case.validate(command) {
        let reason = match &e {
            BridgeError::CommandDenied { reason } => reason.clone(),
            _ => e.to_string(),
        };
        ctx.execute_use_case.log_denied(host, command, &reason);
        return Err(e);
    }

    info!(host = %host, command = %command, "Executing SSH command");

    // Build limits with timeout override
    let mut limits = config.limits.clone();
    limits.command_timeout_seconds = timeout;

    // Build the actual command (with optional cd)
    let full_command = working_dir.map_or_else(
        || command.to_string(),
        |dir| format!("cd {} && {}", shell_escape(dir), command),
    );

    // Get retry config
    let retry_config = limits.retry_config();

    // Resolve jump host if configured
    let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
        config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    // Execute with retry logic
    let output = with_retry_if(
        &retry_config,
        "cli_exec",
        async || {
            let mut conn = ctx
                .connection_pool
                .get_connection_with_jump(host, host_config, &limits, jump_host)
                .await?;

            match conn.exec(&full_command, &limits).await {
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
            .log_failure(host, command, &e.to_string());
    })?;

    // Process success
    let response = ctx
        .execute_use_case
        .process_success(host, command, &output.into());

    if response.exit_code != 0 {
        warn!(
            host = %host,
            command = %command,
            exit_code = response.exit_code,
            "Command failed"
        );
    }

    // Print the output
    println!("{}", response.output);

    Ok(())
}

/// Show configured hosts and security settings
///
/// # Errors
///
/// This function is infallible in practice but returns `Result` for
/// consistency with other CLI commands.
pub async fn run_status(config: Arc<Config>) -> Result<()> {
    println!("MCP SSH Bridge Status");
    println!("=====================\n");

    // Security mode
    println!("Security Mode: {:?}", config.security.mode);

    if !config.security.whitelist.is_empty() {
        println!("\nWhitelist patterns:");
        for pattern in &config.security.whitelist {
            println!("  - {pattern}");
        }
    }

    if !config.security.blacklist.is_empty() {
        println!("\nBlacklist patterns:");
        for pattern in &config.security.blacklist {
            println!("  - {pattern}");
        }
    }

    // Hosts
    println!("\nConfigured Hosts ({}):", config.hosts.len());
    println!("{:-<60}", "");

    if config.hosts.is_empty() {
        println!("  (no hosts configured)");
    } else {
        for (alias, host) in &config.hosts {
            println!("\n  {alias}:");
            println!("    Hostname: {}:{}", host.hostname, host.port);
            println!("    User: {}", host.user);
            println!("    Auth: {:?}", auth_type_name(&host.auth));
            println!("    Host Key: {:?}", host.host_key_verification);
            if let Some(ref jump) = host.proxy_jump {
                println!("    Jump Host: {jump}");
            }
            if let Some(ref desc) = host.description {
                println!("    Description: {desc}");
            }
        }
    }

    // Limits
    println!("\nLimits:");
    println!(
        "  Command timeout: {}s",
        config.limits.command_timeout_seconds
    );
    println!(
        "  Connection timeout: {}s",
        config.limits.connection_timeout_seconds
    );
    println!("  Max output: {} bytes", config.limits.max_output_bytes);
    println!(
        "  Max concurrent: {}",
        config.limits.max_concurrent_commands
    );
    println!("  Retry attempts: {}", config.limits.retry_attempts);

    // Audit
    println!("\nAudit:");
    println!("  Enabled: {}", config.audit.enabled);
    if config.audit.enabled {
        println!("  Path: {}", config.audit.path.display());
    }

    Ok(())
}

const fn auth_type_name(auth: &crate::config::AuthConfig) -> &'static str {
    match auth {
        crate::config::AuthConfig::Key { .. } => "SSH Key",
        crate::config::AuthConfig::Agent => "SSH Agent",
        crate::config::AuthConfig::Password { .. } => "Password",
    }
}

/// Show command execution history
///
/// # Errors
///
/// This function is infallible in practice but returns `Result` for
/// consistency with other CLI commands.
pub async fn run_history(
    config: Arc<Config>,
    limit: usize,
    host_filter: Option<&str>,
) -> Result<()> {
    let ctx = create_context(config);

    let entries = if let Some(host) = host_filter {
        ctx.history.for_host(host, limit)
    } else {
        ctx.history.recent(limit)
    };

    if entries.is_empty() {
        println!("No command history available.");
        println!("\nNote: History is only available during a CLI session.");
        println!("For persistent history, check the audit log if enabled.");
        return Ok(());
    }

    println!("Command History (most recent first):");
    println!("{:-<80}", "");

    for entry in &entries {
        let status = if entry.success { "OK" } else { "FAIL" };
        let exit_info = if entry.exit_code == u32::MAX {
            "error".to_string()
        } else {
            format!("exit {}", entry.exit_code)
        };

        println!(
            "\n[{}] {} - {} ({})",
            entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
            entry.host,
            status,
            exit_info
        );
        println!("  Command: {}", entry.command);
        if entry.duration_ms > 0 {
            println!("  Duration: {}ms", entry.duration_ms);
        }
    }

    println!("\n{:-<80}", "");
    println!("Total: {} entries", entries.len());

    Ok(())
}

/// Upload a file to a remote host via SFTP
///
/// # Errors
///
/// Returns an error if:
/// - The specified host is not found in the configuration
/// - The transfer mode is invalid
/// - The local file does not exist or cannot be read
/// - SSH/SFTP connection fails
/// - The file transfer fails (permissions, disk space, network)
/// - Checksum verification fails (if enabled)
#[expect(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn run_upload(
    config: Arc<Config>,
    host: &str,
    local_path: &Path,
    remote_path: &str,
    mode: &str,
    chunk_size: u64,
    verify_checksum: bool,
    preserve_permissions: bool,
    show_progress: bool,
) -> Result<()> {
    let ctx = create_context(Arc::clone(&config));

    // Get host config
    let host_config = config
        .hosts
        .get(host)
        .ok_or_else(|| BridgeError::UnknownHost {
            host: host.to_string(),
        })?;

    // Parse transfer mode
    let transfer_mode = TransferMode::parse(mode).ok_or_else(|| BridgeError::FileTransfer {
        reason: format!(
            "Invalid transfer mode: {mode}. Valid modes: overwrite, append, resume, fail-if-exists"
        ),
    })?;

    // Expand and check local path
    let local_path_str = local_path.to_string_lossy();
    let expanded_path = shellexpand::tilde(&local_path_str).to_string();
    let local_path = Path::new(&expanded_path);

    if !local_path.exists() {
        return Err(BridgeError::FileTransfer {
            reason: format!("Local file not found: {}", local_path.display()),
        });
    }

    let metadata = std::fs::metadata(local_path).map_err(|e| BridgeError::FileTransfer {
        reason: format!("Cannot read file metadata: {e}"),
    })?;

    info!(
        host = %host,
        local = %local_path.display(),
        remote = %remote_path,
        size = metadata.len(),
        mode = %mode,
        "Uploading file via SFTP"
    );

    // Build transfer options
    let options = TransferOptions {
        mode: transfer_mode,
        chunk_size,
        verify_checksum,
        preserve_permissions,
    };

    // Resolve jump host if configured
    let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
        config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    // Connect to host (via jump host if configured)
    let client = if let Some((jump_name, jump_config)) = jump_host {
        SshClient::connect_via_jump(host, host_config, jump_name, jump_config, &config.limits)
            .await?
    } else {
        SshClient::connect(host, host_config, &config.limits).await?
    };

    // Create SFTP session
    let sftp = client.sftp_session().await?;

    // Progress callback (must be Send for future_not_send lint)
    let progress_callback: Option<Box<dyn FnMut(TransferProgress) + Send>> = if show_progress {
        Some(Box::new(|progress: TransferProgress| {
            print!(
                "\r  Progress: {:.1}% ({} / {} bytes)",
                progress.percentage, progress.bytes_transferred, progress.total_bytes
            );
            let _ = io::stdout().flush();
        }))
    } else {
        None
    };

    // Upload the file
    let result = sftp
        .upload_file(local_path, remote_path, &options, progress_callback)
        .await;

    // Log the result
    match &result {
        Ok(transfer_result) => {
            ctx.audit_logger.log(AuditEvent::new(
                host,
                &format!("SFTP_UPLOAD {} -> {}", local_path.display(), remote_path),
                CommandResult::Success {
                    exit_code: 0,
                    duration_ms: transfer_result.duration_ms,
                },
            ));
        }
        Err(e) => {
            ctx.audit_logger.log(AuditEvent::new(
                host,
                &format!("SFTP_UPLOAD {} -> {}", local_path.display(), remote_path),
                CommandResult::Error {
                    message: e.to_string(),
                },
            ));
        }
    }

    let transfer_result = result?;

    // Clear progress line if shown
    if show_progress {
        println!();
    }

    // Format output
    let mut output = String::new();
    let _ = writeln!(output, "File uploaded successfully:");
    let _ = writeln!(output, "  Host: {host}");
    let _ = writeln!(output, "  Local: {}", local_path.display());
    let _ = writeln!(output, "  Remote: {remote_path}");
    let _ = writeln!(
        output,
        "  Size: {} bytes",
        transfer_result.bytes_transferred
    );
    let _ = writeln!(output, "  Duration: {}ms", transfer_result.duration_ms);
    let _ = writeln!(
        output,
        "  Speed: {:.2} MB/s",
        transfer_result.bytes_per_second / 1_000_000.0
    );
    if let Some(checksum) = &transfer_result.checksum {
        let _ = writeln!(output, "  SHA256: {checksum}");
    }

    println!("{output}");

    Ok(())
}

/// Download a file from a remote host via SFTP
///
/// # Errors
///
/// Returns an error if:
/// - The specified host is not found in the configuration
/// - The transfer mode is invalid
/// - The local destination directory cannot be created
/// - SSH/SFTP connection fails
/// - The remote file does not exist or cannot be read
/// - The file transfer fails (permissions, disk space, network)
/// - Checksum verification fails (if enabled)
#[expect(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn run_download(
    config: Arc<Config>,
    host: &str,
    remote_path: &str,
    local_path: &Path,
    mode: &str,
    chunk_size: u64,
    verify_checksum: bool,
    preserve_permissions: bool,
    show_progress: bool,
) -> Result<()> {
    let ctx = create_context(Arc::clone(&config));

    // Get host config
    let host_config = config
        .hosts
        .get(host)
        .ok_or_else(|| BridgeError::UnknownHost {
            host: host.to_string(),
        })?;

    // Parse transfer mode
    let transfer_mode = TransferMode::parse(mode).ok_or_else(|| BridgeError::FileTransfer {
        reason: format!(
            "Invalid transfer mode: {mode}. Valid modes: overwrite, append, resume, fail-if-exists"
        ),
    })?;

    // Expand local path
    let local_path_str = local_path.to_string_lossy();
    let expanded_path = shellexpand::tilde(&local_path_str).to_string();
    let local_path = Path::new(&expanded_path);

    // Create parent directories if needed
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BridgeError::FileTransfer {
            reason: format!("Cannot create directory: {e}"),
        })?;
    }

    info!(
        host = %host,
        remote = %remote_path,
        local = %local_path.display(),
        mode = %mode,
        "Downloading file via SFTP"
    );

    // Build transfer options
    let options = TransferOptions {
        mode: transfer_mode,
        chunk_size,
        verify_checksum,
        preserve_permissions,
    };

    // Resolve jump host if configured
    let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
        config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    // Connect to host (via jump host if configured)
    let client = if let Some((jump_name, jump_config)) = jump_host {
        SshClient::connect_via_jump(host, host_config, jump_name, jump_config, &config.limits)
            .await?
    } else {
        SshClient::connect(host, host_config, &config.limits).await?
    };

    // Create SFTP session
    let sftp = client.sftp_session().await?;

    // Progress callback (must be Send for future_not_send lint)
    let progress_callback: Option<Box<dyn FnMut(TransferProgress) + Send>> = if show_progress {
        Some(Box::new(|progress: TransferProgress| {
            print!(
                "\r  Progress: {:.1}% ({} / {} bytes)",
                progress.percentage, progress.bytes_transferred, progress.total_bytes
            );
            let _ = io::stdout().flush();
        }))
    } else {
        None
    };

    // Download the file
    let result = sftp
        .download_file(remote_path, local_path, &options, progress_callback)
        .await;

    // Log the result
    match &result {
        Ok(transfer_result) => {
            ctx.audit_logger.log(AuditEvent::new(
                host,
                &format!("SFTP_DOWNLOAD {} -> {}", remote_path, local_path.display()),
                CommandResult::Success {
                    exit_code: 0,
                    duration_ms: transfer_result.duration_ms,
                },
            ));
        }
        Err(e) => {
            ctx.audit_logger.log(AuditEvent::new(
                host,
                &format!("SFTP_DOWNLOAD {} -> {}", remote_path, local_path.display()),
                CommandResult::Error {
                    message: e.to_string(),
                },
            ));
        }
    }

    let transfer_result = result?;

    // Clear progress line if shown
    if show_progress {
        println!();
    }

    // Format output
    let mut output = String::new();
    let _ = writeln!(output, "File downloaded successfully:");
    let _ = writeln!(output, "  Host: {host}");
    let _ = writeln!(output, "  Remote: {remote_path}");
    let _ = writeln!(output, "  Local: {}", local_path.display());
    let _ = writeln!(
        output,
        "  Size: {} bytes",
        transfer_result.bytes_transferred
    );
    let _ = writeln!(output, "  Duration: {}ms", transfer_result.duration_ms);
    let _ = writeln!(
        output,
        "  Speed: {:.2} MB/s",
        transfer_result.bytes_per_second / 1_000_000.0
    );
    if let Some(checksum) = &transfer_result.checksum {
        let _ = writeln!(output, "  SHA256: {checksum}");
    }

    println!("{output}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, AuthConfig, HostConfig, HostKeyVerification, LimitsConfig, OsType,
        SecurityConfig, SessionConfig, SshConfigDiscovery, ToolGroupsConfig,
    };
    use std::collections::HashMap;

    // ============== shell_escape Tests ==============

    #[test]
    fn test_shell_escape_simple() {
        assert_eq!(shell_escape("simple"), "'simple'");
    }

    #[test]
    fn test_shell_escape_empty() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn test_shell_escape_with_spaces() {
        assert_eq!(shell_escape("with spaces"), "'with spaces'");
    }

    #[test]
    fn test_shell_escape_with_single_quote() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_escape_multiple_single_quotes() {
        assert_eq!(shell_escape("a'b'c"), "'a'\\''b'\\''c'");
    }

    #[test]
    fn test_shell_escape_only_single_quote() {
        assert_eq!(shell_escape("'"), "''\\'''");
    }

    #[test]
    fn test_shell_escape_special_chars() {
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
        assert_eq!(shell_escape("`cmd`"), "'`cmd`'");
        assert_eq!(shell_escape("a;b"), "'a;b'");
        assert_eq!(shell_escape("a|b"), "'a|b'");
        assert_eq!(shell_escape("a&b"), "'a&b'");
    }

    #[test]
    fn test_shell_escape_double_quotes() {
        assert_eq!(shell_escape("\"quoted\""), "'\"quoted\"'");
    }

    #[test]
    fn test_shell_escape_newlines() {
        assert_eq!(shell_escape("line1\nline2"), "'line1\nline2'");
    }

    #[test]
    fn test_shell_escape_tabs() {
        assert_eq!(shell_escape("col1\tcol2"), "'col1\tcol2'");
    }

    #[test]
    fn test_shell_escape_unicode() {
        assert_eq!(shell_escape("日本語"), "'日本語'");
        assert_eq!(shell_escape("émoji 🎉"), "'émoji 🎉'");
    }

    #[test]
    fn test_shell_escape_path() {
        assert_eq!(shell_escape("/path/to/file"), "'/path/to/file'");
        assert_eq!(
            shell_escape("/path with spaces/file"),
            "'/path with spaces/file'"
        );
    }

    #[test]
    fn test_shell_escape_backslash() {
        assert_eq!(shell_escape("a\\b"), "'a\\b'");
    }

    // ============== auth_type_name Tests ==============

    #[test]
    fn test_auth_type_name_key() {
        let auth = AuthConfig::Key {
            path: "~/.ssh/id_rsa".to_string(),
            passphrase: None,
        };
        assert_eq!(auth_type_name(&auth), "SSH Key");
    }

    #[test]
    fn test_auth_type_name_key_with_passphrase() {
        let auth = AuthConfig::Key {
            path: "~/.ssh/id_rsa".to_string(),
            passphrase: Some(zeroize::Zeroizing::new("secret".to_string())),
        };
        assert_eq!(auth_type_name(&auth), "SSH Key");
    }

    #[test]
    fn test_auth_type_name_agent() {
        let auth = AuthConfig::Agent;
        assert_eq!(auth_type_name(&auth), "SSH Agent");
    }

    #[test]
    fn test_auth_type_name_password() {
        let auth = AuthConfig::Password {
            password: zeroize::Zeroizing::new("secret".to_string()),
        };
        assert_eq!(auth_type_name(&auth), "Password");
    }

    // ============== create_context Tests ==============

    #[test]
    fn test_create_context_with_empty_config() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let ctx = create_context(Arc::new(config));

        // Verify context components are created
        assert!(ctx.config.hosts.is_empty());
    }

    #[test]
    fn test_create_context_with_hosts() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test-server".to_string(),
            HostConfig {
                hostname: "192.168.1.1".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Agent,
                description: Some("Test server".to_string()),
                host_key_verification: HostKeyVerification::Strict,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                os_type: OsType::Linux,
                shell: None,
            },
        );

        let config = Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let ctx = create_context(Arc::new(config));

        assert_eq!(ctx.config.hosts.len(), 1);
        assert!(ctx.config.hosts.contains_key("test-server"));
    }

    #[test]
    fn test_create_context_rate_limiter_from_config() {
        let limits = LimitsConfig {
            rate_limit_per_second: 10,
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits,
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let ctx = create_context(Arc::new(config));

        // Rate limiter should be configured
        assert!(ctx.rate_limiter.check("test").is_ok());
    }

    #[test]
    fn test_create_context_preserves_security_config() {
        let security = SecurityConfig {
            whitelist: vec!["ls".to_string(), "pwd".to_string()],
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security,
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let ctx = create_context(Arc::new(config));

        // Validator should reject commands not in whitelist
        assert!(ctx.execute_use_case.validate("ls").is_ok());
        assert!(ctx.execute_use_case.validate("rm -rf /").is_err());
    }

    // ============== Edge Cases ==============

    #[test]
    fn test_shell_escape_very_long_string() {
        let long_str = "a".repeat(10000);
        let escaped = shell_escape(&long_str);
        assert!(escaped.starts_with('\''));
        assert!(escaped.ends_with('\''));
        assert_eq!(escaped.len(), 10002); // 10000 + 2 quotes
    }

    #[test]
    fn test_shell_escape_all_quotes() {
        let all_quotes = "'''''";
        let escaped = shell_escape(all_quotes);
        // Each ' becomes '\'' (4 chars)
        assert!(escaped.contains("'\\''"));
    }

    // ============== Additional shell_escape Tests ==============

    #[test]
    fn test_shell_escape_null_byte() {
        // Null bytes in strings
        let with_null = "before\0after";
        let escaped = shell_escape(with_null);
        assert!(escaped.starts_with('\''));
        assert!(escaped.ends_with('\''));
    }

    #[test]
    fn test_shell_escape_parentheses() {
        assert_eq!(shell_escape("(cmd)"), "'(cmd)'");
        assert_eq!(shell_escape("$(cmd)"), "'$(cmd)'");
    }

    #[test]
    fn test_shell_escape_redirects() {
        assert_eq!(shell_escape("cmd > file"), "'cmd > file'");
        assert_eq!(shell_escape("cmd >> file"), "'cmd >> file'");
        assert_eq!(shell_escape("cmd < file"), "'cmd < file'");
        assert_eq!(shell_escape("2>&1"), "'2>&1'");
    }

    #[test]
    fn test_shell_escape_glob_patterns() {
        assert_eq!(shell_escape("*.txt"), "'*.txt'");
        assert_eq!(shell_escape("file?.log"), "'file?.log'");
        assert_eq!(shell_escape("[abc]"), "'[abc]'");
    }

    #[test]
    fn test_shell_escape_environment_vars() {
        assert_eq!(shell_escape("${VAR}"), "'${VAR}'");
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
        assert_eq!(shell_escape("${HOME:-/default}"), "'${HOME:-/default}'");
    }

    #[test]
    fn test_shell_escape_complex_path() {
        let path = "/home/user/my project's files/file (1).txt";
        let escaped = shell_escape(path);
        // Should handle spaces and apostrophe
        assert!(escaped.contains("'\\''"));
    }

    // ============== Additional create_context Tests ==============

    #[test]
    fn test_create_context_with_custom_limits() {
        let limits = LimitsConfig {
            command_timeout_seconds: 3600,
            max_output_bytes: 50 * 1024 * 1024,
            retry_attempts: 5,
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits,
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let ctx = create_context(Arc::new(config));

        assert_eq!(ctx.config.limits.command_timeout_seconds, 3600);
        assert_eq!(ctx.config.limits.max_output_bytes, 50 * 1024 * 1024);
        assert_eq!(ctx.config.limits.retry_attempts, 5);
    }

    #[test]
    fn test_create_context_with_disabled_audit() {
        let audit = AuditConfig {
            enabled: false,
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit,
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let ctx = create_context(Arc::new(config));
        assert!(!ctx.config.audit.enabled);
    }

    #[test]
    fn test_create_context_with_session_config() {
        let sessions = SessionConfig {
            max_sessions: 50,
            idle_timeout_seconds: 600,
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions,
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let ctx = create_context(Arc::new(config));

        assert_eq!(ctx.config.sessions.max_sessions, 50);
        assert_eq!(ctx.config.sessions.idle_timeout_seconds, 600);
    }

    #[test]
    fn test_create_context_with_multiple_hosts() {
        let mut hosts = HashMap::new();

        for i in 1..=5 {
            hosts.insert(
                format!("server{i}"),
                HostConfig {
                    hostname: format!("192.168.1.{i}"),
                    port: 22,
                    user: "admin".to_string(),
                    auth: AuthConfig::Agent,
                    description: Some(format!("Server {i}")),
                    host_key_verification: HostKeyVerification::Strict,
                    proxy_jump: None,
                    socks_proxy: None,
                    sudo_password: None,
                    os_type: OsType::Linux,
                    shell: None,
                },
            );
        }

        let config = Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let ctx = create_context(Arc::new(config));
        assert_eq!(ctx.config.hosts.len(), 5);
    }

    #[test]
    fn test_create_context_with_proxy_jump() {
        let mut hosts = HashMap::new();

        hosts.insert(
            "bastion".to_string(),
            HostConfig {
                hostname: "bastion.example.com".to_string(),
                port: 22,
                user: "jump".to_string(),
                auth: AuthConfig::Agent,
                description: Some("Jump host".to_string()),
                host_key_verification: HostKeyVerification::Strict,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                os_type: OsType::Linux,
                shell: None,
            },
        );

        hosts.insert(
            "internal".to_string(),
            HostConfig {
                hostname: "internal.local".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Agent,
                description: Some("Internal server".to_string()),
                host_key_verification: HostKeyVerification::Strict,
                proxy_jump: Some("bastion".to_string()),
                socks_proxy: None,
                sudo_password: None,
                os_type: OsType::Linux,
                shell: None,
            },
        );

        let config = Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let ctx = create_context(Arc::new(config));

        let internal = ctx.config.hosts.get("internal").unwrap();
        assert_eq!(internal.proxy_jump, Some("bastion".to_string()));
    }

    // ============== run_status Tests (async) ==============

    #[tokio::test]
    async fn test_run_status_empty_config() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_status(Arc::new(config)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_status_with_hosts() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test-server".to_string(),
            HostConfig {
                hostname: "test.example.com".to_string(),
                port: 2222,
                user: "testuser".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: Some("Test server description".to_string()),
                host_key_verification: HostKeyVerification::AcceptNew,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                os_type: OsType::Linux,
                shell: None,
            },
        );

        let config = Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_status(Arc::new(config)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_status_with_whitelist() {
        let security = SecurityConfig {
            whitelist: vec!["ls".to_string(), "pwd".to_string(), "whoami".to_string()],
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security,
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_status(Arc::new(config)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_status_with_audit_disabled() {
        let audit = AuditConfig {
            enabled: false,
            ..Default::default()
        };

        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit,
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_status(Arc::new(config)).await;
        assert!(result.is_ok());
    }

    // ============== run_history Tests (async) ==============

    #[tokio::test]
    async fn test_run_history_empty() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_history(Arc::new(config), 10, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_history_with_host_filter() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_history(Arc::new(config), 10, Some("nonexistent-host")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_history_with_limit_zero() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_history(Arc::new(config), 0, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_run_history_with_large_limit() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_history(Arc::new(config), 1000, None).await;
        assert!(result.is_ok());
    }

    // ============== run_exec Error Cases (async) ==============

    #[tokio::test]
    async fn test_run_exec_unknown_host() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_exec(Arc::new(config), "unknown-host", "ls", 30, None).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "unknown-host");
            }
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_run_exec_command_denied() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test".to_string(),
            HostConfig {
                hostname: "test.local".to_string(),
                port: 22,
                user: "user".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::Off,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                os_type: OsType::Linux,
                shell: None,
            },
        );

        let security = SecurityConfig {
            whitelist: vec!["ls".to_string()], // Only allow ls
            ..Default::default()
        };

        let config = Config {
            hosts,
            security,
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        // Try to execute a command not in whitelist
        let result = run_exec(Arc::new(config), "test", "rm -rf /", 30, None).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { .. } => {}
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    // ============== run_upload Error Cases (async) ==============

    #[tokio::test]
    async fn test_run_upload_unknown_host() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_upload(
            Arc::new(config),
            "unknown-host",
            Path::new("/local/file"),
            "/remote/file",
            "overwrite",
            1024 * 1024,
            false,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "unknown-host");
            }
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_run_upload_invalid_mode() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test".to_string(),
            HostConfig {
                hostname: "test.local".to_string(),
                port: 22,
                user: "user".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::Off,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                os_type: OsType::Linux,
                shell: None,
            },
        );

        let config = Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_upload(
            Arc::new(config),
            "test",
            Path::new("/local/file"),
            "/remote/file",
            "invalid_mode",
            1024 * 1024,
            false,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("Invalid transfer mode"));
            }
            e => panic!("Expected FileTransfer error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_run_upload_file_not_found() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test".to_string(),
            HostConfig {
                hostname: "test.local".to_string(),
                port: 22,
                user: "user".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::Off,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                os_type: OsType::Linux,
                shell: None,
            },
        );

        let config = Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_upload(
            Arc::new(config),
            "test",
            Path::new("/nonexistent/file/that/does/not/exist.txt"),
            "/remote/file",
            "overwrite",
            1024 * 1024,
            false,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("not found"));
            }
            e => panic!("Expected FileTransfer error, got: {e:?}"),
        }
    }

    // ============== run_download Error Cases (async) ==============

    #[tokio::test]
    async fn test_run_download_unknown_host() {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_download(
            Arc::new(config),
            "unknown-host",
            "/remote/file",
            Path::new("/local/file"),
            "overwrite",
            1024 * 1024,
            false,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "unknown-host");
            }
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_run_download_invalid_mode() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "test".to_string(),
            HostConfig {
                hostname: "test.local".to_string(),
                port: 22,
                user: "user".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: HostKeyVerification::Off,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                os_type: OsType::Linux,
                shell: None,
            },
        );

        let config = Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let result = run_download(
            Arc::new(config),
            "test",
            "/remote/file",
            Path::new("/local/file"),
            "bad_mode",
            1024 * 1024,
            false,
            true,
            false,
        )
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::FileTransfer { reason } => {
                assert!(reason.contains("Invalid transfer mode"));
            }
            e => panic!("Expected FileTransfer error, got: {e:?}"),
        }
    }

    // ============== Transfer Mode Parsing ==============

    #[test]
    fn test_transfer_mode_parsing_in_runner() {
        use crate::ssh::TransferMode;

        assert!(TransferMode::parse("overwrite").is_some());
        assert!(TransferMode::parse("append").is_some());
        assert!(TransferMode::parse("resume").is_some());
        assert!(TransferMode::parse("fail_if_exists").is_some());
        assert!(TransferMode::parse("fail-if-exists").is_some());
        assert!(TransferMode::parse("invalid").is_none());
    }

    // ============== Host Config Tests ==============

    #[test]
    fn test_host_config_with_all_auth_types() {
        let key_auth = AuthConfig::Key {
            path: "~/.ssh/id_ed25519".to_string(),
            passphrase: Some(zeroize::Zeroizing::new("secret".to_string())),
        };
        let agent_auth = AuthConfig::Agent;
        let password_auth = AuthConfig::Password {
            password: zeroize::Zeroizing::new("pass123".to_string()),
        };

        assert_eq!(auth_type_name(&key_auth), "SSH Key");
        assert_eq!(auth_type_name(&agent_auth), "SSH Agent");
        assert_eq!(auth_type_name(&password_auth), "Password");
    }

    #[test]
    fn test_host_config_with_different_ports() {
        let mut hosts = HashMap::new();

        for port in [22, 2222, 22222, 443] {
            hosts.insert(
                format!("host-{port}"),
                HostConfig {
                    hostname: "test.local".to_string(),
                    port,
                    user: "user".to_string(),
                    auth: AuthConfig::Agent,
                    description: None,
                    host_key_verification: HostKeyVerification::Off,
                    proxy_jump: None,
                    socks_proxy: None,
                    sudo_password: None,
                    os_type: OsType::Linux,
                    shell: None,
                },
            );
        }

        assert_eq!(hosts.get("host-22").unwrap().port, 22);
        assert_eq!(hosts.get("host-2222").unwrap().port, 2222);
        assert_eq!(hosts.get("host-22222").unwrap().port, 22222);
        assert_eq!(hosts.get("host-443").unwrap().port, 443);
    }

    #[test]
    fn test_host_key_verification_modes() {
        let modes = [
            HostKeyVerification::Strict,
            HostKeyVerification::AcceptNew,
            HostKeyVerification::Off,
        ];

        for mode in modes {
            let host = HostConfig {
                hostname: "test.local".to_string(),
                port: 22,
                user: "user".to_string(),
                auth: AuthConfig::Agent,
                description: None,
                host_key_verification: mode,
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                os_type: OsType::Linux,
                shell: None,
            };
            // Should not panic
            let _ = format!("{:?}", host.host_key_verification);
        }
    }
}
