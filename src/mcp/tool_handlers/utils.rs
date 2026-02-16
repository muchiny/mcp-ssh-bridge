//! Utility functions for tool handlers

use crate::config::{Config, HostConfig, LimitsConfig, ShellType};
use crate::error::{BridgeError, Result};
use crate::ssh::SshClient;

/// Validate a file path for potential path traversal attacks.
///
/// Returns an error if the path contains `..` components that could be used
/// for directory traversal attacks.
pub fn validate_path(path: &str) -> Result<()> {
    // Check for path traversal patterns
    if path.contains("..") {
        return Err(BridgeError::FileTransfer {
            reason: "Path traversal not allowed: path contains '..'".to_string(),
        });
    }
    Ok(())
}

/// Shell escape a string for safe use in shell commands
///
/// Wraps the string in single quotes and escapes any existing single quotes.
/// This is the POSIX-only variant. For shell-aware escaping, use [`shell_escape_for`].
pub fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Shell escape a string for a specific shell type.
///
/// Delegates to [`crate::domain::use_cases::shell::escape`].
pub fn shell_escape_for(s: &str, shell: ShellType) -> String {
    crate::domain::use_cases::shell::escape(s, shell)
}

/// Connect to a host, resolving jump host if configured.
pub async fn connect_with_jump(
    host_name: &str,
    host_config: &HostConfig,
    limits: &LimitsConfig,
    config: &Config,
) -> Result<SshClient> {
    let jump_host = host_config.proxy_jump.as_ref().and_then(|jump_name| {
        config
            .hosts
            .get(jump_name)
            .map(|jump_config| (jump_name.as_str(), jump_config))
    });

    if let Some((jump_name, jump_config)) = jump_host {
        SshClient::connect_via_jump(host_name, host_config, jump_name, jump_config, limits).await
    } else {
        SshClient::connect(host_name, host_config, limits).await
    }
}

/// Save full output to a local file on the MCP server's filesystem.
///
/// Creates parent directories if needed. Returns a confirmation message
/// with byte count on success, or a [`BridgeError::FileTransfer`] on failure.
pub async fn save_output_to_file(path: &str, content: &str) -> Result<String> {
    // Reject path traversal attempts
    if path.contains("..") {
        return Err(BridgeError::FileTransfer {
            reason: "Path traversal not allowed: path contains '..'".to_string(),
        });
    }

    let path = std::path::Path::new(path);

    // Create parent directories if needed
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| BridgeError::FileTransfer {
                reason: format!("Failed to create directory {}: {e}", parent.display()),
            })?;
    }

    // Write with restrictive permissions (0o600) to protect sensitive output
    {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let path_owned = path.to_path_buf();
        let content_owned = content.to_string();
        tokio::task::spawn_blocking(move || {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            opts.mode(0o600);
            let mut file = opts
                .open(&path_owned)
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Failed to write to {}: {e}", path_owned.display()),
                })?;
            file.write_all(content_owned.as_bytes())
                .map_err(|e| BridgeError::FileTransfer {
                    reason: format!("Failed to write to {}: {e}", path_owned.display()),
                })?;
            Ok::<(), BridgeError>(())
        })
        .await
        .map_err(|e| BridgeError::FileTransfer {
            reason: format!("Failed to write to {}: {e}", path.display()),
        })??;
    }

    Ok(format!(
        "Full output saved to {} ({} bytes)",
        path.display(),
        content.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_escape_simple() {
        assert_eq!(shell_escape("simple"), "'simple'");
    }

    #[test]
    fn test_shell_escape_with_spaces() {
        assert_eq!(shell_escape("with spaces"), "'with spaces'");
    }

    #[test]
    fn test_shell_escape_with_quotes() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_escape_empty() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn test_shell_escape_special_chars() {
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
        assert_eq!(shell_escape("foo;bar"), "'foo;bar'");
        assert_eq!(shell_escape("a`cmd`b"), "'a`cmd`b'");
    }

    // ============== Additional shell_escape Tests ==============

    #[test]
    fn test_shell_escape_multiple_quotes() {
        assert_eq!(shell_escape("a'b'c'd"), "'a'\\''b'\\''c'\\''d'");
    }

    #[test]
    fn test_shell_escape_consecutive_quotes() {
        // '' becomes: open quote, escape first ', escape second ', close quote
        // '' -> ' + '\'' + '\'' + ' = ''\\'''\\'''
        assert_eq!(shell_escape("''"), "''\\'''\\'''");
    }

    #[test]
    fn test_shell_escape_quote_at_start() {
        // 'hello -> ' + '\'' + hello + '
        assert_eq!(shell_escape("'hello"), "''\\''hello'");
    }

    #[test]
    fn test_shell_escape_quote_at_end() {
        assert_eq!(shell_escape("hello'"), "'hello'\\'''");
    }

    #[test]
    fn test_shell_escape_newline() {
        assert_eq!(shell_escape("line1\nline2"), "'line1\nline2'");
    }

    #[test]
    fn test_shell_escape_tab() {
        assert_eq!(shell_escape("col1\tcol2"), "'col1\tcol2'");
    }

    #[test]
    fn test_shell_escape_carriage_return() {
        assert_eq!(shell_escape("a\rb"), "'a\rb'");
    }

    #[test]
    fn test_shell_escape_double_quotes() {
        assert_eq!(shell_escape("\"quoted\""), "'\"quoted\"'");
    }

    #[test]
    fn test_shell_escape_mixed_quotes() {
        assert_eq!(shell_escape("\"it's\""), "'\"it'\\''s\"'");
    }

    #[test]
    fn test_shell_escape_backslash() {
        assert_eq!(shell_escape("a\\b"), "'a\\b'");
    }

    #[test]
    fn test_shell_escape_pipe() {
        assert_eq!(shell_escape("a|b"), "'a|b'");
    }

    #[test]
    fn test_shell_escape_ampersand() {
        assert_eq!(shell_escape("a&b"), "'a&b'");
    }

    #[test]
    fn test_shell_escape_redirect() {
        assert_eq!(shell_escape("a>b"), "'a>b'");
        assert_eq!(shell_escape("a<b"), "'a<b'");
    }

    #[test]
    fn test_shell_escape_wildcard() {
        assert_eq!(shell_escape("*.txt"), "'*.txt'");
        assert_eq!(shell_escape("?file"), "'?file'");
    }

    #[test]
    fn test_shell_escape_bracket() {
        assert_eq!(shell_escape("[abc]"), "'[abc]'");
    }

    #[test]
    fn test_shell_escape_unicode() {
        assert_eq!(shell_escape("日本語"), "'日本語'");
        assert_eq!(shell_escape("emoji🎉"), "'emoji🎉'");
    }

    #[test]
    fn test_shell_escape_path() {
        assert_eq!(shell_escape("/path/to/file"), "'/path/to/file'");
    }

    #[test]
    fn test_shell_escape_path_with_spaces() {
        assert_eq!(
            shell_escape("/path/to/my file.txt"),
            "'/path/to/my file.txt'"
        );
    }

    #[test]
    fn test_shell_escape_very_long_string() {
        let long_str = "a".repeat(10000);
        let escaped = shell_escape(&long_str);
        assert_eq!(escaped.len(), 10002); // 10000 + 2 quotes
    }

    #[test]
    fn test_shell_escape_null_byte() {
        // Null bytes shouldn't happen but test handling
        assert_eq!(shell_escape("a\0b"), "'a\0b'");
    }

    #[test]
    fn test_shell_escape_environment_var() {
        assert_eq!(shell_escape("$HOME/dir"), "'$HOME/dir'");
        assert_eq!(shell_escape("${VAR}"), "'${VAR}'");
    }

    #[test]
    fn test_shell_escape_command_substitution() {
        assert_eq!(shell_escape("$(whoami)"), "'$(whoami)'");
    }

    // ============== validate_path Tests ==============

    #[test]
    fn test_validate_path_normal() {
        assert!(validate_path("/home/user/file.txt").is_ok());
        assert!(validate_path("relative/path/file.txt").is_ok());
        assert!(validate_path("file.txt").is_ok());
    }

    #[test]
    fn test_validate_path_traversal_rejected() {
        assert!(validate_path("../secret").is_err());
        assert!(validate_path("/home/../etc/passwd").is_err());
        assert!(validate_path("foo/../../bar").is_err());
        assert!(validate_path("..").is_err());
    }

    #[test]
    fn test_validate_path_dots_allowed() {
        // Single dots and dots in filenames are fine
        assert!(validate_path("/home/user/.bashrc").is_ok());
        assert!(validate_path("./file.txt").is_ok());
        assert!(validate_path(".hidden").is_ok());
        assert!(validate_path("file.name.txt").is_ok());
    }

    // ============== save_output_to_file Tests ==============

    #[tokio::test]
    async fn test_save_output_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.txt");

        let result = save_output_to_file(path.to_str().unwrap(), "hello world").await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("11 bytes"));

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(content, "hello world");
    }

    #[tokio::test]
    async fn test_save_output_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deep").join("nested").join("output.txt");

        let result = save_output_to_file(path.to_str().unwrap(), "data").await;
        assert!(result.is_ok());
        assert!(path.exists());
    }

    #[tokio::test]
    async fn test_save_output_invalid_path() {
        let result = save_output_to_file("/proc/0/nonexistent/file", "data").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed"));
    }
}
