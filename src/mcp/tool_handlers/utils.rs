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

/// Parsed columnar CLI output (docker ps, docker stats, kubectl top, etc.).
pub struct ParsedTable {
    /// Column headers, lowercased (e.g., `["container id", "image", "status", "names"]`).
    pub headers: Vec<String>,
    /// Data rows. Each inner `Vec` has the same length as `headers`.
    pub rows: Vec<Vec<String>>,
}

impl ParsedTable {
    /// Convert to TSV (tab-separated values) for token-efficient LLM consumption.
    ///
    /// Returns uppercased header row + tab-separated data rows.
    /// TSV uses 30-40% fewer tokens than JSON for tabular data (pgEdge benchmark).
    #[must_use]
    pub fn to_tsv(&self) -> String {
        let mut result = String::new();
        // Header row (uppercase for readability)
        for (i, h) in self.headers.iter().enumerate() {
            if i > 0 {
                result.push('\t');
            }
            result.push_str(&h.to_uppercase());
        }
        // Data rows
        for row in &self.rows {
            result.push('\n');
            for (i, val) in row.iter().enumerate() {
                if i > 0 {
                    result.push('\t');
                }
                result.push_str(val);
            }
        }
        result
    }
}

/// Parse columnar CLI output using header-position-based column boundary detection.
///
/// Algorithm:
/// 1. First non-empty line is the header
/// 2. Header tokens are separated by 2+ whitespace characters
/// 3. Each token's byte-offset start position defines a column boundary
/// 4. Data rows are sliced at these boundaries: `row[start[N]..start[N+1]].trim()`
///
/// Returns `None` if fewer than 2 non-empty lines are found.
#[must_use]
pub fn parse_columnar_output(output: &str) -> Option<ParsedTable> {
    let lines: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 2 {
        return None;
    }

    let header_line = lines[0];

    // Find column start positions by scanning for 2+ space boundaries.
    // Each header token starts after a run of 2+ spaces (or at position 0).
    let mut col_starts: Vec<usize> = Vec::new();
    let bytes = header_line.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    // First token always starts at 0 (skip leading whitespace if any)
    while i < len && bytes[i] == b' ' {
        i += 1;
    }
    if i < len {
        col_starts.push(i);
    }

    // Scan for transitions: non-space -> 2+ spaces -> non-space
    while i < len {
        // Skip non-space characters (current token)
        while i < len && bytes[i] != b' ' {
            i += 1;
        }
        // Count consecutive spaces
        let space_start = i;
        while i < len && bytes[i] == b' ' {
            i += 1;
        }
        // If 2+ spaces and followed by non-space, this is a column boundary
        if i - space_start >= 2 && i < len {
            col_starts.push(i);
        } else if i - space_start == 1 && i < len {
            // Single space = part of the same token (e.g., "CONTAINER ID", "MEM USAGE / LIMIT")
            // Continue scanning
        }
    }

    if col_starts.is_empty() {
        return None;
    }

    // Extract header names from the column boundaries
    let headers: Vec<String> = col_starts
        .iter()
        .enumerate()
        .map(|(idx, &start)| {
            let end = col_starts.get(idx + 1).copied().unwrap_or(len);
            header_line
                .get(start..end)
                .unwrap_or("")
                .trim()
                .to_lowercase()
        })
        .collect();

    // Parse data rows
    let rows: Vec<Vec<String>> = lines[1..]
        .iter()
        .map(|line| {
            let line_len = line.len();
            col_starts
                .iter()
                .enumerate()
                .map(|(idx, &start)| {
                    if start >= line_len {
                        return String::new();
                    }
                    let end = col_starts
                        .get(idx + 1)
                        .copied()
                        .unwrap_or(line_len)
                        .min(line_len);
                    line.get(start..end).unwrap_or("").trim().to_string()
                })
                .collect()
        })
        .collect();

    Some(ParsedTable { headers, rows })
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

    // ============== parse_columnar_output Tests ==============

    #[test]
    fn test_parse_columnar_docker_ps() {
        let output = "\
CONTAINER ID   IMAGE          COMMAND       CREATED        STATUS        PORTS                  NAMES
a1b2c3d4e5f6   nginx:latest   \"nginx -g…\"   2 hours ago    Up 2 hours    0.0.0.0:80->80/tcp     web
f6e5d4c3b2a1   redis:7        \"redis-s…\"    3 hours ago    Up 3 hours    6379/tcp               cache";

        let parsed = parse_columnar_output(output).unwrap();
        assert_eq!(parsed.headers.len(), 7);
        assert_eq!(parsed.headers[0], "container id");
        assert_eq!(parsed.headers[1], "image");
        assert_eq!(parsed.headers[6], "names");
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0][1], "nginx:latest");
        assert_eq!(parsed.rows[0][6], "web");
        assert_eq!(parsed.rows[1][1], "redis:7");
        assert_eq!(parsed.rows[1][6], "cache");
    }

    #[test]
    fn test_parse_columnar_docker_stats() {
        let output = "\
CONTAINER ID   NAME   CPU %   MEM USAGE / LIMIT     MEM %   NET I/O         BLOCK I/O       PIDS
a1b2c3d4e5f6   web    0.50%   24.5MiB / 7.77GiB     0.31%   1.2kB / 648B    8.19kB / 0B     2
f6e5d4c3b2a1   db     1.20%   128MiB / 7.77GiB      1.61%   5.4kB / 3.2kB   12.5kB / 4kB    8";

        let parsed = parse_columnar_output(output).unwrap();
        assert_eq!(parsed.headers[1], "name");
        assert_eq!(parsed.headers[2], "cpu %");
        assert_eq!(parsed.headers[3], "mem usage / limit");
        assert_eq!(parsed.headers[4], "mem %");
        assert_eq!(parsed.headers[5], "net i/o");
        assert_eq!(parsed.headers[6], "block i/o");
        assert_eq!(parsed.headers[7], "pids");
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0][1], "web");
        assert_eq!(parsed.rows[0][2], "0.50%");
        assert_eq!(parsed.rows[1][1], "db");
    }

    #[test]
    fn test_parse_columnar_kubectl_top_pods() {
        let output = "\
NAME                           CPU(cores)   MEMORY(bytes)
nginx-deploy-6799fc88d8-abc    3m           52Mi
redis-master-0                 15m          128Mi";

        let parsed = parse_columnar_output(output).unwrap();
        assert_eq!(parsed.headers, vec!["name", "cpu(cores)", "memory(bytes)"]);
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0][0], "nginx-deploy-6799fc88d8-abc");
        assert_eq!(parsed.rows[0][1], "3m");
        assert_eq!(parsed.rows[0][2], "52Mi");
    }

    #[test]
    fn test_parse_columnar_kubectl_top_nodes() {
        let output = "\
NAME     CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%
node-1   250m         12%    1024Mi          25%
node-2   500m         25%    2048Mi          50%";

        let parsed = parse_columnar_output(output).unwrap();
        assert_eq!(parsed.headers.len(), 5);
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0][0], "node-1");
        assert_eq!(parsed.rows[0][2], "12%");
        assert_eq!(parsed.rows[1][4], "50%");
    }

    #[test]
    fn test_parse_columnar_empty() {
        assert!(parse_columnar_output("").is_none());
        assert!(parse_columnar_output("   \n  \n  ").is_none());
    }

    #[test]
    fn test_parse_columnar_header_only() {
        assert!(parse_columnar_output("NAME   IMAGE   STATUS").is_none());
    }

    #[test]
    fn test_parse_columnar_short_lines() {
        let output = "\
NAME           IMAGE          STATUS
container1     nginx:latest
short";

        let parsed = parse_columnar_output(output).unwrap();
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0][0], "container1");
        assert_eq!(parsed.rows[0][1], "nginx:latest");
        assert_eq!(parsed.rows[0][2], ""); // short line, no status
        assert_eq!(parsed.rows[1][0], "short");
        assert_eq!(parsed.rows[1][1], ""); // even shorter
    }

    // ============== to_tsv Tests ==============

    #[test]
    fn test_to_tsv_basic() {
        let output = "\
NAME           IMAGE          STATUS
container1     nginx:latest   Up 2 hours
container2     redis:7        Up 3 hours";

        let parsed = parse_columnar_output(output).unwrap();
        let tsv = parsed.to_tsv();
        let lines: Vec<&str> = tsv.lines().collect();
        assert_eq!(lines[0], "NAME\tIMAGE\tSTATUS");
        assert_eq!(lines[1], "container1\tnginx:latest\tUp 2 hours");
        assert_eq!(lines[2], "container2\tredis:7\tUp 3 hours");
    }

    #[test]
    fn test_to_tsv_single_row() {
        let output = "\
NAME     CPU
node-1   250m";

        let parsed = parse_columnar_output(output).unwrap();
        let tsv = parsed.to_tsv();
        assert_eq!(tsv, "NAME\tCPU\nnode-1\t250m");
    }
}
