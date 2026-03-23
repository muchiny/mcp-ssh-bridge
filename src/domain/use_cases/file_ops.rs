//! File Operations Command Builder
//!
//! Builds commands for file read, write, permissions, and stat operations.

use std::fmt::Write;

use crate::config::ShellType;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds file operation commands for remote execution.
pub struct FileOpsCommandBuilder;

impl FileOpsCommandBuilder {
    /// Build a command to read a file with optional line range.
    ///
    /// Constructs: `sed -n '{start},{end}p' {path}` or `cat {path}`
    #[must_use]
    pub fn build_read_command(path: &str, offset: Option<u64>, limit: Option<u64>) -> String {
        let escaped = shell_escape(path);
        match (offset, limit) {
            (Some(off), Some(lim)) => {
                let end = off.saturating_add(lim);
                format!("sed -n '{off},{end}p' {escaped}")
            }
            (Some(off), None) => format!("sed -n '{off},$p' {escaped}"),
            (None, Some(lim)) => format!("head -n {lim} {escaped}"),
            (None, None) => format!("cat {escaped}"),
        }
    }

    /// Build a command to write content to a file.
    ///
    /// Constructs: `cat > {path} << 'MCPEOF'\n{content}\nMCPEOF` or append variant
    #[must_use]
    pub fn build_write_command(path: &str, content: &str, append: bool) -> String {
        let escaped = shell_escape(path);
        let operator = if append { ">>" } else { ">" };
        // Use printf for safe content transfer (handles special chars)
        let encoded = content.replace('\\', "\\\\").replace('%', "%%");
        let printf_escaped = shell_escape(&encoded);
        format!("printf {printf_escaped} {operator} {escaped}")
    }

    /// Build a chmod command.
    ///
    /// Constructs: `chmod [-R] {mode} {path}`
    #[must_use]
    pub fn build_chmod_command(path: &str, mode: &str, recursive: bool) -> String {
        let escaped = shell_escape(path);
        let mode_escaped = shell_escape(mode);
        let recursive_flag = if recursive { "-R " } else { "" };
        format!("chmod {recursive_flag}{mode_escaped} {escaped}")
    }

    /// Build a chown command.
    ///
    /// Constructs: `chown [-R] {owner}[:{group}] {path}`
    #[must_use]
    pub fn build_chown_command(
        path: &str,
        owner: &str,
        group: Option<&str>,
        recursive: bool,
    ) -> String {
        let escaped = shell_escape(path);
        let recursive_flag = if recursive { "-R " } else { "" };
        let ownership = if let Some(g) = group {
            let mut s = String::new();
            let _ = write!(s, "{owner}:{g}");
            s
        } else {
            owner.to_string()
        };
        let ownership_escaped = shell_escape(&ownership);
        format!("chown {recursive_flag}{ownership_escaped} {escaped}")
    }

    /// Build a stat command.
    ///
    /// Constructs: `stat -c '{format}' {path}` (Linux)
    #[must_use]
    pub fn build_stat_command(path: &str) -> String {
        let escaped = shell_escape(path);
        format!("stat -c '%A %U %G %s %Y %n' {escaped} && file -b {escaped}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_command_simple() {
        let cmd = FileOpsCommandBuilder::build_read_command("/etc/hosts", None, None);
        assert!(cmd.contains("cat"));
        assert!(cmd.contains("/etc/hosts"));
    }

    #[test]
    fn test_read_command_with_offset_limit() {
        let cmd = FileOpsCommandBuilder::build_read_command("/var/log/syslog", Some(10), Some(20));
        assert!(cmd.contains("sed"));
        assert!(cmd.contains("10,30p"));
    }

    #[test]
    fn test_read_command_head_only() {
        let cmd = FileOpsCommandBuilder::build_read_command("/etc/hosts", None, Some(50));
        assert!(cmd.contains("head"));
        assert!(cmd.contains("-n 50"));
    }

    #[test]
    fn test_write_command_overwrite() {
        let cmd = FileOpsCommandBuilder::build_write_command("/tmp/test.txt", "hello", false);
        assert!(cmd.contains("> "));
        assert!(!cmd.contains(">>"));
    }

    #[test]
    fn test_write_command_append() {
        let cmd = FileOpsCommandBuilder::build_write_command("/tmp/test.txt", "hello", true);
        assert!(cmd.contains(">>"));
    }

    #[test]
    fn test_chmod_command() {
        let cmd = FileOpsCommandBuilder::build_chmod_command("/tmp/script.sh", "755", false);
        assert!(cmd.contains("chmod"));
        assert!(cmd.contains("755"));
    }

    #[test]
    fn test_chmod_recursive() {
        let cmd = FileOpsCommandBuilder::build_chmod_command("/var/www", "755", true);
        assert!(cmd.contains("-R"));
    }

    #[test]
    fn test_chown_command() {
        let cmd = FileOpsCommandBuilder::build_chown_command(
            "/tmp/file",
            "root",
            Some("www-data"),
            false,
        );
        assert!(cmd.contains("chown"));
        assert!(cmd.contains("root:www-data"));
    }

    #[test]
    fn test_chown_no_group() {
        let cmd = FileOpsCommandBuilder::build_chown_command("/tmp/file", "admin", None, false);
        assert!(cmd.contains("admin"));
        assert!(!cmd.contains(':'));
    }

    #[test]
    fn test_stat_command() {
        let cmd = FileOpsCommandBuilder::build_stat_command("/etc/passwd");
        assert!(cmd.contains("stat"));
        assert!(cmd.contains("/etc/passwd"));
    }
}
