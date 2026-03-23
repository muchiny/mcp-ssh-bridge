//! Journald Command Builder
//!
//! Builds journalctl commands for querying systemd journal logs.

use std::fmt::Write;

use crate::config::ShellType;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds journalctl commands.
pub struct JournaldCommandBuilder;

impl JournaldCommandBuilder {
    /// Build a journalctl query command.
    #[must_use]
    pub fn build_query_command(
        unit: Option<&str>,
        priority: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
        lines: Option<u64>,
        grep: Option<&str>,
        reverse: bool,
    ) -> String {
        let mut cmd = String::from("journalctl --no-pager");
        if let Some(u) = unit {
            let _ = write!(cmd, " -u {}", shell_escape(u));
        }
        if let Some(p) = priority {
            let _ = write!(cmd, " -p {}", shell_escape(p));
        }
        if let Some(s) = since {
            let _ = write!(cmd, " --since {}", shell_escape(s));
        }
        if let Some(u) = until {
            let _ = write!(cmd, " --until {}", shell_escape(u));
        }
        if let Some(n) = lines {
            let _ = write!(cmd, " -n {n}");
        }
        if let Some(g) = grep {
            let _ = write!(cmd, " -g {}", shell_escape(g));
        }
        if reverse {
            cmd.push_str(" -r");
        }
        cmd
    }

    /// Build a journal follow command (with timeout safety).
    #[must_use]
    pub fn build_follow_command(unit: Option<&str>, lines: Option<u64>) -> String {
        let mut cmd = String::from("journalctl --no-pager -f");
        if let Some(u) = unit {
            let _ = write!(cmd, " -u {}", shell_escape(u));
        }
        let n = lines.unwrap_or(50);
        let _ = write!(cmd, " -n {n}");
        cmd
    }

    /// Build a list-boots command.
    #[must_use]
    pub fn build_boots_command() -> String {
        "journalctl --list-boots --no-pager".to_string()
    }

    /// Build a disk-usage command.
    #[must_use]
    pub fn build_disk_usage_command() -> String {
        "journalctl --disk-usage".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_simple() {
        let cmd = JournaldCommandBuilder::build_query_command(
            Some("nginx"),
            None,
            None,
            None,
            Some(100),
            None,
            false,
        );
        assert!(cmd.contains("journalctl"));
        assert!(cmd.contains("-u"));
        assert!(cmd.contains("nginx"));
        assert!(cmd.contains("-n 100"));
    }

    #[test]
    fn test_query_with_priority_and_time() {
        let cmd = JournaldCommandBuilder::build_query_command(
            None,
            Some("err"),
            Some("2024-01-01"),
            Some("2024-01-02"),
            None,
            None,
            true,
        );
        assert!(cmd.contains("-p"));
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("--until"));
        assert!(cmd.contains("-r"));
    }

    #[test]
    fn test_query_with_grep() {
        let cmd = JournaldCommandBuilder::build_query_command(
            None,
            None,
            None,
            None,
            Some(50),
            Some("error"),
            false,
        );
        assert!(cmd.contains("-g"));
    }

    #[test]
    fn test_follow() {
        let cmd = JournaldCommandBuilder::build_follow_command(Some("sshd"), Some(20));
        assert!(cmd.contains("-f"));
        assert!(cmd.contains("-u"));
        assert!(cmd.contains("-n 20"));
    }

    #[test]
    fn test_boots() {
        let cmd = JournaldCommandBuilder::build_boots_command();
        assert!(cmd.contains("--list-boots"));
    }

    #[test]
    fn test_disk_usage() {
        let cmd = JournaldCommandBuilder::build_disk_usage_command();
        assert!(cmd.contains("--disk-usage"));
    }
}
