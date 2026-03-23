//! Podman Command Builder
//!
//! Builds Podman CLI commands. Mirrors Docker builder but uses podman binary.

use std::fmt::Write;

use crate::config::ShellType;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds Podman CLI commands for remote execution.
pub struct PodmanCommandBuilder;

impl PodmanCommandBuilder {
    /// Build a `podman ps` command.
    #[must_use]
    pub fn build_ps_command(all: bool, filter: Option<&str>, format: Option<&str>) -> String {
        let mut cmd = String::from("podman ps");
        if all {
            cmd.push_str(" -a");
        }
        if let Some(f) = filter {
            let _ = write!(cmd, " --filter {}", shell_escape(f));
        }
        if let Some(fmt) = format {
            let _ = write!(cmd, " --format {}", shell_escape(fmt));
        }
        cmd
    }

    /// Build a `podman logs` command.
    #[must_use]
    pub fn build_logs_command(
        container: &str,
        tail: Option<u64>,
        since: Option<&str>,
        follow: bool,
    ) -> String {
        let mut cmd = String::from("podman logs");
        if let Some(t) = tail {
            let _ = write!(cmd, " --tail {t}");
        }
        if let Some(s) = since {
            let _ = write!(cmd, " --since {}", shell_escape(s));
        }
        if follow {
            cmd.push_str(" -f");
        }
        let _ = write!(cmd, " {}", shell_escape(container));
        cmd
    }

    /// Build a `podman inspect` command.
    #[must_use]
    pub fn build_inspect_command(target: &str) -> String {
        format!("podman inspect {}", shell_escape(target))
    }

    /// Build a `podman exec` command.
    #[must_use]
    pub fn build_exec_command(container: &str, command: &str, interactive: bool) -> String {
        let mut cmd = String::from("podman exec");
        if interactive {
            cmd.push_str(" -it");
        }
        let _ = write!(cmd, " {} {}", shell_escape(container), command);
        cmd
    }

    /// Build a `podman images` command.
    #[must_use]
    pub fn build_images_command(filter: Option<&str>) -> String {
        let mut cmd = String::from("podman images");
        if let Some(f) = filter {
            let _ = write!(cmd, " --filter {}", shell_escape(f));
        }
        cmd
    }

    /// Build a `podman-compose` or `podman compose` command.
    #[must_use]
    pub fn build_compose_command(action: &str, file: Option<&str>) -> String {
        let mut cmd = String::from("podman compose");
        if let Some(f) = file {
            let _ = write!(cmd, " -f {}", shell_escape(f));
        }
        let _ = write!(cmd, " {action}");
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ps_default() {
        let cmd = PodmanCommandBuilder::build_ps_command(false, None, None);
        assert_eq!(cmd, "podman ps");
    }

    #[test]
    fn test_ps_all_with_filter() {
        let cmd = PodmanCommandBuilder::build_ps_command(true, Some("status=running"), None);
        assert!(cmd.contains("-a"));
        assert!(cmd.contains("--filter"));
    }

    #[test]
    fn test_logs() {
        let cmd = PodmanCommandBuilder::build_logs_command("myapp", Some(100), None, false);
        assert!(cmd.contains("podman logs"));
        assert!(cmd.contains("--tail 100"));
        assert!(cmd.contains("myapp"));
    }

    #[test]
    fn test_inspect() {
        let cmd = PodmanCommandBuilder::build_inspect_command("mycontainer");
        assert!(cmd.contains("podman inspect"));
    }

    #[test]
    fn test_exec() {
        let cmd = PodmanCommandBuilder::build_exec_command("myapp", "bash", true);
        assert!(cmd.contains("-it"));
        assert!(cmd.contains("bash"));
    }

    #[test]
    fn test_images() {
        let cmd = PodmanCommandBuilder::build_images_command(None);
        assert_eq!(cmd, "podman images");
    }

    #[test]
    fn test_compose() {
        let cmd =
            PodmanCommandBuilder::build_compose_command("up -d", Some("docker-compose.prod.yml"));
        assert!(cmd.contains("podman compose"));
        assert!(cmd.contains("-f"));
        assert!(cmd.contains("up -d"));
    }
}
