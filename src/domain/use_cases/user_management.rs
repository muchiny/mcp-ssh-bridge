//! User Management Command Builder
//!
//! Builds commands for user and group management on Linux hosts.

use std::fmt::Write;

use crate::config::ShellType;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds user and group management commands.
pub struct UserCommandBuilder;

impl UserCommandBuilder {
    /// Build a command to list system users.
    #[must_use]
    pub fn build_user_list_command(system: bool) -> String {
        if system {
            "getent passwd".to_string()
        } else {
            // Only regular users (UID >= 1000, excluding nobody)
            "awk -F: '$3 >= 1000 && $1 != \"nobody\" {print}' /etc/passwd".to_string()
        }
    }

    /// Build a command to get user info.
    #[must_use]
    pub fn build_user_info_command(username: &str) -> String {
        let escaped = shell_escape(username);
        format!(
            "id {escaped} && getent passwd {escaped} && lastlog -u {escaped} 2>/dev/null; groups {escaped}"
        )
    }

    /// Build a useradd command.
    #[must_use]
    pub fn build_user_add_command(
        username: &str,
        home_dir: Option<&str>,
        shell: Option<&str>,
        groups: Option<&str>,
        system: bool,
        create_home: bool,
    ) -> String {
        let mut cmd = String::from("useradd");
        if system {
            cmd.push_str(" --system");
        }
        if create_home {
            cmd.push_str(" --create-home");
        }
        if let Some(h) = home_dir {
            let _ = write!(cmd, " --home-dir {}", shell_escape(h));
        }
        if let Some(s) = shell {
            let _ = write!(cmd, " --shell {}", shell_escape(s));
        }
        if let Some(g) = groups {
            let _ = write!(cmd, " --groups {}", shell_escape(g));
        }
        let _ = write!(cmd, " {}", shell_escape(username));
        cmd
    }

    /// Build a usermod command.
    #[must_use]
    pub fn build_user_modify_command(
        username: &str,
        shell: Option<&str>,
        groups: Option<&str>,
        append_groups: bool,
        home_dir: Option<&str>,
        lock: Option<bool>,
    ) -> String {
        let mut cmd = String::from("usermod");
        if let Some(s) = shell {
            let _ = write!(cmd, " --shell {}", shell_escape(s));
        }
        if let Some(g) = groups {
            if append_groups {
                let _ = write!(cmd, " --append --groups {}", shell_escape(g));
            } else {
                let _ = write!(cmd, " --groups {}", shell_escape(g));
            }
        }
        if let Some(h) = home_dir {
            let _ = write!(cmd, " --home {}", shell_escape(h));
        }
        if let Some(true) = lock {
            cmd.push_str(" --lock");
        }
        if let Some(false) = lock {
            cmd.push_str(" --unlock");
        }
        let _ = write!(cmd, " {}", shell_escape(username));
        cmd
    }

    /// Build a userdel command.
    #[must_use]
    pub fn build_user_delete_command(username: &str, remove_home: bool) -> String {
        let escaped = shell_escape(username);
        if remove_home {
            format!("userdel --remove {escaped}")
        } else {
            format!("userdel {escaped}")
        }
    }

    /// Build a command to list groups.
    #[must_use]
    pub fn build_group_list_command() -> String {
        "getent group".to_string()
    }

    /// Build a groupadd command.
    #[must_use]
    pub fn build_group_add_command(name: &str, gid: Option<u32>, system: bool) -> String {
        let mut cmd = String::from("groupadd");
        if system {
            cmd.push_str(" --system");
        }
        if let Some(id) = gid {
            let _ = write!(cmd, " --gid {id}");
        }
        let _ = write!(cmd, " {}", shell_escape(name));
        cmd
    }

    /// Build a groupdel command.
    #[must_use]
    pub fn build_group_delete_command(name: &str) -> String {
        format!("groupdel {}", shell_escape(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_list_regular() {
        let cmd = UserCommandBuilder::build_user_list_command(false);
        assert!(cmd.contains("awk"));
        assert!(cmd.contains("1000"));
    }

    #[test]
    fn test_user_list_system() {
        let cmd = UserCommandBuilder::build_user_list_command(true);
        assert_eq!(cmd, "getent passwd");
    }

    #[test]
    fn test_user_info() {
        let cmd = UserCommandBuilder::build_user_info_command("admin");
        assert!(cmd.contains("id"));
        assert!(cmd.contains("getent passwd"));
        assert!(cmd.contains("admin"));
    }

    #[test]
    fn test_user_add_simple() {
        let cmd =
            UserCommandBuilder::build_user_add_command("newuser", None, None, None, false, true);
        assert!(cmd.contains("useradd"));
        assert!(cmd.contains("--create-home"));
        assert!(cmd.contains("newuser"));
    }

    #[test]
    fn test_user_add_full() {
        let cmd = UserCommandBuilder::build_user_add_command(
            "deploy",
            Some("/opt/deploy"),
            Some("/bin/bash"),
            Some("docker,sudo"),
            false,
            true,
        );
        assert!(cmd.contains("--home-dir"));
        assert!(cmd.contains("--shell"));
        assert!(cmd.contains("--groups"));
    }

    #[test]
    fn test_user_modify() {
        let cmd = UserCommandBuilder::build_user_modify_command(
            "admin",
            Some("/bin/zsh"),
            Some("docker"),
            true,
            None,
            None,
        );
        assert!(cmd.contains("usermod"));
        assert!(cmd.contains("--append"));
        assert!(cmd.contains("--groups"));
    }

    #[test]
    fn test_user_delete() {
        let cmd = UserCommandBuilder::build_user_delete_command("olduser", true);
        assert!(cmd.contains("userdel"));
        assert!(cmd.contains("--remove"));
    }

    #[test]
    fn test_group_list() {
        let cmd = UserCommandBuilder::build_group_list_command();
        assert_eq!(cmd, "getent group");
    }

    #[test]
    fn test_group_add() {
        let cmd = UserCommandBuilder::build_group_add_command("developers", Some(1500), false);
        assert!(cmd.contains("groupadd"));
        assert!(cmd.contains("--gid 1500"));
    }

    #[test]
    fn test_group_delete() {
        let cmd = UserCommandBuilder::build_group_delete_command("oldgroup");
        assert!(cmd.contains("groupdel"));
    }
}
