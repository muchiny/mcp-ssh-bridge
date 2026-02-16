//! Ansible Command Builder
//!
//! Builds `ansible-playbook`, `ansible-inventory`, and `ansible` (ad-hoc)
//! CLI commands for remote execution via SSH.

use std::collections::HashMap;
use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Write verbose flags (`-v`, `-vv`, `-vvv`, `-vvvv`) capped at 4.
fn write_verbose_flags(cmd: &mut String, level: u8) {
    let capped = level.min(4);
    if capped > 0 {
        cmd.push_str(" -");
        for _ in 0..capped {
            cmd.push('v');
        }
    }
}

/// Builds Ansible CLI commands for remote execution.
pub struct AnsibleCommandBuilder;

impl AnsibleCommandBuilder {
    /// Build an `ansible-playbook` command.
    ///
    /// Constructs a shell command string like:
    /// `[cd {working_dir} && ] ansible-playbook {playbook} [-i {inventory}]
    /// [--limit {limit}] [--tags {tags}] [--skip-tags {skip}]
    /// [-e key=value ...] [--check] [--diff] [-v..vvvv] [-f {forks}]
    /// [-b] [--become-user {user}]`
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build_playbook_command(
        playbook: &str,
        inventory: Option<&str>,
        limit: Option<&str>,
        tags: Option<&str>,
        skip_tags: Option<&str>,
        extra_vars: Option<&HashMap<String, String>>,
        check: bool,
        diff: bool,
        verbose: Option<u8>,
        forks: Option<u32>,
        use_become: bool,
        become_user: Option<&str>,
        working_dir: Option<&str>,
    ) -> String {
        let mut cmd = String::new();

        if let Some(dir) = working_dir {
            let _ = write!(cmd, "cd {} && ", shell_escape(dir));
        }

        let _ = write!(cmd, "ansible-playbook {}", shell_escape(playbook));

        if let Some(inv) = inventory {
            let _ = write!(cmd, " -i {}", shell_escape(inv));
        }

        if let Some(lim) = limit {
            let _ = write!(cmd, " --limit {}", shell_escape(lim));
        }

        if let Some(t) = tags {
            let _ = write!(cmd, " --tags {}", shell_escape(t));
        }

        if let Some(st) = skip_tags {
            let _ = write!(cmd, " --skip-tags {}", shell_escape(st));
        }

        if let Some(vars) = extra_vars {
            let mut keys: Vec<&String> = vars.keys().collect();
            keys.sort();
            for key in keys {
                let value = &vars[key];
                let _ = write!(cmd, " -e {}={}", shell_escape(key), shell_escape(value));
            }
        }

        if check {
            cmd.push_str(" --check");
        }

        if diff {
            cmd.push_str(" --diff");
        }

        if let Some(v) = verbose {
            write_verbose_flags(&mut cmd, v);
        }

        if let Some(f) = forks {
            let _ = write!(cmd, " -f {f}");
        }

        if use_become {
            cmd.push_str(" -b");
        }

        if let Some(user) = become_user {
            let _ = write!(cmd, " --become-user {}", shell_escape(user));
        }

        cmd
    }

    /// Build an `ansible-inventory` command.
    ///
    /// Constructs a shell command string like:
    /// `ansible-inventory [-i {inventory}] [--list] [--graph [{group}]]
    /// [--host {host}] [--yaml] [--vars]`
    ///
    /// If none of `list`, `graph`, or `host_pattern` is set, defaults to `--list`.
    #[must_use]
    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    pub fn build_inventory_command(
        inventory: Option<&str>,
        list: bool,
        graph: bool,
        host_pattern: Option<&str>,
        group: Option<&str>,
        yaml: bool,
        vars: bool,
    ) -> String {
        let mut cmd = String::from("ansible-inventory");

        if let Some(inv) = inventory {
            let _ = write!(cmd, " -i {}", shell_escape(inv));
        }

        let has_action = list || graph || host_pattern.is_some();

        if list {
            cmd.push_str(" --list");
        }

        if graph {
            if let Some(g) = group {
                let _ = write!(cmd, " --graph {}", shell_escape(g));
            } else {
                cmd.push_str(" --graph");
            }
        }

        if let Some(host) = host_pattern {
            let _ = write!(cmd, " --host {}", shell_escape(host));
        }

        if !has_action {
            cmd.push_str(" --list");
        }

        if yaml {
            cmd.push_str(" --yaml");
        }

        if vars {
            cmd.push_str(" --vars");
        }

        cmd
    }

    /// Build an `ansible` ad-hoc command.
    ///
    /// Constructs a shell command string like:
    /// `ansible {pattern} -m {module} [-a {args}] [-i {inventory}]
    /// [-b] [--become-user {user}] [-u {user}] [-f {forks}]
    /// [-v..vvvv] [-C]`
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build_adhoc_command(
        pattern: &str,
        module: &str,
        args: Option<&str>,
        inventory: Option<&str>,
        use_become: bool,
        become_user: Option<&str>,
        user: Option<&str>,
        forks: Option<u32>,
        verbose: Option<u8>,
        check: bool,
    ) -> String {
        let mut cmd = String::new();

        let _ = write!(
            cmd,
            "ansible {} -m {}",
            shell_escape(pattern),
            shell_escape(module)
        );

        if let Some(a) = args {
            let _ = write!(cmd, " -a {}", shell_escape(a));
        }

        if let Some(inv) = inventory {
            let _ = write!(cmd, " -i {}", shell_escape(inv));
        }

        if use_become {
            cmd.push_str(" -b");
        }

        if let Some(bu) = become_user {
            let _ = write!(cmd, " --become-user {}", shell_escape(bu));
        }

        if let Some(u) = user {
            let _ = write!(cmd, " -u {}", shell_escape(u));
        }

        if let Some(f) = forks {
            let _ = write!(cmd, " -f {f}");
        }

        if let Some(v) = verbose {
            write_verbose_flags(&mut cmd, v);
        }

        if check {
            cmd.push_str(" -C");
        }

        cmd
    }

    /// Validate a playbook path.
    ///
    /// Rejects paths with `..` (directory traversal).
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the path contains `..`.
    pub fn validate_playbook_path(playbook: &str) -> Result<()> {
        if playbook.contains("..") {
            return Err(BridgeError::CommandDenied {
                reason: "Path traversal not allowed in playbook path".to_string(),
            });
        }
        Ok(())
    }

    /// Validate an ansible module for safety.
    ///
    /// Blocks the `raw`, `shell`, and `command` modules when args contain
    /// dangerous patterns such as `rm -rf`, `mkfs`, `dd if=`,
    /// `> /dev/`, or `chmod 777`.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if a dangerous combination is
    /// detected.
    pub fn validate_adhoc_module(module: &str, args: Option<&str>) -> Result<()> {
        let dangerous_modules = ["raw", "shell", "command"];
        let dangerous_patterns = ["rm -rf", "mkfs", "dd if=", "> /dev/", "chmod 777"];

        if dangerous_modules.contains(&module)
            && let Some(a) = args
        {
            let lower = a.to_lowercase();
            for pattern in &dangerous_patterns {
                if lower.contains(pattern) {
                    return Err(BridgeError::CommandDenied {
                        reason: format!(
                            "Dangerous pattern '{pattern}' not \
                             allowed with module '{module}'"
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== Playbook Command Tests ==============

    #[test]
    fn test_build_playbook_minimal() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml", None, None, None, None, None, false, false, None, None, false, None, None,
        );
        assert_eq!(cmd, "ansible-playbook 'site.yml'");
    }

    #[test]
    fn test_build_playbook_all_options() {
        let mut vars = HashMap::new();
        vars.insert("env".to_string(), "prod".to_string());
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "deploy.yml",
            Some("/etc/ansible/hosts"),
            Some("webservers"),
            Some("deploy,config"),
            Some("slow"),
            Some(&vars),
            true,
            true,
            Some(2),
            Some(10),
            true,
            Some("deploy_user"),
            Some("/opt/ansible"),
        );
        assert!(cmd.starts_with("cd '/opt/ansible' && "));
        assert!(cmd.contains("ansible-playbook 'deploy.yml'"));
        assert!(cmd.contains("-i '/etc/ansible/hosts'"));
        assert!(cmd.contains("--limit 'webservers'"));
        assert!(cmd.contains("--tags 'deploy,config'"));
        assert!(cmd.contains("--skip-tags 'slow'"));
        assert!(cmd.contains("-e 'env'='prod'"));
        assert!(cmd.contains("--check"));
        assert!(cmd.contains("--diff"));
        assert!(cmd.contains("-vv"));
        assert!(cmd.contains("-f 10"));
        assert!(cmd.contains(" -b"));
        assert!(cmd.contains("--become-user 'deploy_user'"));
    }

    #[test]
    fn test_build_playbook_with_extra_vars() {
        let mut vars = HashMap::new();
        vars.insert("version".to_string(), "1.2.3".to_string());
        vars.insert("env".to_string(), "staging".to_string());
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "deploy.yml",
            None,
            None,
            None,
            None,
            Some(&vars),
            false,
            false,
            None,
            None,
            false,
            None,
            None,
        );
        // Keys are sorted, so env comes before version
        assert!(cmd.contains("-e 'env'='staging'"));
        assert!(cmd.contains("-e 'version'='1.2.3'"));
    }

    #[test]
    fn test_build_playbook_with_working_dir() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            Some("/home/deploy/playbooks"),
        );
        assert!(cmd.starts_with("cd '/home/deploy/playbooks' && "));
        assert!(cmd.contains("ansible-playbook 'site.yml'"));
    }

    #[test]
    fn test_build_playbook_verbose_levels() {
        for level in 0u8..=4 {
            let cmd = AnsibleCommandBuilder::build_playbook_command(
                "site.yml",
                None,
                None,
                None,
                None,
                None,
                false,
                false,
                Some(level),
                None,
                false,
                None,
                None,
            );
            if level == 0 {
                assert!(!cmd.contains("-v"), "level 0 should not have -v");
            } else {
                let expected_v = format!("-{}", "v".repeat(level as usize));
                assert!(
                    cmd.contains(&expected_v),
                    "level {level} should contain {expected_v}, \
                     got: {cmd}"
                );
            }
        }
    }

    #[test]
    fn test_build_playbook_verbose_capped() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            Some(10),
            None,
            false,
            None,
            None,
        );
        // Should be capped at -vvvv (4)
        assert!(cmd.contains("-vvvv"));
        assert!(!cmd.contains("-vvvvv"));
    }

    #[test]
    fn test_build_playbook_shell_escape() {
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "my playbook's.yml",
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            false,
            None,
            None,
        );
        assert!(cmd.contains("'my playbook'\\''s.yml'"));
    }

    // ============== Inventory Command Tests ==============

    #[test]
    fn test_build_inventory_list() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            Some("/etc/ansible/hosts"),
            true,
            false,
            None,
            None,
            false,
            false,
        );
        assert!(cmd.contains("ansible-inventory"));
        assert!(cmd.contains("-i '/etc/ansible/hosts'"));
        assert!(cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_graph() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None, false, true, None, None, false, false,
        );
        assert!(cmd.contains("--graph"));
        assert!(!cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_graph_with_group() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None,
            false,
            true,
            None,
            Some("webservers"),
            false,
            false,
        );
        assert!(cmd.contains("--graph 'webservers'"));
    }

    #[test]
    fn test_build_inventory_host() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None,
            false,
            false,
            Some("server1"),
            None,
            false,
            false,
        );
        assert!(cmd.contains("--host 'server1'"));
        assert!(!cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_default_list() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None, false, false, None, None, false, false,
        );
        assert!(cmd.contains("--list"));
    }

    #[test]
    fn test_build_inventory_yaml() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None, true, false, None, None, true, false,
        );
        assert!(cmd.contains("--list"));
        assert!(cmd.contains("--yaml"));
    }

    // ============== Adhoc Command Tests ==============

    #[test]
    fn test_build_adhoc_ping() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all", "ping", None, None, false, None, None, None, None, false,
        );
        assert_eq!(cmd, "ansible 'all' -m 'ping'");
    }

    #[test]
    fn test_build_adhoc_all_options() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "webservers",
            "shell",
            Some("uptime"),
            Some("/etc/ansible/hosts"),
            true,
            Some("root"),
            Some("admin"),
            Some(5),
            Some(3),
            true,
        );
        assert!(cmd.contains("ansible 'webservers' -m 'shell'"));
        assert!(cmd.contains("-a 'uptime'"));
        assert!(cmd.contains("-i '/etc/ansible/hosts'"));
        assert!(cmd.contains(" -b"));
        assert!(cmd.contains("--become-user 'root'"));
        assert!(cmd.contains("-u 'admin'"));
        assert!(cmd.contains("-f 5"));
        assert!(cmd.contains("-vvv"));
        assert!(cmd.contains("-C"));
    }

    #[test]
    fn test_build_adhoc_shell_module() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all",
            "shell",
            Some("cat /etc/hostname"),
            None,
            false,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(cmd.contains("-m 'shell'"));
        assert!(cmd.contains("-a 'cat /etc/hostname'"));
    }

    // ============== Validation Tests ==============

    #[test]
    fn test_validate_playbook_path_ok() {
        assert!(AnsibleCommandBuilder::validate_playbook_path("site.yml").is_ok());
        assert!(AnsibleCommandBuilder::validate_playbook_path("playbooks/deploy.yml").is_ok());
        assert!(AnsibleCommandBuilder::validate_playbook_path("/opt/ansible/site.yml").is_ok());
    }

    #[test]
    fn test_validate_playbook_path_traversal() {
        let result = AnsibleCommandBuilder::validate_playbook_path("../../../etc/passwd");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Path traversal"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }

        assert!(AnsibleCommandBuilder::validate_playbook_path("roles/../site.yml").is_err());
    }

    #[test]
    fn test_validate_adhoc_safe_modules() {
        assert!(AnsibleCommandBuilder::validate_adhoc_module("ping", None).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("setup", None).is_ok());
        assert!(
            AnsibleCommandBuilder::validate_adhoc_module("copy", Some("src=/tmp/a dest=/tmp/b"))
                .is_ok()
        );
    }

    #[test]
    fn test_validate_adhoc_raw_with_rm() {
        let result = AnsibleCommandBuilder::validate_adhoc_module("raw", Some("rm -rf /"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("rm -rf"));
                assert!(reason.contains("raw"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }
    }

    #[test]
    fn test_validate_adhoc_shell_with_mkfs() {
        let result =
            AnsibleCommandBuilder::validate_adhoc_module("shell", Some("mkfs.ext4 /dev/sda1"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("mkfs"));
                assert!(reason.contains("shell"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }
    }

    #[test]
    fn test_validate_adhoc_shell_safe_args() {
        assert!(AnsibleCommandBuilder::validate_adhoc_module("shell", Some("ls -la /tmp")).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("command", Some("whoami")).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("raw", Some("uptime")).is_ok());
    }

    #[test]
    fn test_validate_adhoc_command_with_dd() {
        let result = AnsibleCommandBuilder::validate_adhoc_module(
            "command",
            Some("dd if=/dev/zero of=/dev/sda"),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("dd if="));
                assert!(reason.contains("command"));
            }
            e => {
                panic!("Expected CommandDenied error, got: {e:?}");
            }
        }
    }

    // ============== Additional Edge Case Tests ==============

    #[test]
    fn test_validate_adhoc_redirect_to_dev() {
        let result =
            AnsibleCommandBuilder::validate_adhoc_module("shell", Some("echo x > /dev/sda"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("> /dev/"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_adhoc_chmod_777() {
        let result =
            AnsibleCommandBuilder::validate_adhoc_module("raw", Some("chmod 777 /etc/passwd"));
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("chmod 777"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_adhoc_dangerous_module_no_args() {
        // Dangerous module with no args should be OK (no pattern to match)
        assert!(AnsibleCommandBuilder::validate_adhoc_module("raw", None).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("shell", None).is_ok());
        assert!(AnsibleCommandBuilder::validate_adhoc_module("command", None).is_ok());
    }

    #[test]
    fn test_build_adhoc_verbose_capped() {
        let cmd = AnsibleCommandBuilder::build_adhoc_command(
            "all",
            "ping",
            None,
            None,
            false,
            None,
            None,
            None,
            Some(10), // Should be capped at 4
            false,
        );
        // Should have -vvvv (4 v's max), not -vvvvvvvvvv
        assert!(cmd.contains("-vvvv"));
        let count = cmd.matches("-vvvv").count();
        assert_eq!(count, 1); // Exactly one -vvvv, not more
    }

    // ============== Security: Injection Prevention Tests ==============

    #[test]
    fn test_extra_vars_key_injection_prevented() {
        let mut vars = HashMap::new();
        vars.insert("$(whoami)".to_string(), "bar".to_string());
        let cmd = AnsibleCommandBuilder::build_playbook_command(
            "site.yml",
            None,
            None,
            None,
            None,
            Some(&vars),
            false,
            false,
            None,
            None,
            false,
            None,
            None,
        );
        // Key should be escaped, not interpreted
        assert!(cmd.contains("-e '$(whoami)'='bar'"));
        assert!(!cmd.contains("-e $(whoami)="));
    }

    #[test]
    fn test_build_inventory_vars_without_list() {
        let cmd = AnsibleCommandBuilder::build_inventory_command(
            None,  // inventory
            false, // list
            false, // graph
            None,  // host
            None,  // group
            false, // yaml
            true,  // vars
        );
        assert!(cmd.contains("ansible-inventory"));
        assert!(cmd.contains("--vars"));
    }
}
