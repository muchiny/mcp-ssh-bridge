//! Security Modules Command Builder
//!
//! Builds commands for `SELinux` and `AppArmor` status and management.

use crate::config::ShellType;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds security module commands (`SELinux`, `AppArmor`).
pub struct SecurityModulesCommandBuilder;

impl SecurityModulesCommandBuilder {
    /// Build `SELinux` status command.
    #[must_use]
    pub fn build_selinux_status_command() -> String {
        "getenforce 2>/dev/null && sestatus 2>/dev/null || echo 'SELinux not available'".to_string()
    }

    /// Build `SELinux` booleans list/set command.
    #[must_use]
    pub fn build_selinux_booleans_command(name: Option<&str>, value: Option<bool>) -> String {
        match (name, value) {
            (Some(n), Some(v)) => {
                let val = if v { "on" } else { "off" };
                format!("setsebool -P {} {}", shell_escape(n), val)
            }
            (Some(n), None) => format!("getsebool {}", shell_escape(n)),
            _ => "getsebool -a".to_string(),
        }
    }

    /// Build `AppArmor` status command.
    #[must_use]
    pub fn build_apparmor_status_command() -> String {
        "aa-status 2>/dev/null || apparmor_status 2>/dev/null || echo 'AppArmor not available'"
            .to_string()
    }

    /// Build `AppArmor` profiles list command.
    #[must_use]
    pub fn build_apparmor_profiles_command() -> String {
        "aa-status --json 2>/dev/null || cat /sys/kernel/security/apparmor/profiles 2>/dev/null || echo 'AppArmor not available'".to_string()
    }

    /// Build a quick security audit command.
    #[must_use]
    pub fn build_security_audit_command() -> String {
        "echo '=== Users without password ===' && \
         awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow 2>/dev/null; \
         echo '=== SUID binaries ===' && \
         find / -perm -4000 -type f 2>/dev/null | head -50; \
         echo '=== World-writable files (non-tmp) ===' && \
         find / -path /tmp -prune -o -path /var/tmp -prune -o -perm -0002 -type f -print 2>/dev/null | head -50; \
         echo '=== Listening ports ===' && \
         ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selinux_status() {
        let cmd = SecurityModulesCommandBuilder::build_selinux_status_command();
        assert!(cmd.contains("getenforce"));
        assert!(cmd.contains("sestatus"));
    }

    #[test]
    fn test_selinux_booleans_list() {
        let cmd = SecurityModulesCommandBuilder::build_selinux_booleans_command(None, None);
        assert!(cmd.contains("getsebool -a"));
    }

    #[test]
    fn test_selinux_booleans_get() {
        let cmd = SecurityModulesCommandBuilder::build_selinux_booleans_command(
            Some("httpd_can_network_connect"),
            None,
        );
        assert!(cmd.contains("getsebool"));
        assert!(cmd.contains("httpd_can_network_connect"));
    }

    #[test]
    fn test_selinux_booleans_set() {
        let cmd = SecurityModulesCommandBuilder::build_selinux_booleans_command(
            Some("httpd_can_network_connect"),
            Some(true),
        );
        assert!(cmd.contains("setsebool"));
        assert!(cmd.contains("on"));
    }

    #[test]
    fn test_apparmor_status() {
        let cmd = SecurityModulesCommandBuilder::build_apparmor_status_command();
        assert!(cmd.contains("aa-status"));
    }

    #[test]
    fn test_apparmor_profiles() {
        let cmd = SecurityModulesCommandBuilder::build_apparmor_profiles_command();
        assert!(cmd.contains("aa-status"));
    }

    #[test]
    fn test_security_audit() {
        let cmd = SecurityModulesCommandBuilder::build_security_audit_command();
        assert!(cmd.contains("SUID"));
        assert!(cmd.contains("shadow"));
        assert!(cmd.contains("World-writable"));
    }
}
