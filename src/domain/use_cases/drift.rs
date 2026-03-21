//! Environment Drift Detection Command Builder
//!
//! Builds commands to capture system state snapshots for drift detection.

/// Builds drift detection commands for remote execution.
pub struct DriftCommandBuilder;

impl DriftCommandBuilder {
    /// Build a command to capture a comprehensive environment snapshot.
    #[must_use]
    pub fn build_snapshot_command() -> String {
        [
            r#"echo "=== OS ===""#,
            "cat /etc/os-release 2>/dev/null | head -5 || uname -a",
            r#"echo "=== KERNEL ===""#,
            "uname -r",
            r#"echo "=== HOSTNAME ===""#,
            "hostname -f 2>/dev/null || hostname",
            r#"echo "=== PACKAGES ===""#,
            "dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | sort || rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort || apk list -I 2>/dev/null | sort || echo 'unknown'",
            r#"echo "=== SERVICES ===""#,
            "systemctl list-units --type=service --state=active --no-pager --no-legend 2>/dev/null | awk '{print $1}' | sort || true",
            r#"echo "=== LISTENERS ===""#,
            "ss -tunapl 2>/dev/null | tail -n +2 | awk '{print $1,$4,$5}' | sort || netstat -tunapl 2>/dev/null | tail -n +3 | awk '{print $1,$4,$5}' | sort || true",
            r#"echo "=== USERS ===""#,
            "getent passwd | awk -F: '$3>=1000{print $1}' | sort || true",
            r#"echo "=== GROUPS ===""#,
            "getent group | awk -F: '$3>=1000{print $1}' | sort || true",
            r#"echo "=== CRONTABS ===""#,
            "for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do crontab -u $u -l 2>/dev/null | grep -v '^#' | grep -v '^$' && echo \"USER:$u\"; done || true",
            r#"echo "=== CHECKSUM ===""#,
            "sha256sum /etc/ssh/sshd_config /etc/passwd /etc/group /etc/fstab 2>/dev/null | sort || true",
        ]
        .join(" && ")
    }

    /// Build a command to diff two snapshot outputs.
    ///
    /// This builds a local diff command (not SSH) since the snapshots are stored locally.
    #[must_use]
    pub fn build_diff_instruction() -> &'static str {
        "Use ssh_env_snapshot on two hosts (or the same host at different times), \
         save outputs to local files with save_output, then use your local diff \
         capability to compare them."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_command_contains_sections() {
        let cmd = DriftCommandBuilder::build_snapshot_command();
        assert!(cmd.contains("PACKAGES"));
        assert!(cmd.contains("SERVICES"));
        assert!(cmd.contains("LISTENERS"));
        assert!(cmd.contains("USERS"));
        assert!(cmd.contains("KERNEL"));
        assert!(cmd.contains("CHECKSUM"));
    }

    #[test]
    fn test_diff_instruction() {
        let instr = DriftCommandBuilder::build_diff_instruction();
        assert!(instr.contains("ssh_env_snapshot"));
    }
}
