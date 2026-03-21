//! SBOM & Vulnerability Scanning Command Builder
//!
//! Builds commands for software inventory and security scanning.

/// Builds SBOM and vulnerability scanning commands.
pub struct SbomCommandBuilder;

impl SbomCommandBuilder {
    /// Build a command to generate a software bill of materials.
    #[must_use]
    pub fn build_sbom_command() -> String {
        [
            r#"echo "=== PACKAGE MANAGER ===""#,
            "command -v dpkg >/dev/null && echo 'dpkg' || (command -v rpm >/dev/null && echo 'rpm' || (command -v apk >/dev/null && echo 'apk' || echo 'unknown'))",
            r#"echo "=== INSTALLED PACKAGES ===""#,
            "dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' 2>/dev/null | grep 'install ok installed' || rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\tinstalled\n' 2>/dev/null || apk list -I 2>/dev/null || echo 'Cannot determine packages'",
            r#"echo "=== KERNEL ===""#,
            "uname -r",
            r#"echo "=== OS ===""#,
            "cat /etc/os-release 2>/dev/null | grep -E '^(NAME|VERSION_ID|ID)=' || uname -a",
        ]
        .join(" && ")
    }

    /// Build a command to check for known vulnerabilities.
    #[must_use]
    pub fn build_vuln_scan_command() -> String {
        [
            r#"echo "=== UPGRADABLE PACKAGES (Security) ===""#,
            "apt list --upgradable 2>/dev/null | grep -i secur || yum updateinfo list sec 2>/dev/null || apk audit 2>/dev/null || echo 'No native security scanner available'",
            r#"echo "=== KERNEL VERSION CHECK ===""#,
            "uname -r",
            r#"echo "=== PENDING UPDATES ===""#,
            "apt list --upgradable 2>/dev/null | wc -l || yum check-update 2>/dev/null | tail -n +2 | wc -l || echo 'N/A'",
            r#"echo "=== LAST UPDATE ===""#,
            "stat -c '%y' /var/cache/apt/pkgcache.bin 2>/dev/null || stat -c '%y' /var/cache/yum 2>/dev/null || echo 'Unknown'",
        ]
        .join(" && ")
    }

    /// Build a CIS compliance check command.
    #[must_use]
    pub fn build_compliance_command(profile: &str) -> String {
        let checks = match profile {
            "cis-level1" | "cis-level2" => vec![
                r#"echo "=== CIS COMPLIANCE CHECK ===""#,
                r#"echo "--- File Permissions ---""#,
                "stat -c '%a %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null || true",
                r#"echo "--- SSH Configuration ---""#,
                "grep -E '^(PermitRootLogin|PasswordAuthentication|X11Forwarding|MaxAuthTries|Protocol)' /etc/ssh/sshd_config 2>/dev/null || true",
                r#"echo "--- Firewall Status ---""#,
                "ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -20 || firewall-cmd --state 2>/dev/null || echo 'No firewall detected'",
                r#"echo "--- Password Policy ---""#,
                "grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)' /etc/login.defs 2>/dev/null || true",
                r#"echo "--- Core Dumps ---""#,
                "grep -r 'hard.*core' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null || echo 'No core dump limits set'",
                r#"echo "--- Sysctl Security ---""#,
                "sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects kernel.randomize_va_space 2>/dev/null || true",
            ],
            _ => vec![
                r#"echo "=== BASIC COMPLIANCE CHECK ===""#,
                "stat -c '%a %n' /etc/passwd /etc/shadow 2>/dev/null || true",
                "grep '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || true",
            ],
        };
        checks.join(" && ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbom_command() {
        let cmd = SbomCommandBuilder::build_sbom_command();
        assert!(cmd.contains("INSTALLED PACKAGES"));
        assert!(cmd.contains("dpkg-query"));
        assert!(cmd.contains("rpm -qa"));
    }

    #[test]
    fn test_vuln_scan_command() {
        let cmd = SbomCommandBuilder::build_vuln_scan_command();
        assert!(cmd.contains("UPGRADABLE"));
        assert!(cmd.contains("KERNEL VERSION"));
    }

    #[test]
    fn test_compliance_cis() {
        let cmd = SbomCommandBuilder::build_compliance_command("cis-level1");
        assert!(cmd.contains("CIS COMPLIANCE"));
        assert!(cmd.contains("SSH Configuration"));
        assert!(cmd.contains("Firewall"));
        assert!(cmd.contains("Password Policy"));
    }

    #[test]
    fn test_compliance_basic() {
        let cmd = SbomCommandBuilder::build_compliance_command("basic");
        assert!(cmd.contains("BASIC COMPLIANCE"));
    }
}
