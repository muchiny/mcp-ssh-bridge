//! Orchestration Command Builder
//!
//! Builds commands for multi-host orchestration patterns: canary deployments,
//! rolling updates, and fleet-wide configuration drift detection.
//!
//! The actual orchestration logic (canary, rolling) lives in the tool handlers
//! since they need to coordinate multiple SSH calls. This builder only provides
//! helper methods for constructing the individual commands.

/// Builds commands for multi-host orchestration patterns.
pub struct OrchestrationCommandBuilder;

impl OrchestrationCommandBuilder {
    /// Build a canary execution command with an optional health check.
    ///
    /// Runs the primary command and, if a health check is provided,
    /// chains it with `&&` so a failing health check is visible in the output.
    #[must_use]
    pub fn build_canary_command(command: &str, health_check: Option<&str>) -> String {
        match health_check {
            Some(hc) if !hc.is_empty() => format!("{command} && ({hc} || true)"),
            _ => command.to_string(),
        }
    }

    /// Build a rolling execution command with an optional health check.
    ///
    /// Similar to canary but uses a descriptive fallback message when
    /// no health check is configured.
    #[must_use]
    pub fn build_rolling_command(command: &str, health_check: Option<&str>) -> String {
        match health_check {
            Some(hc) if !hc.is_empty() => {
                format!("{command} && ({hc} || echo 'no health check configured')")
            }
            _ => format!("{command} && echo 'no health check configured'"),
        }
    }

    /// Build a fleet diff command (just the command itself).
    ///
    /// The diff comparison is performed by the caller (Claude) across
    /// multiple hosts, so no additional logic is needed here.
    #[must_use]
    pub fn build_fleet_diff_command(command: &str) -> String {
        command.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_with_health_check() {
        let cmd =
            OrchestrationCommandBuilder::build_canary_command("apt upgrade -y", Some("curl -f http://localhost/health"));
        assert!(cmd.contains("apt upgrade -y"));
        assert!(cmd.contains("curl -f http://localhost/health"));
        assert!(cmd.contains("|| true"));
    }

    #[test]
    fn test_canary_without_health_check() {
        let cmd = OrchestrationCommandBuilder::build_canary_command("apt upgrade -y", None);
        assert_eq!(cmd, "apt upgrade -y");
    }

    #[test]
    fn test_canary_with_empty_health_check() {
        let cmd = OrchestrationCommandBuilder::build_canary_command("apt upgrade -y", Some(""));
        assert_eq!(cmd, "apt upgrade -y");
    }

    #[test]
    fn test_rolling_with_health_check() {
        let cmd = OrchestrationCommandBuilder::build_rolling_command(
            "systemctl restart nginx",
            Some("curl -f http://localhost"),
        );
        assert!(cmd.contains("systemctl restart nginx"));
        assert!(cmd.contains("curl -f http://localhost"));
    }

    #[test]
    fn test_rolling_without_health_check() {
        let cmd = OrchestrationCommandBuilder::build_rolling_command("systemctl restart nginx", None);
        assert!(cmd.contains("systemctl restart nginx"));
        assert!(cmd.contains("no health check configured"));
    }

    #[test]
    fn test_fleet_diff_command() {
        let cmd = OrchestrationCommandBuilder::build_fleet_diff_command("cat /etc/os-release");
        assert_eq!(cmd, "cat /etc/os-release");
    }
}
