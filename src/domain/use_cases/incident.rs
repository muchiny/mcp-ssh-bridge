//! Incident Timeline Command Builder
//!
//! Builds incident investigation commands for remote execution via SSH.
//! Supports timeline construction from multiple log sources and
//! service-specific correlation.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate that a services string contains only valid service name characters.
/// Service names must be comma-separated and contain only alphanumeric chars, `-`, `_`, and `.`.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if any service name contains invalid characters.
pub fn validate_services(services: &str) -> Result<()> {
    if services.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Services string must not be empty".to_string(),
        });
    }
    for service in services.split(',') {
        let trimmed = service.trim();
        if trimmed.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Service name must not be empty".to_string(),
            });
        }
        if !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid service name '{trimmed}': only alphanumeric characters, '-', '_', \
                     and '.' are allowed"
                ),
            });
        }
    }
    Ok(())
}

/// Builds incident investigation commands for remote execution.
pub struct IncidentCommandBuilder;

impl IncidentCommandBuilder {
    /// Build a compound command that constructs an incident timeline by correlating
    /// multiple log sources: journalctl errors, failed systemd units, login events,
    /// kernel messages, and recently modified log files.
    ///
    /// # Arguments
    ///
    /// * `since` - Optional start time (e.g., "1 hour ago", "2024-01-01 00:00:00")
    /// * `until` - Optional end time
    #[must_use]
    pub fn build_incident_timeline_command(since: Option<&str>, until: Option<&str>) -> String {
        let since_flag = since.map_or(String::new(), |s| format!(" --since {}", shell_escape(s)));
        let until_flag = until.map_or(String::new(), |u| format!(" --until {}", shell_escape(u)));

        let timestamp_ref = since.map_or_else(
            || {
                String::from(
                    "$(date -d '1 hour ago' +%Y%m%d%H%M.%S 2>/dev/null || \
                             date -v-1H +%Y%m%d%H%M.%S 2>/dev/null)",
                )
            },
            |s| {
                format!(
                    "$(date -d {} +%Y%m%d%H%M.%S 2>/dev/null || echo '000000000000.00')",
                    shell_escape(s)
                )
            },
        );

        format!(
            "echo '=== Incident Timeline ===' && \
             echo '--- Journal Errors ---' && \
             journalctl -p err{since_flag}{until_flag} --no-pager -q -n 50 2>/dev/null \
             || echo 'journalctl not available' && \
             echo '--- Failed Units ---' && \
             systemctl --failed --no-pager 2>/dev/null || echo 'systemctl not available' && \
             echo '--- Recent Logins ---' && \
             last -n 10 2>/dev/null || echo 'last not available' && \
             echo '--- Kernel Messages ---' && \
             dmesg --time-format iso 2>/dev/null | tail -20 \
             || dmesg 2>/dev/null | tail -20 \
             || echo 'dmesg not available' && \
             echo '--- Recently Modified Logs ---' && \
             find /var/log -name '*.log' -newer /tmp/.incident_ref 2>/dev/null | head -20; \
             touch -t {timestamp_ref} /tmp/.incident_ref 2>/dev/null; true"
        )
    }

    /// Build a command to correlate log entries across specific services.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the services string is invalid.
    pub fn build_incident_correlate_command(services: &str, since: Option<&str>) -> Result<String> {
        validate_services(services)?;

        let mut service_flags = String::new();
        for s in services.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let _ = write!(service_flags, " -u {}", shell_escape(s));
        }

        let since_flag = since.map_or(String::new(), |s| format!(" --since {}", shell_escape(s)));

        Ok(format!(
            "echo '=== Service Correlation ===' && \
             journalctl{service_flags}{since_flag} --no-pager -q 2>/dev/null \
             || echo 'journalctl not available'"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_services ────────────────────────────────────────

    #[test]
    fn test_validate_services_valid() {
        assert!(validate_services("nginx").is_ok());
        assert!(validate_services("nginx,postgresql").is_ok());
        assert!(validate_services("my-service,other_service").is_ok());
        assert!(validate_services("app.service").is_ok());
        assert!(validate_services("svc1, svc2, svc3").is_ok());
    }

    #[test]
    fn test_validate_services_empty() {
        assert!(validate_services("").is_err());
    }

    #[test]
    fn test_validate_services_empty_element() {
        assert!(validate_services("nginx,,postgresql").is_err());
        assert!(validate_services(",nginx").is_err());
    }

    #[test]
    fn test_validate_services_invalid_chars() {
        assert!(validate_services("nginx;rm -rf /").is_err());
        assert!(validate_services("$(whoami)").is_err());
        assert!(validate_services("a b").is_err());
        assert!(validate_services("svc&other").is_err());
    }

    #[test]
    fn test_validate_services_error_message() {
        let result = validate_services("bad;service");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Invalid service name"));
                assert!(reason.contains("bad;service"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── build_incident_timeline_command ──────────────────────────

    #[test]
    fn test_timeline_no_args() {
        let cmd = IncidentCommandBuilder::build_incident_timeline_command(None, None);
        assert!(cmd.contains("Incident Timeline"));
        assert!(cmd.contains("Journal Errors"));
        assert!(cmd.contains("Failed Units"));
        assert!(cmd.contains("Recent Logins"));
        assert!(cmd.contains("Kernel Messages"));
        assert!(cmd.contains("Recently Modified Logs"));
    }

    #[test]
    fn test_timeline_with_since() {
        let cmd = IncidentCommandBuilder::build_incident_timeline_command(Some("1 hour ago"), None);
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("1 hour ago"));
    }

    #[test]
    fn test_timeline_with_until() {
        let cmd = IncidentCommandBuilder::build_incident_timeline_command(
            None,
            Some("2024-01-01 12:00:00"),
        );
        assert!(cmd.contains("--until"));
        assert!(cmd.contains("2024-01-01 12:00:00"));
    }

    #[test]
    fn test_timeline_with_both() {
        let cmd = IncidentCommandBuilder::build_incident_timeline_command(
            Some("2024-01-01"),
            Some("2024-01-02"),
        );
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("--until"));
    }

    #[test]
    fn test_timeline_contains_journalctl() {
        let cmd = IncidentCommandBuilder::build_incident_timeline_command(None, None);
        assert!(cmd.contains("journalctl -p err"));
    }

    #[test]
    fn test_timeline_contains_systemctl() {
        let cmd = IncidentCommandBuilder::build_incident_timeline_command(None, None);
        assert!(cmd.contains("systemctl --failed"));
    }

    #[test]
    fn test_timeline_contains_dmesg() {
        let cmd = IncidentCommandBuilder::build_incident_timeline_command(None, None);
        assert!(cmd.contains("dmesg"));
    }

    #[test]
    fn test_timeline_contains_last() {
        let cmd = IncidentCommandBuilder::build_incident_timeline_command(None, None);
        assert!(cmd.contains("last -n 10"));
    }

    #[test]
    fn test_timeline_shell_escapes_since() {
        let cmd = IncidentCommandBuilder::build_incident_timeline_command(Some("$(whoami)"), None);
        assert!(cmd.contains("'$(whoami)'"));
    }

    // ── build_incident_correlate_command ─────────────────────────

    #[test]
    fn test_correlate_single_service() {
        let cmd = IncidentCommandBuilder::build_incident_correlate_command("nginx", None).unwrap();
        assert!(cmd.contains("-u 'nginx'"));
        assert!(cmd.contains("Service Correlation"));
    }

    #[test]
    fn test_correlate_multiple_services() {
        let cmd =
            IncidentCommandBuilder::build_incident_correlate_command("nginx,postgresql", None)
                .unwrap();
        assert!(cmd.contains("-u 'nginx'"));
        assert!(cmd.contains("-u 'postgresql'"));
    }

    #[test]
    fn test_correlate_with_since() {
        let cmd =
            IncidentCommandBuilder::build_incident_correlate_command("nginx", Some("1 hour ago"))
                .unwrap();
        assert!(cmd.contains("--since"));
        assert!(cmd.contains("1 hour ago"));
    }

    #[test]
    fn test_correlate_invalid_services() {
        let result = IncidentCommandBuilder::build_incident_correlate_command("bad;service", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_correlate_empty_services() {
        let result = IncidentCommandBuilder::build_incident_correlate_command("", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_correlate_shell_escapes_since() {
        let cmd =
            IncidentCommandBuilder::build_incident_correlate_command("nginx", Some("$(whoami)"))
                .unwrap();
        assert!(cmd.contains("'$(whoami)'"));
    }
}
