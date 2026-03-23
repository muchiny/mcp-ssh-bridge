//! Capacity Planning Command Builder
//!
//! Builds capacity collection, trend analysis, and prediction commands
//! for remote execution via SSH. Supports CPU, memory, and disk resources.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Allowed resource names for capacity planning.
const ALLOWED_RESOURCES: &[&str] = &["cpu", "memory", "disk", "all"];

/// Maximum number of days for trend analysis.
const MAX_DAYS: u32 = 365;

/// Validate that a resource name is one of the allowed values.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the resource is not in the allowed list.
pub fn validate_resource(resource: &str) -> Result<()> {
    if !ALLOWED_RESOURCES.contains(&resource) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid resource '{}'. Allowed resources: {}",
                resource,
                ALLOWED_RESOURCES.join(", ")
            ),
        });
    }
    Ok(())
}

/// Validate that the number of days is within the allowed range.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if days exceeds the maximum.
pub fn validate_days(days: u32) -> Result<()> {
    if days > MAX_DAYS {
        return Err(BridgeError::CommandDenied {
            reason: format!("Days value {days} exceeds maximum of {MAX_DAYS}"),
        });
    }
    if days == 0 {
        return Err(BridgeError::CommandDenied {
            reason: "Days value must be at least 1".to_string(),
        });
    }
    Ok(())
}

/// Builds capacity planning commands for remote execution.
pub struct CapacityCommandBuilder;

impl CapacityCommandBuilder {
    /// Build a compound command to collect a comprehensive capacity snapshot.
    ///
    /// Collects: CPU count + usage, total/used/free RAM, disk usage per mount,
    /// inode usage, uptime, and load average.
    #[must_use]
    pub fn build_capacity_collect_command() -> String {
        "echo '=== CPU ===' && \
         nproc && \
         awk '{u=$2+$4; t=$2+$4+$5; if (NR>1) printf \"cpu_usage=%.1f%%\\n\", \
         ((u-pu)/(t-pt))*100; pu=u; pt=t}' \
         <(head -1 /proc/stat) <(sleep 1 && head -1 /proc/stat) && \
         echo '=== Memory ===' && \
         free -h && \
         echo '=== Disk Usage ===' && \
         df -h && \
         echo '=== Inode Usage ===' && \
         df -i && \
         echo '=== Uptime ===' && \
         uptime && \
         echo '=== Load Average ===' && \
         cat /proc/loadavg"
            .to_string()
    }

    /// Build a command to show resource usage trends using `sar` if available,
    /// falling back to a current snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the resource or days value is invalid.
    pub fn build_capacity_trend_command(
        resource: Option<&str>,
        days: Option<u32>,
    ) -> Result<String> {
        if let Some(r) = resource {
            validate_resource(r)?;
        }
        if let Some(d) = days {
            validate_days(d)?;
        }

        let resource = resource.unwrap_or("all");
        let days = days.unwrap_or(7);

        let sar_flag = match resource {
            "cpu" => "-u",
            "memory" => "-r",
            "disk" => "-d",
            _ => "-u -r -d",
        };

        let escaped_resource = shell_escape(resource);

        Ok(format!(
            "if command -v sar >/dev/null 2>&1; then \
             echo \"=== sar trends for {escaped_resource} (last {days} days) ===\"; \
             for i in $(seq 0 {days}); do \
             f=\"/var/log/sa/sa$(date -d \"$i days ago\" +%d 2>/dev/null || \
             date -v-${{i}}d +%d 2>/dev/null)\"; \
             [ -f \"$f\" ] && sar {sar_flag} -f \"$f\" 2>/dev/null; \
             done; \
             else \
             echo 'sar not available, showing current snapshot'; \
             echo '=== CPU ===' && \
             awk '{{u=$2+$4; t=$2+$4+$5; if (NR>1) printf \"cpu_usage=%.1f%%\\n\", \
             ((u-pu)/(t-pt))*100; pu=u; pt=t}}' \
             <(head -1 /proc/stat) <(sleep 1 && head -1 /proc/stat) && \
             echo '=== Memory ===' && free -h && \
             echo '=== Disk ===' && df -h; \
             fi"
        ))
    }

    /// Build a command to collect current and historical data for LLM-based
    /// capacity prediction.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CommandDenied`] if the resource is invalid.
    pub fn build_capacity_predict_command(resource: &str) -> Result<String> {
        validate_resource(resource)?;

        let escaped_resource = shell_escape(resource);
        let sar_flag = match resource {
            "cpu" => "-u",
            "memory" => "-r",
            "disk" => "-d",
            _ => "-u -r -d",
        };

        Ok(format!(
            "echo \"=== Capacity Prediction Data for {escaped_resource} ===\"; \
             echo '--- Current Snapshot ---'; \
             echo 'CPU cores:' && nproc; \
             free -h; \
             df -h; \
             uptime; \
             echo '--- Historical Data (sar) ---'; \
             if command -v sar >/dev/null 2>&1; then \
             for i in $(seq 0 30); do \
             f=\"/var/log/sa/sa$(date -d \"$i days ago\" +%d 2>/dev/null || \
             date -v-${{i}}d +%d 2>/dev/null)\"; \
             [ -f \"$f\" ] && sar {sar_flag} -f \"$f\" 2>/dev/null; \
             done; \
             else echo 'sar not available'; fi; \
             echo '--- Growth Indicators ---'; \
             du -sh /var/log/ 2>/dev/null; \
             du -sh /tmp/ 2>/dev/null; \
             du -sh /home/ 2>/dev/null"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_resource ────────────────────────────────────────

    #[test]
    fn test_validate_resource_valid() {
        assert!(validate_resource("cpu").is_ok());
        assert!(validate_resource("memory").is_ok());
        assert!(validate_resource("disk").is_ok());
        assert!(validate_resource("all").is_ok());
    }

    #[test]
    fn test_validate_resource_invalid() {
        assert!(validate_resource("gpu").is_err());
        assert!(validate_resource("").is_err());
        assert!(validate_resource("network").is_err());
        assert!(validate_resource("CPU").is_err());
    }

    #[test]
    fn test_validate_resource_error_message() {
        let result = validate_resource("invalid");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Invalid resource"));
                assert!(reason.contains("invalid"));
                assert!(reason.contains("cpu"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── validate_days ────────────────────────────────────────────

    #[test]
    fn test_validate_days_valid() {
        assert!(validate_days(1).is_ok());
        assert!(validate_days(7).is_ok());
        assert!(validate_days(30).is_ok());
        assert!(validate_days(365).is_ok());
    }

    #[test]
    fn test_validate_days_zero() {
        assert!(validate_days(0).is_err());
    }

    #[test]
    fn test_validate_days_exceeds_max() {
        assert!(validate_days(366).is_err());
        assert!(validate_days(1000).is_err());
    }

    #[test]
    fn test_validate_days_error_message() {
        let result = validate_days(500);
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("500"));
                assert!(reason.contains("365"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── build_capacity_collect_command ────────────────────────────

    #[test]
    fn test_collect_command_contains_cpu() {
        let cmd = CapacityCommandBuilder::build_capacity_collect_command();
        assert!(cmd.contains("CPU"));
        assert!(cmd.contains("nproc"));
    }

    #[test]
    fn test_collect_command_contains_memory() {
        let cmd = CapacityCommandBuilder::build_capacity_collect_command();
        assert!(cmd.contains("Memory"));
        assert!(cmd.contains("free -h"));
    }

    #[test]
    fn test_collect_command_contains_disk() {
        let cmd = CapacityCommandBuilder::build_capacity_collect_command();
        assert!(cmd.contains("Disk"));
        assert!(cmd.contains("df -h"));
    }

    #[test]
    fn test_collect_command_contains_inode() {
        let cmd = CapacityCommandBuilder::build_capacity_collect_command();
        assert!(cmd.contains("Inode"));
        assert!(cmd.contains("df -i"));
    }

    #[test]
    fn test_collect_command_contains_uptime() {
        let cmd = CapacityCommandBuilder::build_capacity_collect_command();
        assert!(cmd.contains("uptime"));
    }

    #[test]
    fn test_collect_command_contains_load() {
        let cmd = CapacityCommandBuilder::build_capacity_collect_command();
        assert!(cmd.contains("loadavg"));
    }

    // ── build_capacity_trend_command ─────────────────────────────

    #[test]
    fn test_trend_defaults() {
        let cmd = CapacityCommandBuilder::build_capacity_trend_command(None, None).unwrap();
        assert!(cmd.contains("sar"));
        assert!(cmd.contains("7"));
    }

    #[test]
    fn test_trend_cpu() {
        let cmd =
            CapacityCommandBuilder::build_capacity_trend_command(Some("cpu"), Some(14)).unwrap();
        assert!(cmd.contains("-u"));
        assert!(cmd.contains("14"));
    }

    #[test]
    fn test_trend_memory() {
        let cmd =
            CapacityCommandBuilder::build_capacity_trend_command(Some("memory"), Some(30)).unwrap();
        assert!(cmd.contains("-r"));
    }

    #[test]
    fn test_trend_disk() {
        let cmd =
            CapacityCommandBuilder::build_capacity_trend_command(Some("disk"), Some(7)).unwrap();
        assert!(cmd.contains("-d"));
    }

    #[test]
    fn test_trend_invalid_resource() {
        let result = CapacityCommandBuilder::build_capacity_trend_command(Some("invalid"), Some(7));
        assert!(result.is_err());
    }

    #[test]
    fn test_trend_invalid_days() {
        let result = CapacityCommandBuilder::build_capacity_trend_command(Some("cpu"), Some(500));
        assert!(result.is_err());
    }

    #[test]
    fn test_trend_fallback_when_sar_unavailable() {
        let cmd = CapacityCommandBuilder::build_capacity_trend_command(None, None).unwrap();
        assert!(cmd.contains("sar not available"));
        assert!(cmd.contains("current snapshot"));
    }

    // ── build_capacity_predict_command ────────────────────────────

    #[test]
    fn test_predict_cpu() {
        let cmd = CapacityCommandBuilder::build_capacity_predict_command("cpu").unwrap();
        assert!(cmd.contains("Prediction"));
        assert!(cmd.contains("-u"));
        assert!(cmd.contains("nproc"));
    }

    #[test]
    fn test_predict_memory() {
        let cmd = CapacityCommandBuilder::build_capacity_predict_command("memory").unwrap();
        assert!(cmd.contains("-r"));
    }

    #[test]
    fn test_predict_disk() {
        let cmd = CapacityCommandBuilder::build_capacity_predict_command("disk").unwrap();
        assert!(cmd.contains("-d"));
        assert!(cmd.contains("du -sh"));
    }

    #[test]
    fn test_predict_all() {
        let cmd = CapacityCommandBuilder::build_capacity_predict_command("all").unwrap();
        assert!(cmd.contains("-u -r -d"));
    }

    #[test]
    fn test_predict_invalid_resource() {
        let result = CapacityCommandBuilder::build_capacity_predict_command("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_predict_contains_growth_indicators() {
        let cmd = CapacityCommandBuilder::build_capacity_predict_command("cpu").unwrap();
        assert!(cmd.contains("Growth Indicators"));
    }
}
