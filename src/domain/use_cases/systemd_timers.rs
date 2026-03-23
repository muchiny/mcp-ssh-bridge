//! Systemd Timers Command Builder
//!
//! Builds systemctl commands for managing systemd timers.

use crate::config::ShellType;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds systemd timer management commands.
pub struct TimerCommandBuilder;

impl TimerCommandBuilder {
    /// Build a command to list timers.
    #[must_use]
    pub fn build_list_command(all: bool) -> String {
        if all {
            "systemctl list-timers --all --no-pager".to_string()
        } else {
            "systemctl list-timers --no-pager".to_string()
        }
    }

    /// Build a command to show timer info.
    #[must_use]
    pub fn build_info_command(timer: &str) -> String {
        let escaped = shell_escape(timer);
        format!("systemctl show {escaped} --no-pager && systemctl status {escaped} --no-pager -l")
    }

    /// Build a command to enable a timer.
    #[must_use]
    pub fn build_enable_command(timer: &str, now: bool) -> String {
        let escaped = shell_escape(timer);
        if now {
            format!("systemctl enable --now {escaped}")
        } else {
            format!("systemctl enable {escaped}")
        }
    }

    /// Build a command to disable a timer.
    #[must_use]
    pub fn build_disable_command(timer: &str, now: bool) -> String {
        let escaped = shell_escape(timer);
        if now {
            format!("systemctl disable --now {escaped}")
        } else {
            format!("systemctl disable {escaped}")
        }
    }

    /// Build a command to manually trigger a timer's service.
    #[must_use]
    pub fn build_trigger_command(timer: &str) -> String {
        // Timers trigger a service with the same name (minus .timer suffix)
        let service = if let Some(base) = std::path::Path::new(timer)
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("timer"))
            .then(|| timer.strip_suffix(".timer").unwrap_or(timer))
        {
            base
        } else {
            timer
        };
        let escaped = shell_escape(service);
        format!("systemctl start {escaped}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_active() {
        let cmd = TimerCommandBuilder::build_list_command(false);
        assert!(cmd.contains("list-timers"));
        assert!(!cmd.contains("--all"));
    }

    #[test]
    fn test_list_all() {
        let cmd = TimerCommandBuilder::build_list_command(true);
        assert!(cmd.contains("--all"));
    }

    #[test]
    fn test_info() {
        let cmd = TimerCommandBuilder::build_info_command("logrotate.timer");
        assert!(cmd.contains("systemctl show"));
        assert!(cmd.contains("systemctl status"));
    }

    #[test]
    fn test_enable() {
        let cmd = TimerCommandBuilder::build_enable_command("backup.timer", true);
        assert!(cmd.contains("enable --now"));
    }

    #[test]
    fn test_disable() {
        let cmd = TimerCommandBuilder::build_disable_command("backup.timer", false);
        assert!(cmd.contains("disable"));
        assert!(!cmd.contains("--now"));
    }

    #[test]
    fn test_trigger() {
        let cmd = TimerCommandBuilder::build_trigger_command("backup.timer");
        assert!(cmd.contains("systemctl start"));
        assert!(cmd.contains("backup"));
        assert!(!cmd.contains(".timer"));
    }

    #[test]
    fn test_trigger_no_suffix() {
        let cmd = TimerCommandBuilder::build_trigger_command("backup.service");
        assert!(cmd.contains("backup.service"));
    }
}
