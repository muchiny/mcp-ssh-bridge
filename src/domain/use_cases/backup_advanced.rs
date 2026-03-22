//! Backup Advanced Command Builder
//!
//! Builds snapshot, verification, and scheduled backup commands for
//! remote execution via SSH.

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Validate backup paths for safety.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if paths are empty or contain
/// path traversal patterns.
pub fn validate_paths(paths: &str) -> Result<()> {
    if paths.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Backup paths must not be empty".to_string(),
        });
    }
    if paths.contains("..") {
        return Err(BridgeError::CommandDenied {
            reason: "Backup paths must not contain '..' (path traversal)".to_string(),
        });
    }
    if paths.len() > 4096 {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Backup paths too long: {} chars (max 4096)",
                paths.len()
            ),
        });
    }
    Ok(())
}

/// Validate an archive path for safety.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the archive path is empty,
/// contains path traversal, or does not end with a tar extension.
pub fn validate_archive(archive: &str) -> Result<()> {
    if archive.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Archive path must not be empty".to_string(),
        });
    }
    if archive.contains("..") {
        return Err(BridgeError::CommandDenied {
            reason: "Archive path must not contain '..' (path traversal)".to_string(),
        });
    }
    if !archive.contains(".tar") {
        return Err(BridgeError::CommandDenied {
            reason: "Archive path must contain '.tar' extension".to_string(),
        });
    }
    Ok(())
}

/// Validate a cron expression for scheduled backups.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the expression is invalid.
pub fn validate_cron_expr(cron_expr: &str) -> Result<()> {
    let fields: Vec<&str> = cron_expr.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid cron expression: expected 5 fields, got {}",
                fields.len()
            ),
        });
    }
    for (i, field) in fields.iter().enumerate() {
        if !field
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '*' | '/' | '-' | ','))
        {
            return Err(BridgeError::CommandDenied {
                reason: format!(
                    "Invalid cron field {}: '{}' contains invalid characters",
                    i + 1,
                    field
                ),
            });
        }
    }
    Ok(())
}

/// Builds advanced backup commands for remote execution.
pub struct BackupAdvancedCommandBuilder;

impl BackupAdvancedCommandBuilder {
    /// Build a command to create a snapshot archive of specified paths.
    ///
    /// Creates a timestamped tar.gz archive in `/tmp/`.
    ///
    /// # Errors
    ///
    /// Returns an error if paths are invalid.
    pub fn build_snapshot_command(
        paths: &str,
        label: Option<&str>,
    ) -> Result<String> {
        validate_paths(paths)?;

        let label_part = label.unwrap_or("snapshot");
        let escaped_label = shell_escape(label_part);
        let escaped_paths = shell_escape(paths);

        Ok(format!(
            "TIMESTAMP=$(date +%Y%m%d_%H%M%S) && \
             ARCHIVE=\"/tmp/snapshot_$(echo {escaped_label} | tr -cd 'a-zA-Z0-9_-')_${{TIMESTAMP}}.tar.gz\" && \
             tar czf \"$ARCHIVE\" {escaped_paths} 2>/dev/null && \
             echo \"Snapshot created: $ARCHIVE\" && \
             ls -lh \"$ARCHIVE\" && \
             sha256sum \"$ARCHIVE\""
        ))
    }

    /// Build a command to verify a backup archive.
    ///
    /// Tests archive integrity and prints a checksum.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive path is invalid.
    pub fn build_verify_command(archive: &str) -> Result<String> {
        validate_archive(archive)?;

        let escaped = shell_escape(archive);

        Ok(format!(
            "tar tzf {escaped} >/dev/null 2>&1 && \
             echo 'Archive OK' && \
             sha256sum {escaped} && \
             echo '--- Archive Contents ---' && \
             tar tzf {escaped} | head -20 && \
             echo '--- Archive Size ---' && \
             ls -lh {escaped}"
        ))
    }

    /// Build a command to schedule a periodic backup via cron.
    ///
    /// # Errors
    ///
    /// Returns an error if the cron expression or paths are invalid.
    pub fn build_schedule_command(
        cron_expr: &str,
        paths: &str,
        dest: &str,
    ) -> Result<String> {
        validate_cron_expr(cron_expr)?;
        validate_paths(paths)?;

        if dest.is_empty() {
            return Err(BridgeError::CommandDenied {
                reason: "Backup destination must not be empty".to_string(),
            });
        }

        let escaped_paths = shell_escape(paths);
        let escaped_dest = shell_escape(dest);
        let backup_cmd = format!(
            "tar czf {escaped_dest}/backup_$(date +\\%Y\\%m\\%d_\\%H\\%M\\%S).tar.gz {escaped_paths}"
        );

        let cron_line = format!("{cron_expr} {backup_cmd}");
        let escaped_cron_line = shell_escape(&cron_line);

        Ok(format!(
            "(crontab -l 2>/dev/null; echo {escaped_cron_line}) | crontab - && \
             echo 'Backup schedule added successfully' && \
             crontab -l | tail -3"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_paths ────────────────────────────────────────

    #[test]
    fn test_validate_paths_valid() {
        assert!(validate_paths("/var/data").is_ok());
        assert!(validate_paths("/etc/config /var/log").is_ok());
    }

    #[test]
    fn test_validate_paths_empty() {
        let err = validate_paths("").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("empty"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_paths_traversal() {
        assert!(validate_paths("/var/../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_paths_too_long() {
        let long = "/a".repeat(2049);
        assert!(validate_paths(&long).is_err());
    }

    // ── validate_archive ──────────────────────────────────────

    #[test]
    fn test_validate_archive_valid() {
        assert!(validate_archive("/tmp/backup.tar.gz").is_ok());
        assert!(validate_archive("/backups/data.tar").is_ok());
        assert!(validate_archive("/tmp/snap.tar.xz").is_ok());
    }

    #[test]
    fn test_validate_archive_empty() {
        assert!(validate_archive("").is_err());
    }

    #[test]
    fn test_validate_archive_traversal() {
        assert!(validate_archive("/tmp/../etc/backup.tar.gz").is_err());
    }

    #[test]
    fn test_validate_archive_no_tar() {
        let err = validate_archive("/tmp/backup.zip").unwrap_err();
        match err {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains(".tar"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ── validate_cron_expr ────────────────────────────────────

    #[test]
    fn test_validate_cron_expr_valid() {
        assert!(validate_cron_expr("0 2 * * *").is_ok());
        assert!(validate_cron_expr("*/15 * * * *").is_ok());
        assert!(validate_cron_expr("0 0 1 1 *").is_ok());
    }

    #[test]
    fn test_validate_cron_expr_wrong_fields() {
        assert!(validate_cron_expr("* * *").is_err());
        assert!(validate_cron_expr("* * * * * *").is_err());
    }

    #[test]
    fn test_validate_cron_expr_invalid_chars() {
        assert!(validate_cron_expr("0 * * * ; rm -rf /").is_err());
    }

    // ── build_snapshot_command ─────────────────────────────────

    #[test]
    fn test_snapshot_defaults() {
        let cmd = BackupAdvancedCommandBuilder::build_snapshot_command(
            "/var/data",
            None,
        )
        .unwrap();
        assert!(cmd.contains("tar czf"));
        assert!(cmd.contains("snapshot"));
        assert!(cmd.contains("sha256sum"));
        assert!(cmd.contains("/var/data"));
    }

    #[test]
    fn test_snapshot_with_label() {
        let cmd = BackupAdvancedCommandBuilder::build_snapshot_command(
            "/var/data",
            Some("mybackup"),
        )
        .unwrap();
        assert!(cmd.contains("mybackup"));
    }

    #[test]
    fn test_snapshot_invalid_paths() {
        let result = BackupAdvancedCommandBuilder::build_snapshot_command("", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_snapshot_shell_injection() {
        let cmd = BackupAdvancedCommandBuilder::build_snapshot_command(
            "/var/data",
            Some("'; rm -rf /; echo '"),
        )
        .unwrap();
        assert!(cmd.contains("'\\''"));
    }

    // ── build_verify_command ──────────────────────────────────

    #[test]
    fn test_verify_valid() {
        let cmd = BackupAdvancedCommandBuilder::build_verify_command(
            "/tmp/backup.tar.gz",
        )
        .unwrap();
        assert!(cmd.contains("tar tzf"));
        assert!(cmd.contains("Archive OK"));
        assert!(cmd.contains("sha256sum"));
        assert!(cmd.contains("Archive Contents"));
    }

    #[test]
    fn test_verify_invalid_archive() {
        assert!(BackupAdvancedCommandBuilder::build_verify_command("").is_err());
        assert!(BackupAdvancedCommandBuilder::build_verify_command("/tmp/file.zip").is_err());
    }

    #[test]
    fn test_verify_shell_injection() {
        let cmd = BackupAdvancedCommandBuilder::build_verify_command(
            "/tmp/'; rm -rf /.tar.gz",
        )
        .unwrap();
        assert!(cmd.contains("'\\''"));
    }

    // ── build_schedule_command ─────────────────────────────────

    #[test]
    fn test_schedule_valid() {
        let cmd = BackupAdvancedCommandBuilder::build_schedule_command(
            "0 2 * * *",
            "/var/data",
            "/backups",
        )
        .unwrap();
        assert!(cmd.contains("crontab"));
        assert!(cmd.contains("0 2 * * *"));
        assert!(cmd.contains("/var/data"));
        assert!(cmd.contains("/backups"));
        assert!(cmd.contains("schedule added"));
    }

    #[test]
    fn test_schedule_invalid_cron() {
        let result = BackupAdvancedCommandBuilder::build_schedule_command(
            "bad",
            "/var/data",
            "/backups",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_schedule_invalid_paths() {
        let result = BackupAdvancedCommandBuilder::build_schedule_command(
            "0 * * * *",
            "",
            "/backups",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_schedule_empty_dest() {
        let result = BackupAdvancedCommandBuilder::build_schedule_command(
            "0 * * * *",
            "/var/data",
            "",
        );
        assert!(result.is_err());
    }
}
