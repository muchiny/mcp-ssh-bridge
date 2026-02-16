//! Backup Verify Prompt Handler
//!
//! Provides a backup verification prompt for a remote host.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::Result;
use crate::mcp::protocol::{PromptArgument, PromptMessage};
use crate::ports::{PromptHandler, ToolContext};

/// Backup verification prompt
pub struct BackupVerifyPrompt;

#[async_trait]
impl PromptHandler for BackupVerifyPrompt {
    fn name(&self) -> &'static str {
        "backup-verify"
    }

    fn description(&self) -> &'static str {
        "Verify backups: list recent backups, check dates, and verify disk space"
    }

    fn arguments(&self) -> Vec<PromptArgument> {
        vec![
            PromptArgument {
                name: "host".to_string(),
                description: "SSH host alias to check backups on".to_string(),
                required: true,
            },
            PromptArgument {
                name: "path".to_string(),
                description: "Backup directory path (default: /var/backups)".to_string(),
                required: false,
            },
        ]
    }

    async fn get(
        &self,
        args: HashMap<String, String>,
        _ctx: &ToolContext,
    ) -> Result<Vec<PromptMessage>> {
        let host = args.get("host").map_or("the target host", String::as_str);
        let path = args.get("path").map_or("/var/backups", String::as_str);

        Ok(vec![PromptMessage::user(format!(
            r#"Please verify the backup status on host '{host}':

1. **List backups** — Use `ssh_backup_list` to see available backups, or use `ssh_ls` on `{path}` with `long: true` and `sort_by: "time"` to list backup files sorted by date.

2. **Check freshness** — Verify that the most recent backup is less than 24 hours old. Use `ssh_exec` with `find {path} -maxdepth 1 -type f -mtime -1 | wc -l` to count files modified in the last day.

3. **Backup sizes** — Check that backup sizes are reasonable (not 0 bytes, not unexpectedly small compared to previous backups). Use `ssh_exec` with `du -sh {path}/*` for a summary.

4. **Disk space** — Use `ssh_exec` with `df -h {path}` to verify sufficient free space remains for future backups.

5. **Backup integrity** — If backups are compressed archives, spot-check the most recent one with `ssh_exec` using `gzip -t` or `tar -tzf` to verify it is not corrupted.

After collecting all data, provide:
- Backup health status (healthy / warning / critical)
- Most recent backup timestamp and whether it is within the expected schedule
- Any missing or unusually sized backups
- Disk space projections (days until full at current backup rate)
- Recommendations for backup improvements"#
        ))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_name() {
        let prompt = BackupVerifyPrompt;
        assert_eq!(prompt.name(), "backup-verify");
    }

    #[test]
    fn test_description() {
        let prompt = BackupVerifyPrompt;
        assert!(prompt.description().contains("backup"));
    }

    #[test]
    fn test_arguments() {
        let prompt = BackupVerifyPrompt;
        let args = prompt.arguments();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].name, "host");
        assert!(args[0].required);
        assert_eq!(args[1].name, "path");
        assert!(!args[1].required);
    }

    #[tokio::test]
    async fn test_prompt_with_host() {
        let prompt = BackupVerifyPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "backup-server".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].role, "user");
        assert!(messages[0].content.text.contains("backup-server"));
        assert!(messages[0].content.text.contains("/var/backups"));
    }

    #[tokio::test]
    async fn test_prompt_with_custom_path() {
        let prompt = BackupVerifyPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "server1".to_string());
        args.insert("path".to_string(), "/mnt/backups".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert!(messages[0].content.text.contains("/mnt/backups"));
        assert!(!messages[0].content.text.contains("/var/backups"));
    }

    #[tokio::test]
    async fn test_prompt_without_host() {
        let prompt = BackupVerifyPrompt;
        let args = HashMap::new();

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert!(messages[0].content.text.contains("the target host"));
    }
}
