//! Advanced File Operations Command Builder
//!
//! Builds commands for file diff, patch, and template operations.

use crate::config::ShellType;

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Builds advanced file operation commands.
pub struct FileAdvancedCommandBuilder;

impl FileAdvancedCommandBuilder {
    /// Build a diff command between two files on the same host.
    #[must_use]
    pub fn build_diff_command(file1: &str, file2: &str, context_lines: u32) -> String {
        let f1 = shell_escape(file1);
        let f2 = shell_escape(file2);
        format!("diff -u --color=never -U {context_lines} {f1} {f2} || true")
    }

    /// Build a patch apply command (with dry-run support).
    #[must_use]
    pub fn build_patch_command(target_file: &str, patch_content: &str, dry_run: bool) -> String {
        let escaped_target = shell_escape(target_file);
        let escaped_patch = shell_escape(patch_content);
        let dry_flag = if dry_run { " --dry-run" } else { "" };
        format!(
            "printf {escaped_patch} | patch{dry_flag} -p0 {escaped_target}"
        )
    }

    /// Build a template rendering command using envsubst.
    #[must_use]
    pub fn build_template_command(
        template_path: &str,
        output_path: &str,
        variables: &[(String, String)],
    ) -> String {
        let escaped_template = shell_escape(template_path);
        let escaped_output = shell_escape(output_path);

        // Build env var exports
        let exports: Vec<String> = variables
            .iter()
            .map(|(k, v)| {
                let escaped_v = shell_escape(v);
                format!("export {k}={escaped_v}")
            })
            .collect();

        let export_str = if exports.is_empty() {
            String::new()
        } else {
            format!("{} && ", exports.join(" && "))
        };

        format!(
            "{export_str}envsubst < {escaped_template} > {escaped_output} && echo 'Template rendered to {output_path}'"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_command() {
        let cmd = FileAdvancedCommandBuilder::build_diff_command("/etc/nginx/a.conf", "/etc/nginx/b.conf", 3);
        assert!(cmd.contains("diff -u"));
        assert!(cmd.contains("-U 3"));
        assert!(cmd.contains("/etc/nginx/a.conf"));
    }

    #[test]
    fn test_patch_command_dry_run() {
        let cmd = FileAdvancedCommandBuilder::build_patch_command("/etc/config", "--- a\n+++ b\n", true);
        assert!(cmd.contains("--dry-run"));
        assert!(cmd.contains("patch"));
    }

    #[test]
    fn test_patch_command_apply() {
        let cmd = FileAdvancedCommandBuilder::build_patch_command("/etc/config", "diff", false);
        assert!(!cmd.contains("--dry-run"));
    }

    #[test]
    fn test_template_command() {
        let vars = vec![
            ("SERVER_NAME".to_string(), "example.com".to_string()),
            ("PORT".to_string(), "8080".to_string()),
        ];
        let cmd = FileAdvancedCommandBuilder::build_template_command(
            "/etc/nginx/template.conf",
            "/etc/nginx/site.conf",
            &vars,
        );
        assert!(cmd.contains("envsubst"));
        assert!(cmd.contains("SERVER_NAME"));
        assert!(cmd.contains("export"));
    }

    #[test]
    fn test_template_command_no_vars() {
        let cmd = FileAdvancedCommandBuilder::build_template_command(
            "/etc/template",
            "/etc/output",
            &[],
        );
        assert!(cmd.contains("envsubst"));
        assert!(!cmd.contains("export"));
    }
}
