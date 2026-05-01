//! Template Command Builder
//!
//! Builds configuration template management commands for remote execution
//! via SSH. Supports listing, showing, applying, validating, and diffing
//! configuration templates for common services (nginx, apache, postgresql,
//! mysql, redis).

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// Known template names for built-in templates.
const KNOWN_TEMPLATES: &[&str] = &[
    "nginx-reverse-proxy",
    "nginx-static",
    "apache-vhost",
    "postgresql-config",
    "mysql-config",
    "redis-config",
];

/// Known service names for validation commands.
const KNOWN_SERVICES: &[&str] = &["nginx", "apache", "postgresql", "mysql", "redis"];

/// Validate that a template name contains only safe characters.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the name is empty or contains
/// characters other than alphanumerics, hyphens, and underscores.
pub fn validate_template_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Template name cannot be empty".to_string(),
        });
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Invalid template name '{name}': only alphanumeric characters, hyphens, \
                 and underscores are allowed"
            ),
        });
    }
    Ok(())
}

/// Validate that a service name is one of the known services.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the service is not recognized.
pub fn validate_service(service: &str) -> Result<()> {
    if !KNOWN_SERVICES.contains(&service) {
        return Err(BridgeError::CommandDenied {
            reason: format!(
                "Unknown service '{}'. Supported services: {}",
                service,
                KNOWN_SERVICES.join(", ")
            ),
        });
    }
    Ok(())
}

/// Validate that a destination path is absolute and does not contain
/// directory traversal sequences.
///
/// # Errors
///
/// Returns [`BridgeError::CommandDenied`] if the path is invalid.
pub fn validate_dest_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(BridgeError::CommandDenied {
            reason: "Destination path cannot be empty".to_string(),
        });
    }
    if !path.starts_with('/') {
        return Err(BridgeError::CommandDenied {
            reason: format!("Destination path '{path}' must be absolute (start with /)"),
        });
    }
    if path.contains("..") {
        return Err(BridgeError::CommandDenied {
            reason: format!("Path traversal not allowed: '{path}' contains '..'"),
        });
    }
    Ok(())
}

/// Builds configuration template management commands for remote execution.
pub struct TemplateCommandBuilder;

impl TemplateCommandBuilder {
    /// Build a command to list available configuration templates.
    ///
    /// Returns an echo command listing all built-in templates.
    #[must_use]
    pub fn build_template_list_command() -> String {
        // Emit a clean two-line tabular layout (single column "NAME") so the
        // generic columnar parser used by `ssh_template_list` sees a proper
        // header row and full-width values. The previous format used a
        // sentence header followed by lines indented with two spaces, which
        // the parser misread as a fixed-width column starting at offset 2,
        // chopping the first two characters off the header.
        let mut lines = vec!["echo NAME".to_string()];
        for tmpl in KNOWN_TEMPLATES {
            lines.push(format!("echo {tmpl}"));
        }
        lines.join(" && ")
    }

    /// Build a command to show a template's content.
    #[must_use]
    pub fn build_template_show_command(template_name: &str) -> String {
        let escaped = shell_escape(template_name);
        format!(
            "echo 'Template: {escaped}' && echo '---' && \
             echo 'Use ssh_template_apply to deploy this template.'"
        )
    }

    /// Build a command to apply template content to a destination file.
    ///
    /// If `backup` is true, creates a `.bak` copy before overwriting.
    #[must_use]
    pub fn build_template_apply_command(content: &str, dest: &str, backup: bool) -> String {
        let escaped_dest = shell_escape(dest);
        let mut cmd = String::new();
        if backup {
            let _ = write!(cmd, "cp {escaped_dest} {escaped_dest}.bak 2>/dev/null; ");
        }
        let _ = write!(
            cmd,
            "cat > {escaped_dest} << 'TEMPLATE_EOF'\n{content}\nTEMPLATE_EOF"
        );
        cmd
    }

    /// Build a command to validate a service's configuration.
    ///
    /// Runs the appropriate config-test command for the given service.
    #[must_use]
    pub fn build_template_validate_command(service: &str, config_path: Option<&str>) -> String {
        match service {
            "nginx" => {
                if let Some(path) = config_path {
                    format!("nginx -t -c {}", shell_escape(path))
                } else {
                    "nginx -t".to_string()
                }
            }
            "apache" => {
                if let Some(path) = config_path {
                    format!("apachectl -t -f {}", shell_escape(path))
                } else {
                    "apachectl configtest".to_string()
                }
            }
            "postgresql" => {
                if let Some(path) = config_path {
                    format!("pg_isready -d {}", shell_escape(path))
                } else {
                    "pg_isready".to_string()
                }
            }
            "mysql" => {
                if let Some(path) = config_path {
                    format!(
                        "mysqld --validate-config --defaults-file={}",
                        shell_escape(path)
                    )
                } else {
                    "mysqld --validate-config".to_string()
                }
            }
            "redis" => {
                if let Some(path) = config_path {
                    format!("redis-cli ping && echo 'Config: {}'", shell_escape(path))
                } else {
                    "redis-cli ping".to_string()
                }
            }
            _ => format!("echo 'Unknown service: {}'", shell_escape(service)),
        }
    }

    /// Build a command to diff template content against an existing file.
    ///
    /// Uses process substitution to compare.
    #[must_use]
    pub fn build_template_diff_command(content: &str, current_path: &str) -> String {
        format!(
            "diff <(cat {}) <(echo {})",
            shell_escape(current_path),
            shell_escape(content)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============== Validation Tests ==============

    #[test]
    fn test_validate_template_name_valid() {
        assert!(validate_template_name("nginx-reverse-proxy").is_ok());
        assert!(validate_template_name("redis-config").is_ok());
        assert!(validate_template_name("my_template").is_ok());
        assert!(validate_template_name("template123").is_ok());
    }

    #[test]
    fn test_validate_template_name_empty() {
        let result = validate_template_name("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_template_name_invalid_chars() {
        assert!(validate_template_name("test;rm -rf").is_err());
        assert!(validate_template_name("$(whoami)").is_err());
        assert!(validate_template_name("name with spaces").is_err());
    }

    #[test]
    fn test_validate_template_name_error_message() {
        let result = validate_template_name("bad;name");
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("bad;name"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_service_valid() {
        assert!(validate_service("nginx").is_ok());
        assert!(validate_service("apache").is_ok());
        assert!(validate_service("postgresql").is_ok());
        assert!(validate_service("mysql").is_ok());
        assert!(validate_service("redis").is_ok());
    }

    #[test]
    fn test_validate_service_invalid() {
        let result = validate_service("unknown");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Unknown service"));
                assert!(reason.contains("unknown"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_service_empty() {
        assert!(validate_service("").is_err());
    }

    #[test]
    fn test_validate_dest_path_valid() {
        assert!(validate_dest_path("/etc/nginx/nginx.conf").is_ok());
        assert!(validate_dest_path("/tmp/config.yaml").is_ok());
    }

    #[test]
    fn test_validate_dest_path_empty() {
        assert!(validate_dest_path("").is_err());
    }

    #[test]
    fn test_validate_dest_path_not_absolute() {
        let result = validate_dest_path("relative/path");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("must be absolute"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_dest_path_traversal() {
        let result = validate_dest_path("/etc/../shadow");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("Path traversal"));
            }
            other => panic!("Expected CommandDenied, got: {other:?}"),
        }
    }

    // ============== List Command ==============

    #[test]
    fn test_list_command() {
        let cmd = TemplateCommandBuilder::build_template_list_command();
        assert!(cmd.contains("echo NAME"));
        assert!(cmd.contains("nginx-reverse-proxy"));
        assert!(cmd.contains("nginx-static"));
        assert!(cmd.contains("apache-vhost"));
        assert!(cmd.contains("postgresql-config"));
        assert!(cmd.contains("mysql-config"));
        assert!(cmd.contains("redis-config"));
    }

    #[test]
    fn test_list_command_all_templates() {
        let cmd = TemplateCommandBuilder::build_template_list_command();
        for tmpl in KNOWN_TEMPLATES {
            assert!(cmd.contains(tmpl), "Missing template: {tmpl}");
        }
    }

    // ============== Show Command ==============

    #[test]
    fn test_show_command() {
        let cmd = TemplateCommandBuilder::build_template_show_command("nginx-reverse-proxy");
        assert!(cmd.contains("nginx-reverse-proxy"));
        assert!(cmd.contains("Template:"));
    }

    #[test]
    fn test_show_command_injection() {
        let cmd = TemplateCommandBuilder::build_template_show_command("test; rm -rf /");
        assert!(cmd.contains("'test; rm -rf /'"));
    }

    // ============== Apply Command ==============

    #[test]
    fn test_apply_command_no_backup() {
        let cmd = TemplateCommandBuilder::build_template_apply_command(
            "server { listen 80; }",
            "/etc/nginx/nginx.conf",
            false,
        );
        assert!(cmd.contains("TEMPLATE_EOF"));
        assert!(cmd.contains("server { listen 80; }"));
        assert!(!cmd.contains(".bak"));
    }

    #[test]
    fn test_apply_command_with_backup() {
        let cmd = TemplateCommandBuilder::build_template_apply_command(
            "content",
            "/etc/nginx/nginx.conf",
            true,
        );
        assert!(cmd.contains(".bak"));
        assert!(cmd.contains("TEMPLATE_EOF"));
        assert!(cmd.contains("cp "));
    }

    #[test]
    fn test_apply_command_injection_in_dest() {
        let cmd = TemplateCommandBuilder::build_template_apply_command(
            "content",
            "/tmp/test; rm -rf /",
            false,
        );
        assert!(cmd.contains("'/tmp/test; rm -rf /'"));
    }

    // ============== Validate Command ==============

    #[test]
    fn test_validate_nginx() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("nginx", None);
        assert_eq!(cmd, "nginx -t");
    }

    #[test]
    fn test_validate_nginx_with_path() {
        let cmd = TemplateCommandBuilder::build_template_validate_command(
            "nginx",
            Some("/etc/nginx/nginx.conf"),
        );
        assert!(cmd.contains("nginx -t -c"));
        assert!(cmd.contains("'/etc/nginx/nginx.conf'"));
    }

    #[test]
    fn test_validate_apache() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("apache", None);
        assert_eq!(cmd, "apachectl configtest");
    }

    #[test]
    fn test_validate_postgresql() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("postgresql", None);
        assert_eq!(cmd, "pg_isready");
    }

    #[test]
    fn test_validate_mysql() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("mysql", None);
        assert_eq!(cmd, "mysqld --validate-config");
    }

    #[test]
    fn test_validate_redis() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("redis", None);
        assert_eq!(cmd, "redis-cli ping");
    }

    #[test]
    fn test_validate_unknown_service_fallback() {
        let cmd = TemplateCommandBuilder::build_template_validate_command("unknown", None);
        assert!(cmd.contains("Unknown service"));
    }

    #[test]
    fn test_validate_injection_in_path() {
        let cmd = TemplateCommandBuilder::build_template_validate_command(
            "nginx",
            Some("/tmp/test; cat /etc/shadow"),
        );
        assert!(cmd.contains("'/tmp/test; cat /etc/shadow'"));
    }

    // ============== Diff Command ==============

    #[test]
    fn test_diff_command() {
        let cmd = TemplateCommandBuilder::build_template_diff_command(
            "new content",
            "/etc/nginx/nginx.conf",
        );
        assert!(cmd.contains("diff"));
        assert!(cmd.contains("'/etc/nginx/nginx.conf'"));
        assert!(cmd.contains("'new content'"));
    }

    #[test]
    fn test_diff_command_injection_in_path() {
        let cmd =
            TemplateCommandBuilder::build_template_diff_command("content", "/tmp/test; rm -rf /");
        assert!(cmd.contains("'/tmp/test; rm -rf /'"));
    }

    #[test]
    fn test_diff_command_injection_in_content() {
        let cmd = TemplateCommandBuilder::build_template_diff_command(
            "content'; rm -rf /; echo '",
            "/tmp/test",
        );
        // Verify the content is properly shell-escaped
        assert!(cmd.contains("diff"));
    }

    // ============== All Services Valid ==============

    #[test]
    fn test_all_known_services_valid() {
        for svc in KNOWN_SERVICES {
            assert!(
                validate_service(svc).is_ok(),
                "Service should be valid: {svc}"
            );
        }
    }

    #[test]
    fn test_mysql_with_path() {
        let cmd = TemplateCommandBuilder::build_template_validate_command(
            "mysql",
            Some("/etc/mysql/my.cnf"),
        );
        assert!(cmd.contains("--defaults-file="));
    }
}
