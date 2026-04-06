//! AWX Command Builder
//!
//! Builds `curl` commands for AWX REST API calls, relayed through SSH
//! to reach AWX instances in air-gapped environments.

use std::fmt::Write;

use crate::config::ShellType;
use crate::error::{BridgeError, Result};

fn shell_escape(s: &str) -> String {
    super::shell::escape(s, ShellType::Posix)
}

/// HTTP methods for AWX API calls.
#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Post,
    Delete,
}

impl HttpMethod {
    /// Returns the curl flag for this method.
    fn as_curl_flag(self) -> &'static str {
        match self {
            Self::Get => "-X GET",
            Self::Post => "-X POST",
            Self::Delete => "-X DELETE",
        }
    }
}

/// Builds curl commands for AWX REST API calls.
pub struct AwxCommandBuilder;

impl AwxCommandBuilder {
    /// Build a curl command for an AWX API call.
    ///
    /// The token is included in the Authorization header but masked in
    /// audit logs via the security sanitizer.
    ///
    /// # Arguments
    ///
    /// * `url` - Base URL of AWX (e.g., `https://awx.internal`)
    /// * `token` - AWX API `OAuth2` token
    /// * `endpoint` - API endpoint (e.g., `/api/v2/jobs/123/`)
    /// * `method` - HTTP method
    /// * `body` - Optional JSON body for POST requests
    /// * `verify_ssl` - Whether to verify SSL certificates
    /// * `query_params` - Query string parameters
    /// * `timeout` - Request timeout in seconds
    #[must_use]
    #[expect(clippy::too_many_arguments)]
    pub fn build_api_call(
        url: &str,
        token: &str,
        endpoint: &str,
        method: HttpMethod,
        body: Option<&str>,
        verify_ssl: bool,
        query_params: &[(&str, &str)],
        timeout: u32,
    ) -> String {
        let mut cmd = String::from("curl -s");

        // Method
        let _ = write!(cmd, " {}", method.as_curl_flag());

        // SSL verification
        if !verify_ssl {
            cmd.push_str(" -k");
        }

        // Timeout
        let _ = write!(cmd, " --max-time {timeout}");

        // Auth header
        let _ = write!(cmd, " -H 'Authorization: Bearer {}'", shell_escape(token));

        // Content-Type for POST
        if body.is_some() {
            cmd.push_str(" -H 'Content-Type: application/json'");
        }

        // Body
        if let Some(b) = body {
            let _ = write!(cmd, " -d {}", shell_escape(b));
        }

        // Build full URL with query params
        let mut full_url = format!("{}{}", url.trim_end_matches('/'), endpoint);
        if !query_params.is_empty() {
            full_url.push('?');
            for (i, (key, value)) in query_params.iter().enumerate() {
                if i > 0 {
                    full_url.push('&');
                }
                let _ = write!(full_url, "{key}={value}");
            }
        }

        let _ = write!(cmd, " {}", shell_escape(&full_url));

        cmd
    }

    /// Validate an AWX API endpoint path.
    ///
    /// Rejects paths with `..` (directory traversal) and paths not
    /// starting with `/api/`.
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the path is invalid.
    pub fn validate_endpoint(endpoint: &str) -> Result<()> {
        if endpoint.contains("..") {
            return Err(BridgeError::CommandDenied {
                reason: "Path traversal not allowed in API endpoint".to_string(),
            });
        }
        if !endpoint.starts_with("/api/") {
            return Err(BridgeError::CommandDenied {
                reason: "AWX endpoint must start with /api/".to_string(),
            });
        }
        Ok(())
    }

    /// Validate a template/job ID (must be a positive integer).
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::CommandDenied` if the ID is not a valid
    /// positive integer.
    pub fn validate_id(id: u64) -> Result<()> {
        if id == 0 {
            return Err(BridgeError::CommandDenied {
                reason: "ID must be a positive integer".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_api_call_get() {
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "mytoken123",
            "/api/v2/ping/",
            HttpMethod::Get,
            None,
            true,
            &[],
            30,
        );
        assert!(cmd.contains("curl -s"));
        assert!(cmd.contains("-X GET"));
        assert!(cmd.contains("Authorization: Bearer"));
        assert!(cmd.contains("mytoken123"));
        assert!(cmd.contains("https://awx.internal/api/v2/ping/"));
        assert!(cmd.contains("--max-time 30"));
        assert!(!cmd.contains("-k"));
    }

    #[test]
    fn test_build_api_call_post_with_body() {
        let body = r#"{"extra_vars": {"env": "prod"}}"#;
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "tok",
            "/api/v2/job_templates/5/launch/",
            HttpMethod::Post,
            Some(body),
            false,
            &[],
            60,
        );
        assert!(cmd.contains("-X POST"));
        assert!(cmd.contains("-k"));
        assert!(cmd.contains("Content-Type: application/json"));
        assert!(cmd.contains("-d "));
        assert!(cmd.contains("extra_vars"));
    }

    #[test]
    fn test_build_api_call_with_query_params() {
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "tok",
            "/api/v2/jobs/42/job_events/",
            HttpMethod::Get,
            None,
            true,
            &[("page_size", "20"), ("event", "runner_on_failed")],
            30,
        );
        assert!(cmd.contains("page_size=20"));
        assert!(cmd.contains("event=runner_on_failed"));
        assert!(cmd.contains('?'));
        assert!(cmd.contains('&'));
    }

    #[test]
    fn test_build_api_call_no_trailing_slash_on_url() {
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal/",
            "tok",
            "/api/v2/ping/",
            HttpMethod::Get,
            None,
            true,
            &[],
            30,
        );
        // Should not double the slash
        assert!(cmd.contains("https://awx.internal/api/v2/ping/"));
        assert!(!cmd.contains("https://awx.internal//api/"));
    }

    #[test]
    fn test_build_api_call_delete() {
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "tok",
            "/api/v2/jobs/99/cancel/",
            HttpMethod::Delete,
            None,
            true,
            &[],
            30,
        );
        assert!(cmd.contains("-X DELETE"));
    }

    #[test]
    fn test_token_is_shell_escaped() {
        let cmd = AwxCommandBuilder::build_api_call(
            "https://awx.internal",
            "tok'en$(whoami)",
            "/api/v2/ping/",
            HttpMethod::Get,
            None,
            true,
            &[],
            30,
        );
        // Token with single quote should be escaped (quote-break-quote pattern)
        assert!(cmd.contains("tok'\\''en"));
        // $(whoami) is safely inside single quotes — not interpreted by shell
        assert!(cmd.contains("$(whoami)"));
    }

    // ============== Validation Tests ==============

    #[test]
    fn test_validate_endpoint_ok() {
        assert!(AwxCommandBuilder::validate_endpoint("/api/v2/ping/").is_ok());
        assert!(AwxCommandBuilder::validate_endpoint("/api/v2/jobs/123/").is_ok());
    }

    #[test]
    fn test_validate_endpoint_traversal() {
        let result = AwxCommandBuilder::validate_endpoint("/api/../../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_endpoint_wrong_prefix() {
        let result = AwxCommandBuilder::validate_endpoint("/etc/passwd");
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("/api/"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_validate_id_ok() {
        assert!(AwxCommandBuilder::validate_id(1).is_ok());
        assert!(AwxCommandBuilder::validate_id(42).is_ok());
    }

    #[test]
    fn test_validate_id_zero() {
        assert!(AwxCommandBuilder::validate_id(0).is_err());
    }
}
