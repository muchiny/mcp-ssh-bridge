//! `WinRM` protocol adapter — Windows Remote Management
//!
//! Implements remote command execution on Windows hosts via the
//! WS-Management protocol (SOAP over HTTP/HTTPS, ports 5985/5986).
//!
//! Feature-gated behind `winrm`.

use std::time::{Duration, Instant};

use reqwest::Client;
use tracing::{debug, info};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// `WinRM` transport configuration for a host.
#[derive(Debug, Clone)]
pub struct WinRmConfig {
    /// HTTP or HTTPS endpoint (e.g., `https://192.168.1.200:5986/wsman`)
    pub endpoint: String,
    /// Use SSL (port 5986) or plain HTTP (port 5985)
    pub use_ssl: bool,
}

impl WinRmConfig {
    /// Derive `WinRM` endpoint from a standard `HostConfig`.
    #[must_use]
    pub fn from_host_config(host: &HostConfig) -> Self {
        let use_ssl = host.port != 5985;
        let scheme = if use_ssl { "https" } else { "http" };
        let port = if host.port == 22 {
            // Default SSH port means WinRM wasn't explicitly configured;
            // fall back to HTTPS 5986.
            5986
        } else {
            host.port
        };
        Self {
            endpoint: format!("{scheme}://{}:{port}/wsman", host.hostname),
            use_ssl,
        }
    }
}

/// An active `WinRM` connection (HTTP client + endpoint).
///
/// Unlike SSH, `WinRM` is stateless HTTP — each `exec()` sends a fresh
/// SOAP request. The "connection" is really just a configured HTTP client.
pub struct WinRmConnection {
    client: Client,
    config: WinRmConfig,
    host_name: String,
    user: String,
    password: String,
    failed: bool,
}

impl WinRmConnection {
    /// Create a new `WinRM` connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(host_name: &str, host_config: &HostConfig, _limits: &LimitsConfig) -> Result<Self> {
        let config = WinRmConfig::from_host_config(host_config);

        let password = match &host_config.auth {
            crate::config::AuthConfig::Password { password } => password.to_string(),
            _ => {
                return Err(BridgeError::Config(format!(
                    "WinRM host '{host_name}' requires password authentication"
                )));
            }
        };

        let client = Client::builder()
            .danger_accept_invalid_certs(!config.use_ssl)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| BridgeError::SshExec {
                reason: format!("WinRM HTTP client error: {e}"),
            })?;

        info!(host = %host_name, endpoint = %config.endpoint, "WinRM connection created");

        Ok(Self {
            client,
            config,
            host_name: host_name.to_string(),
            user: host_config.user.clone(),
            password,
            failed: false,
        })
    }

    /// Execute a command via `WinRM` SOAP/WS-Man.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the response is malformed.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        let soap_body = build_winrm_command_envelope(&self.config.endpoint, command);

        debug!(
            host = %self.host_name,
            command = %command,
            "Executing WinRM command"
        );

        let response = self
            .client
            .post(&self.config.endpoint)
            .basic_auth(&self.user, Some(&self.password))
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .body(soap_body)
            .send()
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("WinRM request failed: {e}"),
            })?;

        let status = response.status();
        let body = response.text().await.map_err(|e| BridgeError::SshExec {
            reason: format!("WinRM response read error: {e}"),
        })?;

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        if !status.is_success() {
            return Ok(CommandOutput {
                stdout: String::new(),
                stderr: format!("WinRM HTTP {status}: {body}"),
                exit_code: 1,
                duration_ms,
            });
        }

        // Parse SOAP response to extract stdout/stderr/exit_code
        let (stdout, stderr, exit_code) = parse_winrm_response(&body);

        Ok(CommandOutput {
            stdout,
            stderr,
            exit_code,
            duration_ms,
        })
    }

    /// Mark this connection as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
    }
}

/// Build a WS-Man SOAP envelope for command execution.
fn build_winrm_command_envelope(endpoint: &str, command: &str) -> String {
    // Simplified WinRM SOAP envelope for `cmd.exe /c <command>`
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <wsa:To>{endpoint}</wsa:To>
    <wsa:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
    <wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>
  </s:Header>
  <s:Body>
    <CommandLine xmlns="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
      <Command>cmd.exe /c {command}</Command>
    </CommandLine>
  </s:Body>
</s:Envelope>"#
    )
}

/// Parse a `WinRM` SOAP response to extract stdout, stderr, and exit code.
fn parse_winrm_response(body: &str) -> (String, String, u32) {
    // Simplified parsing — extract text content from known SOAP elements.
    // A production implementation would use quick-xml for proper parsing.
    let stdout = extract_xml_value(body, "Stream Name=\"stdout\"")
        .or_else(|| extract_xml_value(body, "stdout"))
        .unwrap_or_default();
    let stderr = extract_xml_value(body, "Stream Name=\"stderr\"")
        .or_else(|| extract_xml_value(body, "stderr"))
        .unwrap_or_default();
    let exit_code = extract_xml_value(body, "ExitCode")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    (stdout, stderr, exit_code)
}

/// Simple XML value extraction (no full parser needed for known structure).
fn extract_xml_value(xml: &str, tag_hint: &str) -> Option<String> {
    let start = xml.find(tag_hint)?;
    let after_tag = &xml[start..];
    let content_start = after_tag.find('>')? + 1;
    let content_end = after_tag[content_start..].find('<')?;
    let value = &after_tag[content_start..content_start + content_end];
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_winrm_config_from_host_config_https() {
        let host = HostConfig {
            hostname: "10.0.0.1".to_string(),
            port: 5986,
            user: "admin".to_string(),
            auth: crate::config::AuthConfig::Password {
                password: zeroize::Zeroizing::new("pass".to_string()),
            },
            description: None,
            host_key_verification: crate::config::HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: crate::config::OsType::Windows,
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),
        };
        let config = WinRmConfig::from_host_config(&host);
        assert_eq!(config.endpoint, "https://10.0.0.1:5986/wsman");
        assert!(config.use_ssl);
    }

    #[test]
    fn test_winrm_config_from_host_config_http() {
        let host = HostConfig {
            hostname: "10.0.0.1".to_string(),
            port: 5985,
            user: "admin".to_string(),
            auth: crate::config::AuthConfig::Password {
                password: zeroize::Zeroizing::new("pass".to_string()),
            },
            description: None,
            host_key_verification: crate::config::HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: crate::config::OsType::Windows,
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),
        };
        let config = WinRmConfig::from_host_config(&host);
        assert_eq!(config.endpoint, "http://10.0.0.1:5985/wsman");
        assert!(!config.use_ssl);
    }

    #[test]
    fn test_build_soap_envelope() {
        let envelope = build_winrm_command_envelope("https://host:5986/wsman", "whoami");
        assert!(envelope.contains("whoami"));
        assert!(envelope.contains("wsman"));
    }

    #[test]
    fn test_parse_winrm_response_with_exit_code() {
        let body = "<ExitCode>42</ExitCode>";
        let (_, _, exit_code) = parse_winrm_response(body);
        assert_eq!(exit_code, 42);
    }

    #[test]
    fn test_extract_xml_value() {
        let xml = "<foo>bar</foo>";
        assert_eq!(extract_xml_value(xml, "foo"), Some("bar".to_string()));
    }

    #[test]
    fn test_extract_xml_value_empty() {
        let xml = "<foo></foo>";
        assert_eq!(extract_xml_value(xml, "foo"), None);
    }

    #[test]
    fn test_extract_xml_value_missing() {
        let xml = "<baz>qux</baz>";
        assert_eq!(extract_xml_value(xml, "foo"), None);
    }

    #[test]
    fn test_parse_winrm_response_stdout_stderr() {
        let body = r#"<Stream Name="stdout">Hello World</Stream><Stream Name="stderr">Error msg</Stream><ExitCode>1</ExitCode>"#;
        let (stdout, stderr, exit_code) = parse_winrm_response(body);
        assert_eq!(stdout, "Hello World");
        assert_eq!(stderr, "Error msg");
        assert_eq!(exit_code, 1);
    }

    #[test]
    fn test_parse_winrm_response_empty_body() {
        let (stdout, stderr, exit_code) = parse_winrm_response("");
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_parse_winrm_response_only_stdout() {
        let body = r#"<Stream Name="stdout">output data</Stream>"#;
        let (stdout, stderr, exit_code) = parse_winrm_response(body);
        assert_eq!(stdout, "output data");
        assert!(stderr.is_empty());
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_winrm_config_from_host_config_ssh_port_fallback() {
        let host = HostConfig {
            hostname: "10.0.0.2".to_string(),
            port: 22,
            user: "admin".to_string(),
            auth: crate::config::AuthConfig::Password {
                password: zeroize::Zeroizing::new("pass".to_string()),
            },
            description: None,
            host_key_verification: crate::config::HostKeyVerification::default(),
            proxy_jump: None,
            socks_proxy: None,
            sudo_password: None,
            tags: Vec::new(),
            os_type: crate::config::OsType::Windows,
            shell: None,
            retry: None,
            protocol: crate::config::Protocol::default(),
        };
        let config = WinRmConfig::from_host_config(&host);
        assert_eq!(config.endpoint, "https://10.0.0.2:5986/wsman");
        assert!(config.use_ssl);
    }

    #[test]
    fn test_parse_winrm_response_fallback_stdout_tag() {
        let body = "<stdout>fallback output</stdout><ExitCode>0</ExitCode>";
        let (stdout, _, exit_code) = parse_winrm_response(body);
        assert_eq!(stdout, "fallback output");
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_parse_winrm_response_invalid_exit_code() {
        let body = "<ExitCode>not_a_number</ExitCode>";
        let (_, _, exit_code) = parse_winrm_response(body);
        assert_eq!(exit_code, 0); // defaults to 0
    }

    #[test]
    fn test_parse_winrm_response_fallback_stderr_tag() {
        let body = "<stderr>error text</stderr>";
        let (stdout, stderr, _) = parse_winrm_response(body);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "error text");
    }

    #[test]
    fn test_extract_xml_value_nested() {
        let xml = "<outer><inner>value</inner></outer>";
        assert_eq!(extract_xml_value(xml, "inner"), Some("value".to_string()));
    }

    #[test]
    fn test_build_soap_envelope_structure() {
        let envelope = build_winrm_command_envelope("https://host:5986/wsman", "ipconfig");
        assert!(envelope.contains("xmlns:s="));
        assert!(envelope.contains("xmlns:wsa="));
        assert!(envelope.contains("xmlns:wsman="));
        assert!(envelope.contains("wsa:Action"));
        assert!(envelope.contains("wsman:ResourceURI"));
        assert!(envelope.contains("cmd.exe /c ipconfig"));
    }

    #[test]
    fn test_build_soap_envelope_contains_command() {
        let envelope = build_winrm_command_envelope("https://host:5986/wsman", "Get-Process");
        assert!(envelope.contains("Get-Process"));
        assert!(envelope.contains("Envelope"));
        assert!(envelope.contains("wsman"));
    }
}
