//! SNMP protocol adapter — network device monitoring
//!
//! Implements SNMP `GET`, `WALK`, and `GETNEXT` operations for querying
//! network devices (routers, switches, printers, UPS, etc.) via `SNMPv2c`.
//!
//! Feature-gated behind `snmp`.

use std::fmt::Write;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Default SNMP port.
const DEFAULT_SNMP_PORT: u16 = 161;

/// Default SNMP community string.
const DEFAULT_COMMUNITY: &str = "public";

/// An active SNMP session.
///
/// Uses synchronous UDP (via `snmp` crate) wrapped in `spawn_blocking`.
pub struct SnmpConnection {
    host_addr: String,
    community: Vec<u8>,
    host_name: String,
    failed: bool,
}

impl SnmpConnection {
    /// Create an SNMP session configuration.
    ///
    /// `HostConfig` is interpreted as:
    /// - `hostname` → SNMP agent IP/hostname
    /// - `port` → SNMP port (default: 161)
    /// - `user` → SNMP community string (default: "public")
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    #[allow(clippy::unused_async)]
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        let port = if host_config.port == 22 {
            DEFAULT_SNMP_PORT
        } else {
            host_config.port
        };

        let host_addr = format!("{}:{port}", host_config.hostname);
        let community = if host_config.user.is_empty() || host_config.user == "root" {
            DEFAULT_COMMUNITY.as_bytes().to_vec()
        } else {
            host_config.user.as_bytes().to_vec()
        };

        info!(
            host = %host_name,
            addr = %host_addr,
            "SNMP session configured"
        );

        Ok(Self {
            host_addr,
            community,
            host_name: host_name.to_string(),
            failed: false,
        })
    }

    /// Execute an SNMP operation.
    ///
    /// The `command` is interpreted as:
    /// - `get <OID>` — SNMP GET
    /// - `walk <OID>` — SNMP WALK (sequential GETNEXT)
    /// - `getnext <OID>` — SNMP GETNEXT
    ///
    /// OIDs are dotted numeric format, e.g. `1.3.6.1.2.1.1.1.0`
    ///
    /// # Errors
    ///
    /// Returns an error if the SNMP operation fails.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(host = %self.host_name, command = %command, "Executing SNMP operation");

        let parts: Vec<&str> = command.splitn(2, ' ').collect();
        if parts.len() < 2 {
            return Err(BridgeError::SshExec {
                reason: "SNMP command format: <get|walk|getnext> <OID>".to_string(),
            });
        }

        let operation = parts[0].to_lowercase();
        let oid_str = parts[1].trim();

        let host_addr = self.host_addr.clone();
        let community = self.community.clone();
        let oid = oid_str.to_string();
        let op = operation.clone();

        // snmp crate is synchronous, run in blocking thread
        let result =
            tokio::task::spawn_blocking(move || snmp_operation(&host_addr, &community, &op, &oid))
                .await
                .map_err(|e| BridgeError::SshExec {
                    reason: format!("SNMP task join failed: {e}"),
                })?;

        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(output) => Ok(CommandOutput {
                stdout: output,
                stderr: String::new(),
                exit_code: 0,
                duration_ms,
            }),
            Err(err) => Ok(CommandOutput {
                stdout: String::new(),
                stderr: err,
                exit_code: 1,
                duration_ms,
            }),
        }
    }

    /// Mark this connection as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "SNMP session marked as failed");
    }
}

/// Parse a dotted OID string into a `Vec<u32>`.
fn parse_oid(oid: &str) -> std::result::Result<Vec<u32>, String> {
    oid.split('.')
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u32>()
                .map_err(|e| format!("Invalid OID component '{s}': {e}"))
        })
        .collect()
}

/// Format an SNMP value for display.
fn format_value(value: &snmp::Value<'_>) -> String {
    match value {
        snmp::Value::Integer(i) => format!("INTEGER: {i}"),
        snmp::Value::OctetString(s) => {
            format!("STRING: {}", String::from_utf8_lossy(s))
        }
        snmp::Value::ObjectIdentifier(oid) => format!("OID: {oid}"),
        snmp::Value::Null => "NULL".to_string(),
        snmp::Value::Counter32(c) => format!("Counter32: {c}"),
        snmp::Value::Unsigned32(u) => format!("Gauge32: {u}"),
        snmp::Value::Timeticks(t) => format!("Timeticks: ({t})"),
        snmp::Value::Counter64(c) => format!("Counter64: {c}"),
        snmp::Value::IpAddress(a) => format!("IpAddress: {}.{}.{}.{}", a[0], a[1], a[2], a[3]),
        _ => format!("{value:?}"),
    }
}

/// Perform a synchronous SNMP operation.
fn snmp_operation(
    host_addr: &str,
    community: &[u8],
    operation: &str,
    oid: &str,
) -> std::result::Result<String, String> {
    let timeout = Duration::from_secs(5);
    let oid_components = parse_oid(oid)?;

    let mut session = snmp::SyncSession::new(host_addr, community, Some(timeout), 0)
        .map_err(|e| format!("SNMP session failed: {e:?}"))?;

    match operation {
        "get" => {
            let response = session
                .get(&oid_components)
                .map_err(|e| format!("SNMP GET failed: {e:?}"))?;

            let mut output = String::new();
            for (oid_resp, value) in response.varbinds {
                let _ = writeln!(output, "{oid_resp} = {}", format_value(&value));
            }
            Ok(output)
        }
        "getnext" => {
            let response = session
                .getnext(&oid_components)
                .map_err(|e| format!("SNMP GETNEXT failed: {e:?}"))?;

            let mut output = String::new();
            for (oid_resp, value) in response.varbinds {
                let _ = writeln!(output, "{oid_resp} = {}", format_value(&value));
            }
            Ok(output)
        }
        "walk" => {
            // SNMP WALK: repeated GETNEXT until OID leaves subtree
            let mut output = String::new();
            let mut current_oid = oid_components;
            let max_iterations = 1000;

            for _ in 0..max_iterations {
                let response = session
                    .getnext(&current_oid)
                    .map_err(|e| format!("SNMP WALK failed: {e:?}"))?;

                let mut done = true;
                for (oid_resp, value) in response.varbinds {
                    let resp_str = format!("{oid_resp}");
                    // Check if still within the original subtree
                    if !resp_str.starts_with(oid) {
                        done = true;
                        break;
                    }
                    let _ = writeln!(output, "{resp_str} = {}", format_value(&value));
                    current_oid = parse_oid(&resp_str).unwrap_or_default();
                    done = false;
                }

                if done {
                    break;
                }
            }
            Ok(output)
        }
        _ => Err(format!(
            "Unknown SNMP operation: {operation}. Use get, getnext, or walk."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_snmp_port() {
        assert_eq!(DEFAULT_SNMP_PORT, 161);
    }

    #[test]
    fn test_parse_oid_valid() {
        let oid = parse_oid("1.3.6.1.2.1.1.1.0").unwrap();
        assert_eq!(oid, vec![1, 3, 6, 1, 2, 1, 1, 1, 0]);
    }

    #[test]
    fn test_parse_oid_leading_dot() {
        let oid = parse_oid(".1.3.6.1").unwrap();
        assert_eq!(oid, vec![1, 3, 6, 1]);
    }

    #[test]
    fn test_parse_oid_invalid() {
        assert!(parse_oid("1.3.abc.1").is_err());
    }

    #[test]
    fn test_parse_oid_empty() {
        let oid = parse_oid("").unwrap();
        assert!(oid.is_empty());
    }

    #[test]
    fn test_parse_oid_single() {
        let oid = parse_oid("1").unwrap();
        assert_eq!(oid, vec![1]);
    }

    #[test]
    fn test_parse_oid_trailing_dot() {
        let oid = parse_oid("1.3.6.").unwrap();
        assert_eq!(oid, vec![1, 3, 6]);
    }

    #[test]
    fn test_parse_oid_very_long() {
        let oid = parse_oid("1.3.6.1.2.1.1.1.0.1.2.3.4.5.6.7.8.9").unwrap();
        assert_eq!(oid.len(), 18);
    }

    #[test]
    fn test_parse_oid_large_component() {
        let oid = parse_oid("1.3.4294967295").unwrap();
        assert_eq!(oid, vec![1, 3, u32::MAX]);
    }

    #[test]
    fn test_parse_oid_overflow_component() {
        assert!(parse_oid("1.3.4294967296").is_err());
    }

    #[test]
    fn test_format_value_integer() {
        let val = snmp::Value::Integer(42);
        assert_eq!(format_value(&val), "INTEGER: 42");
    }

    #[test]
    fn test_format_value_octet_string() {
        let val = snmp::Value::OctetString(b"hello");
        assert_eq!(format_value(&val), "STRING: hello");
    }

    #[test]
    fn test_format_value_null() {
        let val = snmp::Value::Null;
        assert_eq!(format_value(&val), "NULL");
    }

    #[test]
    fn test_format_value_counter32() {
        let val = snmp::Value::Counter32(1000);
        assert_eq!(format_value(&val), "Counter32: 1000");
    }

    #[test]
    fn test_format_value_unsigned32() {
        let val = snmp::Value::Unsigned32(500);
        assert_eq!(format_value(&val), "Gauge32: 500");
    }

    #[test]
    fn test_format_value_timeticks() {
        let val = snmp::Value::Timeticks(123_456);
        assert_eq!(format_value(&val), "Timeticks: (123456)");
    }

    #[test]
    fn test_format_value_counter64() {
        let val = snmp::Value::Counter64(9_999_999_999);
        assert_eq!(format_value(&val), "Counter64: 9999999999");
    }

    #[test]
    fn test_format_value_ip_address() {
        let val = snmp::Value::IpAddress([192, 168, 1, 1]);
        assert_eq!(format_value(&val), "IpAddress: 192.168.1.1");
    }

    #[test]
    fn test_parse_oid_negative_number() {
        assert!(parse_oid("1.3.-1").is_err());
    }

    #[test]
    fn test_parse_oid_double_dot() {
        // Double dots produce empty segments which are filtered out
        let oid = parse_oid("1..3.6").unwrap();
        assert_eq!(oid, vec![1, 3, 6]);
    }

    #[test]
    fn test_parse_oid_whitespace() {
        assert!(parse_oid("1.3. 6").is_err());
    }

    #[test]
    fn test_parse_oid_hex_component() {
        assert!(parse_oid("1.3.0xFF").is_err());
    }

    #[test]
    fn test_format_value_integer_negative() {
        let val = snmp::Value::Integer(-42);
        assert_eq!(format_value(&val), "INTEGER: -42");
    }

    #[test]
    fn test_format_value_integer_zero() {
        let val = snmp::Value::Integer(0);
        assert_eq!(format_value(&val), "INTEGER: 0");
    }

    #[test]
    fn test_format_value_octet_string_non_utf8() {
        let val = snmp::Value::OctetString(&[0xFF, 0xFE, 0x00]);
        let formatted = format_value(&val);
        assert!(formatted.starts_with("STRING: "));
    }

    #[test]
    fn test_format_value_octet_string_empty() {
        let val = snmp::Value::OctetString(b"");
        assert_eq!(format_value(&val), "STRING: ");
    }

    #[test]
    fn test_format_value_counter32_zero() {
        let val = snmp::Value::Counter32(0);
        assert_eq!(format_value(&val), "Counter32: 0");
    }

    #[test]
    fn test_format_value_counter32_max() {
        let val = snmp::Value::Counter32(u32::MAX);
        assert_eq!(format_value(&val), format!("Counter32: {}", u32::MAX));
    }

    #[test]
    fn test_format_value_counter64_zero() {
        let val = snmp::Value::Counter64(0);
        assert_eq!(format_value(&val), "Counter64: 0");
    }

    #[test]
    fn test_format_value_timeticks_zero() {
        let val = snmp::Value::Timeticks(0);
        assert_eq!(format_value(&val), "Timeticks: (0)");
    }

    #[test]
    fn test_format_value_ip_address_zeros() {
        let val = snmp::Value::IpAddress([0, 0, 0, 0]);
        assert_eq!(format_value(&val), "IpAddress: 0.0.0.0");
    }

    #[test]
    fn test_format_value_ip_address_broadcast() {
        let val = snmp::Value::IpAddress([255, 255, 255, 255]);
        assert_eq!(format_value(&val), "IpAddress: 255.255.255.255");
    }

    #[test]
    fn test_default_community_string() {
        assert_eq!(DEFAULT_COMMUNITY, "public");
    }
}
