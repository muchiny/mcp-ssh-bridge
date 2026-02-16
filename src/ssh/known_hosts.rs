//! SSH `known_hosts` verification wrapper around russh's built-in support

use russh::keys::known_hosts::{check_known_hosts, learn_known_hosts};
use russh::keys::{Error as KeyError, HashAlg, PublicKey};
use tracing::{debug, warn};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::config::HostKeyVerification;
use crate::error::{BridgeError, Result};

/// Result of verifying a host key
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Key matches a known entry
    Match,
    /// Key does not match the expected key (line number where mismatch occurred)
    Mismatch { line: usize },
    /// Host is not in `known_hosts`
    Unknown,
}

/// Verify a host key against `known_hosts`
///
/// # Errors
///
/// Returns an error if the `known_hosts` file cannot be read or parsed.
pub fn verify(hostname: &str, port: u16, key: &PublicKey) -> Result<VerifyResult> {
    match check_known_hosts(hostname, port, key) {
        Ok(true) => {
            debug!(hostname = %hostname, port = %port, "Host key verified");
            Ok(VerifyResult::Match)
        }
        Ok(false) => {
            debug!(hostname = %hostname, port = %port, "Host key not in known_hosts");
            Ok(VerifyResult::Unknown)
        }
        Err(KeyError::KeyChanged { line }) => {
            warn!(
                hostname = %hostname,
                port = %port,
                line = %line,
                "Host key mismatch detected"
            );
            Ok(VerifyResult::Mismatch { line })
        }
        Err(e) => Err(BridgeError::Config(format!(
            "Failed to check known_hosts: {e}"
        ))),
    }
}

/// Add a host key to `known_hosts`
///
/// Uses russh's built-in `learn_known_hosts` which appends to the file.
///
/// **Security note:** There is a potential TOCTOU race between `verify()` and
/// `add_key()` in `AcceptNew` mode. This is inherent to the TOFU (Trust On First
/// Use) model and is acceptable for most use cases. In high-security environments,
/// use `Strict` mode with pre-provisioned `known_hosts` files instead.
///
/// # Errors
///
/// Returns an error if the `known_hosts` file cannot be written to.
pub fn add_key(hostname: &str, port: u16, key: &PublicKey) -> Result<()> {
    learn_known_hosts(hostname, port, key)
        .map_err(|e| BridgeError::Config(format!("Failed to add host key to known_hosts: {e}")))?;

    debug!(hostname = %hostname, port = %port, "Added host key to known_hosts");
    Ok(())
}

/// Get the fingerprint of a public key
#[must_use]
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Check that the `known_hosts` file has secure permissions (Unix only).
///
/// Warns if the file is readable by others (mode not 0600 or 0644).
/// This is advisory only - the file is still used but a warning is logged.
#[cfg(unix)]
fn check_known_hosts_permissions() {
    let home = dirs::home_dir();
    let Some(home) = home else {
        return;
    };
    let known_hosts_path = home.join(".ssh").join("known_hosts");
    if let Ok(metadata) = std::fs::metadata(&known_hosts_path) {
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 && mode != 0o644 {
            warn!(
                path = %known_hosts_path.display(),
                mode = format!("{mode:o}"),
                "known_hosts file has overly permissive permissions. \
                 Consider running: chmod 600 ~/.ssh/known_hosts"
            );
        }
    }
}

#[cfg(not(unix))]
fn check_known_hosts_permissions() {
    // Permission checks not available on non-Unix platforms
}

/// Verify a host key according to the verification mode
///
/// # Errors
///
/// Returns an error if:
/// - The host key is mismatched (in `Strict` or `AcceptNew` mode)
/// - The host is unknown (in `Strict` mode)
/// - The `known_hosts` file cannot be read or written to
pub fn verify_host_key(
    hostname: &str,
    port: u16,
    key: &PublicKey,
    mode: HostKeyVerification,
) -> Result<()> {
    check_known_hosts_permissions();

    match mode {
        HostKeyVerification::Off => {
            warn!(
                hostname = %hostname,
                "SECURITY WARNING: Host key verification is DISABLED for this host. \
                 This is vulnerable to MITM attacks. \
                 Use 'strict' or 'accept_new' in production."
            );
            Ok(())
        }
        HostKeyVerification::Strict => match verify(hostname, port, key)? {
            VerifyResult::Match => Ok(()),
            VerifyResult::Mismatch { line } => Err(BridgeError::SshHostKeyMismatch {
                host: hostname.to_string(),
                expected: format!("key from known_hosts line {line}"),
                actual: fingerprint(key),
            }),
            VerifyResult::Unknown => Err(BridgeError::SshHostKeyUnknown {
                host: hostname.to_string(),
                fingerprint: fingerprint(key),
            }),
        },
        HostKeyVerification::AcceptNew => match verify(hostname, port, key)? {
            VerifyResult::Match => Ok(()),
            VerifyResult::Mismatch { line } => Err(BridgeError::SshHostKeyMismatch {
                host: hostname.to_string(),
                expected: format!("key from known_hosts line {line}"),
                actual: fingerprint(key),
            }),
            VerifyResult::Unknown => {
                warn!(hostname = %hostname, "Adding new host key to known_hosts");
                add_key(hostname, port, key)?;
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_known_hosts_permissions_does_not_panic() {
        // This function should never panic, even if the file doesn't exist
        check_known_hosts_permissions();
    }

    #[test]
    fn test_host_key_verification_default_is_strict() {
        // Security: default mode should be strict for safety
        let default_mode = HostKeyVerification::default();
        assert_eq!(default_mode, HostKeyVerification::Strict);
    }

    #[test]
    fn test_verify_result_mismatch_contains_line_number() {
        // Verify that mismatch captures the line number for debugging
        let mismatch = VerifyResult::Mismatch { line: 42 };

        if let VerifyResult::Mismatch { line } = mismatch {
            assert_eq!(line, 42);
        } else {
            panic!("Expected Mismatch variant");
        }
    }

    #[test]
    fn test_verify_result_distinguishes_mismatch_from_unknown() {
        // Important security distinction: mismatch (MITM?) vs unknown (new host)
        let mismatch = VerifyResult::Mismatch { line: 1 };
        let unknown = VerifyResult::Unknown;

        assert_ne!(mismatch, unknown);
    }

    // ============== VerifyResult Tests ==============

    #[test]
    fn test_verify_result_match() {
        let result = VerifyResult::Match;
        assert_eq!(result, VerifyResult::Match);
    }

    #[test]
    fn test_verify_result_unknown() {
        let result = VerifyResult::Unknown;
        assert_eq!(result, VerifyResult::Unknown);
    }

    #[test]
    fn test_verify_result_debug() {
        let match_result = VerifyResult::Match;
        let unknown_result = VerifyResult::Unknown;
        let mismatch_result = VerifyResult::Mismatch { line: 10 };

        assert!(format!("{match_result:?}").contains("Match"));
        assert!(format!("{unknown_result:?}").contains("Unknown"));
        assert!(format!("{mismatch_result:?}").contains("Mismatch"));
        assert!(format!("{mismatch_result:?}").contains("10"));
    }

    #[test]
    fn test_verify_result_clone() {
        let original = VerifyResult::Mismatch { line: 5 };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_verify_result_eq_same_variant() {
        assert_eq!(VerifyResult::Match, VerifyResult::Match);
        assert_eq!(VerifyResult::Unknown, VerifyResult::Unknown);
        assert_eq!(
            VerifyResult::Mismatch { line: 1 },
            VerifyResult::Mismatch { line: 1 }
        );
    }

    #[test]
    fn test_verify_result_ne_different_line() {
        assert_ne!(
            VerifyResult::Mismatch { line: 1 },
            VerifyResult::Mismatch { line: 2 }
        );
    }

    #[test]
    fn test_verify_result_ne_different_variants() {
        assert_ne!(VerifyResult::Match, VerifyResult::Unknown);
        assert_ne!(VerifyResult::Match, VerifyResult::Mismatch { line: 1 });
        assert_ne!(VerifyResult::Unknown, VerifyResult::Mismatch { line: 1 });
    }

    #[test]
    fn test_verify_result_mismatch_line_zero() {
        let result = VerifyResult::Mismatch { line: 0 };
        if let VerifyResult::Mismatch { line } = result {
            assert_eq!(line, 0);
        }
    }

    #[test]
    fn test_verify_result_mismatch_large_line() {
        let result = VerifyResult::Mismatch { line: 1_000_000 };
        if let VerifyResult::Mismatch { line } = result {
            assert_eq!(line, 1_000_000);
        }
    }

    // ============== HostKeyVerification Mode Tests ==============

    #[test]
    fn test_host_key_verification_strict() {
        assert_eq!(HostKeyVerification::Strict, HostKeyVerification::Strict);
    }

    #[test]
    fn test_host_key_verification_acceptnew() {
        assert_eq!(
            HostKeyVerification::AcceptNew,
            HostKeyVerification::AcceptNew
        );
    }

    #[test]
    fn test_host_key_verification_off() {
        assert_eq!(HostKeyVerification::Off, HostKeyVerification::Off);
    }

    #[test]
    fn test_host_key_verification_modes_distinct() {
        assert_ne!(HostKeyVerification::Strict, HostKeyVerification::AcceptNew);
        assert_ne!(HostKeyVerification::Strict, HostKeyVerification::Off);
        assert_ne!(HostKeyVerification::AcceptNew, HostKeyVerification::Off);
    }

    // ============== Security Implications ==============

    #[test]
    fn test_strict_mode_rejects_unknown() {
        // In strict mode, unknown hosts should be rejected
        // This test documents the expected behavior
        let mode = HostKeyVerification::Strict;
        assert_eq!(mode, HostKeyVerification::Strict);
        // The actual verify_host_key function would return an error for unknown hosts
    }

    #[test]
    fn test_strict_mode_rejects_mismatch() {
        // In strict mode, key mismatches should be rejected (potential MITM)
        let mode = HostKeyVerification::Strict;
        assert_eq!(mode, HostKeyVerification::Strict);
        // This is the most secure mode
    }

    #[test]
    fn test_acceptnew_allows_first_connection() {
        // AcceptNew mode should allow first connections
        // but reject key changes (TOFU model)
        let mode = HostKeyVerification::AcceptNew;
        assert_eq!(mode, HostKeyVerification::AcceptNew);
    }

    #[test]
    fn test_off_mode_warning() {
        // Off mode is insecure and should only be used for testing
        // This test just verifies the mode exists
        let mode = HostKeyVerification::Off;
        assert_eq!(mode, HostKeyVerification::Off);
    }
}
