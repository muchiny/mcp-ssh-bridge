//! Serial port protocol adapter — embedded devices, PLCs, console ports
//!
//! Implements command execution over serial ports (RS-232, USB-to-serial),
//! primarily for embedded devices, PLCs, and network equipment console ports.
//!
//! Feature-gated behind `serial`.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_serial::{SerialPortBuilderExt, SerialStream};
use tracing::{debug, info, warn};

use crate::config::{HostConfig, LimitsConfig};
use crate::error::{BridgeError, Result};
use crate::ssh::CommandOutput;

/// Default serial baud rate.
const DEFAULT_BAUD_RATE: u32 = 9600;

/// Default read timeout for serial responses.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// An active serial port connection.
pub struct SerialConnection {
    port: SerialStream,
    host_name: String,
    read_timeout: Duration,
    failed: bool,
}

impl SerialConnection {
    /// Open a serial port connection.
    ///
    /// `HostConfig` is interpreted as:
    /// - `hostname` → serial device path (e.g., `/dev/ttyUSB0`, `COM3`)
    /// - `port` → baud rate (default: 9600; set to non-SSH value like 9600)
    ///
    /// # Errors
    ///
    /// Returns an error if the serial port cannot be opened.
    pub async fn connect(
        host_name: &str,
        host_config: &HostConfig,
        _limits: &LimitsConfig,
    ) -> Result<Self> {
        let device = &host_config.hostname;
        let baud_rate = if host_config.port == 22 {
            DEFAULT_BAUD_RATE
        } else {
            u32::from(host_config.port)
        };

        info!(
            host = %host_name,
            device = %device,
            baud_rate = baud_rate,
            "Opening serial port"
        );

        let port = tokio_serial::new(device, baud_rate)
            .open_native_async()
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Serial port open failed for {device}: {e}"),
            })?;

        info!(host = %host_name, "Serial port connected");

        Ok(Self {
            port,
            host_name: host_name.to_string(),
            read_timeout: DEFAULT_READ_TIMEOUT,
            failed: false,
        })
    }

    /// Send a command and read the response from the serial port.
    ///
    /// Writes the command followed by a newline, then reads until
    /// timeout or a prompt character is received.
    ///
    /// # Errors
    ///
    /// Returns an error if the write or read fails.
    pub async fn exec(&mut self, command: &str, _limits: &LimitsConfig) -> Result<CommandOutput> {
        let start = Instant::now();

        debug!(
            host = %self.host_name,
            command = %command,
            "Sending serial command"
        );

        // Write command + newline
        self.port
            .write_all(format!("{command}\r\n").as_bytes())
            .await
            .map_err(|e| BridgeError::SshExec {
                reason: format!("Serial write failed: {e}"),
            })?;

        // Read response with timeout
        let mut output = Vec::with_capacity(4096);
        let mut buf = [0u8; 1024];

        let read_result = tokio::time::timeout(self.read_timeout, async {
            loop {
                match self.port.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        output.extend_from_slice(&buf[..n]);
                        // Check for common prompt endings
                        let tail = String::from_utf8_lossy(&output);
                        if tail.ends_with("# ")
                            || tail.ends_with("$ ")
                            || tail.ends_with("> ")
                            || tail.ends_with("] ")
                        {
                            break;
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        })
        .await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match read_result {
            Ok(Ok(())) | Err(_) => {
                // Timeout is normal for serial — return what we got
                let stdout = String::from_utf8_lossy(&output).to_string();
                Ok(CommandOutput {
                    stdout,
                    stderr: String::new(),
                    exit_code: 0,
                    duration_ms,
                })
            }
            Ok(Err(e)) => Err(BridgeError::SshExec {
                reason: format!("Serial read failed: {e}"),
            }),
        }
    }

    /// Mark this connection as failed.
    pub fn mark_failed(&mut self) {
        self.failed = true;
        warn!(host = %self.host_name, "Serial connection marked as failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_baud_rate() {
        assert_eq!(DEFAULT_BAUD_RATE, 9600);
    }

    #[test]
    fn test_default_read_timeout() {
        assert_eq!(DEFAULT_READ_TIMEOUT, Duration::from_secs(5));
    }
}
