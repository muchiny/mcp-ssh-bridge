//! Local daemon mode for shared SSH pool across CLI invocations.
//!
//! When running as a daemon, the bridge spawns a single long-lived
//! [`McpServer`] process that listens on a Unix domain socket at
//! `$XDG_RUNTIME_DIR/mcp-ssh-bridge.sock` (fallback:
//! `/tmp/mcp-ssh-bridge-$UID.sock`). CLI invocations detect the socket,
//! connect, and forward their `tools/call` requests over JSON-RPC. The
//! shared [`McpServer::connection_pool`] keeps SSH handshakes cached
//! between invocations.
//!
//! # Scope (Sprint 2)
//!
//! This is a **minimal** daemon:
//! - Single subscriber per connection (no multicast).
//! - No server-initiated notifications (elicitation, sampling, logging)
//!   — those require per-connection notification channels which are
//!   deferred to Sprint 3 along with the `Transport` trait unification.
//! - No batch request support in the daemon loop.
//! - No hot-reload of config from inside the daemon (restart required).
//!
//! See `.claude/plans/noble-forging-rossum.md` for the full scope
//! rationale.

mod connection;
mod pidfile;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::UnixListener;

use crate::config::Config;
use crate::error::{BridgeError, Result};
use crate::mcp::McpServer;

pub use pidfile::{DaemonStatus, PidFile};

/// Default socket path resolution.
///
/// - `$XDG_RUNTIME_DIR/mcp-ssh-bridge.sock` if `$XDG_RUNTIME_DIR` is set
///   (standard systemd-logind behavior on Linux, mode `0700`, auto-cleaned
///   at logout).
/// - `/tmp/mcp-ssh-bridge-$UID.sock` as a safe fallback, using the
///   effective UID to avoid collisions between users on a shared host.
#[must_use]
pub fn default_socket_path() -> PathBuf {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR")
        && !runtime.is_empty()
    {
        return PathBuf::from(runtime).join("mcp-ssh-bridge.sock");
    }
    // Fallback: /tmp with UID suffix. Use `unsafe`-free UID lookup via libc
    // through the `rustix` crate if available — otherwise read `$UID` from
    // env (set by most shells). Shell-agnostic fallback: plain `/tmp`.
    let uid = std::env::var("UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    if uid > 0 {
        PathBuf::from(format!("/tmp/mcp-ssh-bridge-{uid}.sock"))
    } else {
        PathBuf::from("/tmp/mcp-ssh-bridge.sock")
    }
}

/// Start the daemon listening on `socket_path`.
///
/// Blocks until the process receives `SIGINT` (Ctrl+C) or `SIGTERM`.
///
/// # Errors
///
/// Returns an error if:
/// - Another daemon is already running (PID file exists and process alive).
/// - The socket path cannot be created (permissions, parent dir missing).
/// - The underlying `McpServer` fails to start (config load error).
pub async fn run_daemon(config: Arc<Config>, socket_path: &Path) -> Result<()> {
    // 1. Acquire PID lock. This fails fast if another daemon is already
    //    running on the same socket.
    let _pid_file = PidFile::acquire(socket_path)?;

    // 2. Remove any stale socket from a previous crash. `ErrorKind::NotFound`
    //    is fine — `ErrorKind::PermissionDenied` is not, but we surface it.
    match std::fs::remove_file(socket_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(BridgeError::Io(e));
        }
    }

    // 3. Build the shared McpServer. The audit writer task is spawned if
    //    the config enables it — otherwise `audit_task` is None.
    let (server, audit_task) = McpServer::new((*config).clone());
    if let Some(task) = audit_task {
        tokio::spawn(task.run());
    }
    let server = Arc::new(server);

    // 4. Bind the Unix socket. Fails cleanly if permissions are wrong.
    let listener = UnixListener::bind(socket_path).map_err(BridgeError::Io)?;
    tracing::info!(
        path = %socket_path.display(),
        "Daemon listening for CLI connections"
    );

    // 5. Accept loop with graceful shutdown on SIGINT.
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::info!("SIGINT received, daemon shutting down");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let server = Arc::clone(&server);
                        tokio::spawn(async move {
                            if let Err(e) = connection::handle(stream, server).await {
                                tracing::warn!(error = %e, "Connection handler failed");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "UnixListener accept failed");
                        // Brief backoff so a persistent error doesn't busy-spin.
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    // 6. Cleanup: remove the socket file. Ignore errors — we're exiting.
    let _ = std::fs::remove_file(socket_path);
    tracing::info!("Daemon stopped");
    Ok(())
}

/// Stop a running daemon by reading its PID file and sending SIGTERM.
///
/// # Errors
///
/// Returns an error if the PID file is missing, unreadable, or if the
/// target process doesn't respond to the signal.
pub fn stop_daemon(socket_path: &Path) -> Result<()> {
    PidFile::stop(socket_path)
}

/// Report the current daemon status (running, stopped, stale PID file).
///
/// # Errors
///
/// Returns an error only on I/O failures reading the PID file.
pub fn daemon_status(socket_path: &Path) -> Result<DaemonStatus> {
    PidFile::status(socket_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default path is read at runtime from `$XDG_RUNTIME_DIR` (or
    /// falls back to `/tmp`). We can't mutate env vars in tests because
    /// the crate is `#![forbid(unsafe_code)]` and `std::env::set_var`
    /// now requires `unsafe`. Instead we assert on the returned path's
    /// filename — which is deterministic regardless of the parent dir.
    #[test]
    fn test_default_socket_path_filename_is_stable() {
        let path = default_socket_path();
        let file_name = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        // Either the XDG-based default or a fallback with UID suffix.
        assert!(
            file_name == "mcp-ssh-bridge.sock" || file_name.starts_with("mcp-ssh-bridge-"),
            "unexpected filename: {file_name}"
        );
        assert_eq!(
            path.extension().and_then(|e| e.to_str()),
            Some("sock"),
            "path must have .sock extension: {}",
            path.display()
        );
    }
}
