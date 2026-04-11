//! Unix Domain Socket Transport
//!
//! Multi-session transport backed by a `tokio::net::UnixListener`. Each
//! `accept()` call returns the next client connection as a fresh
//! [`Session`]. This is the transport used by the daemon mode
//! (`mcp-ssh-bridge daemon start`) to serve many clients on a shared
//! socket without paying SSH pool cold-start costs per request.
//!
//! The real implementation is added in Phase A.5 of Sprint 3. This stub
//! exists so the module hierarchy compiles while Phase A.1-A.4 wire the
//! new [`crate::mcp::transport::Transport`] trait into the stdio path.

// Phase A.5 will replace the contents of this file with a concrete
// `UnixSocketTransport`. Keep the module empty-but-present so the
// `pub mod unix_socket;` declaration in `transport/mod.rs` stays valid.
