//! CLI module for direct command-line usage
//!
//! This module provides a command-line interface to use the SSH bridge
//! without going through the MCP protocol.

mod runner;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub use runner::{run_download, run_exec, run_history, run_status, run_upload};

/// MCP SSH Bridge - Secure SSH access to air-gapped environments
#[derive(Parser)]
#[command(name = "mcp-ssh-bridge")]
#[command(about = "MCP server for SSH access to air-gapped environments")]
#[command(version)]
#[command(after_help = "EXAMPLES:
    # Start MCP server (default mode, for Claude Code integration)
    mcp-ssh-bridge

    # Start MCP server with custom config
    mcp-ssh-bridge --config /path/to/config.yaml

    # Execute a command on a remote host
    mcp-ssh-bridge exec prod-server \"docker ps\"

    # Show configured hosts and security settings
    mcp-ssh-bridge status

    # View command history
    mcp-ssh-bridge history --limit 20

    # Upload a file
    mcp-ssh-bridge upload prod-server ./script.sh /tmp/script.sh

    # Download a file
    mcp-ssh-bridge download prod-server /var/log/app.log ./app.log")]
pub struct Cli {
    /// Path to configuration file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Available CLI commands
#[derive(Subcommand)]
pub enum Commands {
    /// Start MCP server (JSON-RPC over stdio) - same as running without arguments
    Serve,

    /// Execute a command on a remote host
    Exec {
        /// SSH host alias from configuration
        host: String,

        /// Command to execute
        command: String,

        /// Timeout in seconds
        #[arg(short, long, default_value = "120")]
        timeout: u64,

        /// Working directory for command execution
        #[arg(short, long)]
        working_dir: Option<String>,
    },

    /// Show configured hosts and security settings
    Status,

    /// Show command execution history
    History {
        /// Number of entries to show
        #[arg(short, long, default_value = "10")]
        limit: usize,

        /// Filter by host
        #[arg(long)]
        host: Option<String>,
    },

    /// Upload a file to remote host via SFTP
    Upload {
        /// SSH host alias
        host: String,

        /// Local file path
        local_path: PathBuf,

        /// Remote destination path
        remote_path: String,

        /// Transfer mode: overwrite, append, resume, fail-if-exists
        #[arg(long, default_value = "overwrite")]
        mode: String,

        /// Chunk size in bytes for streaming (default: 1MB)
        #[arg(long, default_value = "1048576")]
        chunk_size: u64,

        /// Verify SHA256 checksum after transfer
        #[arg(long)]
        verify_checksum: bool,

        /// Preserve file permissions
        #[arg(long, default_value = "true")]
        preserve_permissions: bool,

        /// Show transfer progress
        #[arg(long, short)]
        progress: bool,
    },

    /// Download a file from remote host via SFTP
    Download {
        /// SSH host alias
        host: String,

        /// Remote file path
        remote_path: String,

        /// Local destination path
        local_path: PathBuf,

        /// Transfer mode: overwrite, append, resume, fail-if-exists
        #[arg(long, default_value = "overwrite")]
        mode: String,

        /// Chunk size in bytes for streaming (default: 1MB)
        #[arg(long, default_value = "1048576")]
        chunk_size: u64,

        /// Verify SHA256 checksum after transfer
        #[arg(long)]
        verify_checksum: bool,

        /// Preserve file permissions
        #[arg(long, default_value = "true")]
        preserve_permissions: bool,

        /// Show transfer progress
        #[arg(long, short)]
        progress: bool,
    },
}
