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

    /// Start MCP server over Streamable HTTP transport
    #[cfg(feature = "http")]
    ServeHttp {
        /// Bind address (overrides config, e.g. "0.0.0.0:3000")
        #[arg(short, long)]
        bind: Option<String>,
    },

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_args_is_serve_mode() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge"]).unwrap();
        assert!(cli.command.is_none());
        assert!(cli.config.is_none());
    }

    #[test]
    fn test_serve_subcommand() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "serve"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Serve)));
    }

    #[test]
    fn test_status_subcommand() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "status"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Status)));
    }

    #[test]
    fn test_exec_subcommand() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "exec", "prod", "docker ps"]).unwrap();
        match cli.command {
            Some(Commands::Exec {
                host,
                command,
                timeout,
                working_dir,
            }) => {
                assert_eq!(host, "prod");
                assert_eq!(command, "docker ps");
                assert_eq!(timeout, 120); // default
                assert!(working_dir.is_none());
            }
            _ => panic!("Expected Exec command"),
        }
    }

    #[test]
    fn test_exec_with_timeout() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "exec", "srv", "ls", "-t", "30"]).unwrap();
        match cli.command {
            Some(Commands::Exec { timeout, .. }) => assert_eq!(timeout, 30),
            _ => panic!("Expected Exec command"),
        }
    }

    #[test]
    fn test_exec_with_working_dir() {
        let cli =
            Cli::try_parse_from(["mcp-ssh-bridge", "exec", "srv", "ls", "-w", "/var/log"]).unwrap();
        match cli.command {
            Some(Commands::Exec { working_dir, .. }) => {
                assert_eq!(working_dir, Some("/var/log".to_string()));
            }
            _ => panic!("Expected Exec command"),
        }
    }

    #[test]
    fn test_history_defaults() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "history"]).unwrap();
        match cli.command {
            Some(Commands::History { limit, host }) => {
                assert_eq!(limit, 10); // default
                assert!(host.is_none());
            }
            _ => panic!("Expected History command"),
        }
    }

    #[test]
    fn test_history_with_options() {
        let cli = Cli::try_parse_from(["mcp-ssh-bridge", "history", "-l", "50", "--host", "prod"])
            .unwrap();
        match cli.command {
            Some(Commands::History { limit, host }) => {
                assert_eq!(limit, 50);
                assert_eq!(host, Some("prod".to_string()));
            }
            _ => panic!("Expected History command"),
        }
    }

    #[test]
    fn test_global_config_flag() {
        let cli =
            Cli::try_parse_from(["mcp-ssh-bridge", "--config", "/etc/mcp.yaml", "status"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/etc/mcp.yaml")));
        assert!(matches!(cli.command, Some(Commands::Status)));
    }

    #[test]
    fn test_config_short_flag() {
        let cli =
            Cli::try_parse_from(["mcp-ssh-bridge", "-c", "/tmp/config.yaml", "serve"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/config.yaml")));
    }

    #[test]
    fn test_upload_subcommand() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "upload",
            "prod",
            "./script.sh",
            "/tmp/script.sh",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Upload {
                host,
                local_path,
                remote_path,
                mode,
                chunk_size,
                verify_checksum,
                ..
            }) => {
                assert_eq!(host, "prod");
                assert_eq!(local_path, PathBuf::from("./script.sh"));
                assert_eq!(remote_path, "/tmp/script.sh");
                assert_eq!(mode, "overwrite");
                assert_eq!(chunk_size, 1_048_576);
                assert!(!verify_checksum);
            }
            _ => panic!("Expected Upload command"),
        }
    }

    #[test]
    fn test_download_subcommand() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "download",
            "prod",
            "/var/log/app.log",
            "./app.log",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Download {
                host,
                remote_path,
                local_path,
                ..
            }) => {
                assert_eq!(host, "prod");
                assert_eq!(remote_path, "/var/log/app.log");
                assert_eq!(local_path, PathBuf::from("./app.log"));
            }
            _ => panic!("Expected Download command"),
        }
    }

    #[test]
    fn test_exec_missing_args_fails() {
        let result = Cli::try_parse_from(["mcp-ssh-bridge", "exec"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_subcommand_fails() {
        let result = Cli::try_parse_from(["mcp-ssh-bridge", "unknown"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_upload_with_verify_checksum() {
        let cli = Cli::try_parse_from([
            "mcp-ssh-bridge",
            "upload",
            "srv",
            "./f",
            "/tmp/f",
            "--verify-checksum",
            "--progress",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Upload {
                verify_checksum,
                progress,
                ..
            }) => {
                assert!(verify_checksum);
                assert!(progress);
            }
            _ => panic!("Expected Upload command"),
        }
    }
}
