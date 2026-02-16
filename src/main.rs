use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use mcp_ssh_bridge::McpServer;
use mcp_ssh_bridge::cli::{
    Cli, Commands, run_download, run_exec, run_history, run_status, run_upload,
};
use mcp_ssh_bridge::config::{default_config_path, load_config};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Determine if we're in MCP mode (no command or serve command)
    let is_mcp_mode = matches!(cli.command, None | Some(Commands::Serve));

    // Initialize logging to stderr (stdout is used for MCP protocol in MCP mode)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        // In CLI mode, use a more compact format
        .with_ansi(!is_mcp_mode)
        .init();

    // Get config path
    let config_path = cli.config.unwrap_or_else(default_config_path);

    info!(config = %config_path.display(), "Loading configuration");

    // Load configuration
    let config = load_config(&config_path)
        .with_context(|| format!("Failed to load config from {}", config_path.display()))?;

    let config = Arc::new(config);

    info!(
        hosts = config.hosts.len(),
        security_mode = ?config.security.mode,
        "Configuration loaded"
    );

    // Dispatch based on command
    match cli.command {
        None | Some(Commands::Serve) => {
            // MCP mode (default, for Claude Code integration)
            let (server, audit_task) = McpServer::new((*config).clone());
            let server = Arc::new(server);
            server.run(audit_task, Some(&config_path)).await?;
        }
        Some(Commands::Exec {
            host,
            command,
            timeout,
            working_dir,
        }) => {
            run_exec(config, &host, &command, timeout, working_dir.as_deref()).await?;
        }
        Some(Commands::Status) => {
            run_status(config).await?;
        }
        Some(Commands::History { limit, host }) => {
            run_history(config, limit, host.as_deref()).await?;
        }
        Some(Commands::Upload {
            host,
            local_path,
            remote_path,
            mode,
            chunk_size,
            verify_checksum,
            preserve_permissions,
            progress,
        }) => {
            run_upload(
                config,
                &host,
                &local_path,
                &remote_path,
                &mode,
                chunk_size,
                verify_checksum,
                preserve_permissions,
                progress,
            )
            .await?;
        }
        Some(Commands::Download {
            host,
            remote_path,
            local_path,
            mode,
            chunk_size,
            verify_checksum,
            preserve_permissions,
            progress,
        }) => {
            run_download(
                config,
                &host,
                &remote_path,
                &local_path,
                &mode,
                chunk_size,
                verify_checksum,
                preserve_permissions,
                progress,
            )
            .await?;
        }
    }

    Ok(())
}
