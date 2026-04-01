use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use mcp_ssh_bridge::McpServer;
use mcp_ssh_bridge::cli::{
    Cli, Commands, run_config_diff, run_describe_tool, run_download, run_exec, run_history,
    run_list_tools, run_status, run_tool, run_upload, run_validate,
};
use mcp_ssh_bridge::config::{default_config_path, load_config};
use mcp_ssh_bridge::error::BridgeError;

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Determine if we're in MCP mode (no command or serve command)
    #[allow(unused_mut)]
    let mut is_mcp_mode = matches!(cli.command, None | Some(Commands::Serve));
    #[cfg(feature = "http")]
    {
        is_mcp_mode = is_mcp_mode || matches!(cli.command, Some(Commands::ServeHttp { .. }));
    }

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
        #[cfg(feature = "http")]
        Some(Commands::ServeHttp { bind }) => {
            use mcp_ssh_bridge::mcp::transport::http as http_transport;
            use mcp_ssh_bridge::mcp::transport::oauth::OAuthConfig as TransportOAuthConfig;

            let (server, _audit_task) = McpServer::new((*config).clone());
            let server = Arc::new(server);

            let oauth = TransportOAuthConfig {
                enabled: config.http.oauth.enabled,
                issuer: config.http.oauth.issuer.clone(),
                audience: config.http.oauth.audience.clone(),
                jwks_uri: config.http.oauth.jwks_uri.clone(),
                client_id: config.http.oauth.client_id.clone(),
                required_scopes: config.http.oauth.required_scopes.clone(),
            };

            let http_config = http_transport::HttpTransportConfig {
                bind: bind.unwrap_or_else(|| config.http.bind.clone()),
                max_body_size: config.http.max_body_size,
                session_timeout: std::time::Duration::from_secs(
                    config.http.session_timeout_seconds,
                ),
                max_sessions: config.http.max_sessions,
                oauth,
            };

            http_transport::serve(server, http_config).await?;
        }
        Some(Commands::Exec {
            host,
            command,
            timeout,
            working_dir,
        }) => {
            if cli.dry_run {
                println!("[dry-run] Would execute on host '{host}': {command}");
                if let Some(ref dir) = working_dir {
                    println!("[dry-run] Working directory: {dir}");
                }
                println!("[dry-run] Timeout: {timeout}s");
                return Ok(());
            }
            run_exec(config, &host, &command, timeout, working_dir.as_deref()).await?;
        }
        Some(Commands::Status) => {
            run_status(config).await?;
        }
        Some(Commands::History { limit, host }) => {
            run_history(config, limit, host.as_deref()).await?;
        }
        Some(Commands::Completions { shell }) => {
            use clap::CommandFactory;
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "mcp-ssh-bridge",
                &mut std::io::stdout(),
            );
        }
        Some(Commands::Tool {
            tool_name,
            args,
            json_args,
        }) => {
            if cli.dry_run {
                println!("[dry-run] Would invoke tool '{tool_name}' with args: {args:?}");
                if let Some(ref ja) = json_args {
                    println!("[dry-run] JSON args: {ja}");
                }
                return Ok(());
            }
            let exit_code = run_tool(config, &tool_name, &args, json_args.as_deref(), cli.json)
                .await
                .map_err(map_exit_code)?;
            if exit_code != 0 {
                std::process::exit(1);
            }
        }
        Some(Commands::DescribeTool { tool_name }) => {
            run_describe_tool(config, &tool_name, cli.json).await?;
        }
        Some(Commands::ListTools {
            group,
            groups_only,
            search,
            json,
        }) => {
            if json {
                eprintln!(
                    "warning: --json under list-tools is deprecated; use the global --json flag"
                );
            }
            run_list_tools(
                config,
                group.as_deref(),
                json || cli.json,
                groups_only,
                search.as_deref(),
            )
            .await?;
        }
        Some(Commands::Validate) => {
            run_validate(config).await?;
        }
        Some(Commands::ConfigDiff) => {
            run_config_diff(config).await?;
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

/// Map `BridgeError` variants to standardised exit codes.
///
/// - 1: tool / command execution error
/// - 2: CLI usage error (unknown tool, bad args)
/// - 3: connection / SSH error
/// - 4: security denial
/// - 5: configuration error
#[expect(clippy::needless_pass_by_value)]
fn map_exit_code(err: BridgeError) -> anyhow::Error {
    let code = match &err {
        BridgeError::CommandDenied { .. } => 4,
        BridgeError::UnknownHost { .. } | BridgeError::SshConnection { .. } => 3,
        BridgeError::McpUnknownTool { .. } => 2,
        BridgeError::Config(_) => 5,
        _ => 1,
    };
    eprintln!("Error: {err}");
    std::process::exit(code);
}
