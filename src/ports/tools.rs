//! Tool Handler Port
//!
//! This module defines the trait for MCP tool handlers,
//! enabling a plugin-like architecture where each tool
//! can be implemented independently.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::RwLock;

use super::protocol::ToolCallResult;
use crate::config::Config;
use crate::domain::CommandHistory;
use crate::domain::{ExecuteCommandUseCase, OutputCache, TunnelManager};
use crate::error::Result;
use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
use crate::ssh::{ConnectionPool, SessionManager};

/// Schema definition for a tool
#[derive(Debug, Clone)]
pub struct ToolSchema {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: &'static str,
}

/// Context provided to tool handlers during execution
///
/// This struct contains all the dependencies that tools might need
/// to execute their operations.
pub struct ToolContext {
    pub config: Arc<Config>,
    pub validator: Arc<CommandValidator>,
    pub sanitizer: Arc<Sanitizer>,
    pub audit_logger: Arc<AuditLogger>,
    pub history: Arc<CommandHistory>,
    pub connection_pool: Arc<ConnectionPool>,
    pub execute_use_case: Arc<ExecuteCommandUseCase>,
    pub rate_limiter: Arc<RateLimiter>,
    pub session_manager: Arc<SessionManager>,
    pub tunnel_manager: Arc<TunnelManager>,
    pub output_cache: Option<Arc<OutputCache>>,
    /// Runtime override for `max_output_chars`, shared with `McpServer`.
    /// Written by `ssh_config_set` or auto-detected from MCP client info.
    pub runtime_max_output_chars: Option<Arc<RwLock<Option<usize>>>>,
}

impl ToolContext {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<Config>,
        validator: Arc<CommandValidator>,
        sanitizer: Arc<Sanitizer>,
        audit_logger: Arc<AuditLogger>,
        history: Arc<CommandHistory>,
        connection_pool: Arc<ConnectionPool>,
        execute_use_case: Arc<ExecuteCommandUseCase>,
        rate_limiter: Arc<RateLimiter>,
        session_manager: Arc<SessionManager>,
    ) -> Self {
        Self {
            config,
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool,
            execute_use_case,
            rate_limiter,
            session_manager,
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
        }
    }
}

/// Trait for tool handlers
///
/// Each tool in the MCP server implements this trait, providing
/// a consistent interface for tool registration and execution.
#[async_trait]
pub trait ToolHandler: Send + Sync {
    /// Get the tool's name (used for routing)
    fn name(&self) -> &'static str;

    /// Get the tool's description
    fn description(&self) -> &'static str;

    /// Get the tool's input schema as a JSON string
    fn schema(&self) -> ToolSchema;

    /// Execute the tool with the given arguments
    ///
    /// # Arguments
    /// * `args` - The tool arguments as a JSON value
    /// * `ctx` - The execution context with dependencies
    ///
    /// # Returns
    /// The tool result, either success or error
    async fn execute(&self, args: Option<Value>, ctx: &ToolContext) -> Result<ToolCallResult>;
}

#[cfg(test)]
#[allow(dead_code)]
pub mod mock {
    use super::*;
    use crate::config::{
        AuditConfig, AuthConfig, Config, HostConfig, HostKeyVerification, LimitsConfig, OsType,
        SecurityConfig, SessionConfig, SshConfigDiscovery, ToolGroupsConfig,
    };
    use crate::domain::history::HistoryConfig;
    use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
    use crate::ssh::SessionManager;
    use std::collections::HashMap;

    /// Create a minimal test context with no hosts configured
    #[must_use]
    pub fn create_test_context() -> ToolContext {
        create_test_context_with_config(Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        })
    }

    /// Create a test context with a single host "server1" at 192.168.1.100
    #[must_use]
    pub fn create_test_context_with_host() -> ToolContext {
        let mut hosts = HashMap::new();
        hosts.insert(
            "server1".to_string(),
            HostConfig {
                hostname: "192.168.1.100".to_string(),
                port: 22,
                user: "admin".to_string(),
                auth: AuthConfig::Key {
                    path: "~/.ssh/id_rsa".to_string(),
                    passphrase: None,
                },
                description: None,
                host_key_verification: HostKeyVerification::default(),
                proxy_jump: None,
                socks_proxy: None,
                sudo_password: None,
                os_type: OsType::Linux,
                shell: None,
            },
        );

        create_test_context_with_config(Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        })
    }

    /// Create a test context with custom hosts
    #[must_use]
    #[allow(clippy::implicit_hasher)]
    pub fn create_test_context_with_hosts(hosts: HashMap<String, HostConfig>) -> ToolContext {
        create_test_context_with_config(Config {
            hosts,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        })
    }

    /// Create a test context with a pre-populated command history
    #[must_use]
    pub fn create_test_context_with_history(history: Arc<CommandHistory>) -> ToolContext {
        let config = Config {
            hosts: HashMap::new(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            sessions: SessionConfig::default(),
            tool_groups: ToolGroupsConfig::default(),
            ssh_config: SshConfigDiscovery::default(),
        };

        let validator = Arc::new(CommandValidator::new(&SecurityConfig::default()));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());

        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ConnectionPool::with_defaults()),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
        }
    }

    /// Create a test context with a custom config
    #[must_use]
    pub fn create_test_context_with_config(config: Config) -> ToolContext {
        let validator = Arc::new(CommandValidator::new(&SecurityConfig::default()));
        let sanitizer = Arc::new(Sanitizer::with_defaults());
        let audit_logger = Arc::new(AuditLogger::disabled());
        let history = Arc::new(CommandHistory::new(&HistoryConfig::default()));

        let execute_use_case = Arc::new(ExecuteCommandUseCase::new(
            Arc::clone(&validator),
            Arc::clone(&sanitizer),
            Arc::clone(&audit_logger),
            Arc::clone(&history),
        ));

        ToolContext {
            config: Arc::new(config),
            validator,
            sanitizer,
            audit_logger,
            history,
            connection_pool: Arc::new(ConnectionPool::with_defaults()),
            execute_use_case,
            rate_limiter: Arc::new(RateLimiter::new(0)), // Disabled for tests
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
        }
    }
}
