//! Resource Registry
//!
//! Manages registration and lookup of MCP resource handlers.

use std::sync::Arc;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::{ResourceContent, ResourceDefinition};
use crate::ports::{ResourceHandler, ToolContext};

/// Registry for MCP resource handlers
#[derive(Default)]
pub struct ResourceRegistry {
    handlers: Vec<Arc<dyn ResourceHandler>>,
}

impl ResourceRegistry {
    /// Create a new empty registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Register a resource handler
    pub fn register(&mut self, handler: Arc<dyn ResourceHandler>) {
        self.handlers.push(handler);
    }

    /// List all available resources from all handlers
    ///
    /// # Errors
    ///
    /// This function logs warnings for handler failures but does not
    /// propagate errors; it always returns `Ok` with the successfully
    /// collected resources.
    pub async fn list(&self, ctx: &ToolContext) -> Result<Vec<ResourceDefinition>> {
        let mut all_resources = Vec::new();
        for handler in &self.handlers {
            match handler.list(ctx).await {
                Ok(resources) => all_resources.extend(resources),
                Err(e) => {
                    tracing::warn!(
                        scheme = handler.scheme(),
                        error = %e,
                        "Failed to list resources"
                    );
                }
            }
        }
        Ok(all_resources)
    }

    /// Read a resource by URI, routing to the appropriate handler
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The URI format is invalid (missing scheme)
    /// - No handler is registered for the URI scheme
    /// - The handler fails to read the resource
    pub async fn read(&self, uri: &str, ctx: &ToolContext) -> Result<Vec<ResourceContent>> {
        let scheme = uri
            .split("://")
            .next()
            .ok_or_else(|| BridgeError::McpInvalidRequest(format!("Invalid URI: {uri}")))?;

        let handler = self
            .handlers
            .iter()
            .find(|h| h.scheme() == scheme)
            .ok_or_else(|| {
                BridgeError::McpInvalidRequest(format!("Unsupported resource scheme: {scheme}"))
            })?;

        handler.read(uri, ctx).await
    }

    /// Get the number of registered handlers
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Check if the registry is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

/// Create the default resource registry with all built-in resource handlers
#[must_use]
pub fn create_default_resource_registry() -> ResourceRegistry {
    use super::resources::{
        FileResourceHandler, HistoryResourceHandler, LogResourceHandler, MetricsResourceHandler,
        ServicesResourceHandler,
    };

    let mut registry = ResourceRegistry::new();

    registry.register(Arc::new(MetricsResourceHandler));
    registry.register(Arc::new(LogResourceHandler));
    registry.register(Arc::new(FileResourceHandler));
    registry.register(Arc::new(ServicesResourceHandler));
    registry.register(Arc::new(HistoryResourceHandler));

    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuditConfig, Config, LimitsConfig, SecurityConfig, SessionConfig, SshConfigDiscovery,
        ToolGroupsConfig,
    };
    use crate::domain::{ExecuteCommandUseCase, TunnelManager};
    use crate::mcp::CommandHistory;
    use crate::mcp::history::HistoryConfig;
    use crate::security::{AuditLogger, CommandValidator, RateLimiter, Sanitizer};
    use crate::ssh::{ConnectionPool, SessionManager};
    use std::collections::HashMap;

    fn create_test_context() -> ToolContext {
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
            rate_limiter: Arc::new(RateLimiter::new(0)),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            tunnel_manager: Arc::new(TunnelManager::new(20)),
            output_cache: None,
            runtime_max_output_chars: None,
        }
    }

    #[test]
    fn test_resource_registry_new() {
        let registry = ResourceRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_resource_registry_default() {
        let registry = ResourceRegistry::default();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_default_resource_registry_has_all_handlers() {
        let registry = create_default_resource_registry();
        assert_eq!(registry.len(), 5);
        assert!(!registry.is_empty());
    }

    #[tokio::test]
    async fn test_list_returns_resources() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        let resources = registry.list(&ctx).await.unwrap();
        // With no hosts configured, only host-independent resources are listed.
        // history://recent is always present regardless of host config.
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "history://recent");
    }

    #[tokio::test]
    async fn test_read_invalid_uri() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        let result = registry.read("invalid-no-scheme", &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_unsupported_scheme() {
        let registry = create_default_resource_registry();
        let ctx = create_test_context();

        let result = registry.read("ftp://server/file", &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(msg) => {
                assert!(msg.contains("ftp"));
            }
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
