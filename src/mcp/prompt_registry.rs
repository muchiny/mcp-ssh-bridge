//! Prompt Registry
//!
//! Manages registration and lookup of MCP prompt handlers.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{BridgeError, Result};
use crate::mcp::protocol::{PromptDefinition, PromptMessage};
use crate::ports::{PromptHandler, ToolContext};

/// Registry for MCP prompt handlers
#[derive(Default)]
pub struct PromptRegistry {
    prompts: HashMap<&'static str, Arc<dyn PromptHandler>>,
}

impl PromptRegistry {
    /// Create a new empty registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            prompts: HashMap::new(),
        }
    }

    /// Register a prompt handler
    pub fn register(&mut self, handler: Arc<dyn PromptHandler>) {
        self.prompts.insert(handler.name(), handler);
    }

    /// Get a prompt handler by name
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Arc<dyn PromptHandler>> {
        self.prompts.get(name)
    }

    /// List all registered prompts
    #[must_use]
    pub fn list(&self) -> Vec<PromptDefinition> {
        self.prompts
            .values()
            .map(|h| PromptDefinition {
                name: h.name().to_string(),
                description: h.description().to_string(),
                arguments: h.arguments(),
            })
            .collect()
    }

    /// Execute a prompt and get the messages
    ///
    /// # Errors
    ///
    /// Returns an error if the prompt name is unknown or if the prompt
    /// handler fails to generate messages.
    pub async fn get_messages(
        &self,
        name: &str,
        args: HashMap<String, String>,
        ctx: &ToolContext,
    ) -> Result<Vec<PromptMessage>> {
        let handler = self
            .get(name)
            .ok_or_else(|| BridgeError::McpInvalidRequest(format!("Unknown prompt: {name}")))?;

        handler.get(args, ctx).await
    }

    /// Get the number of registered prompts
    #[must_use]
    pub fn len(&self) -> usize {
        self.prompts.len()
    }

    /// Check if the registry is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prompts.is_empty()
    }
}

/// Create the default prompt registry with all built-in prompts
#[must_use]
pub fn create_default_prompt_registry() -> PromptRegistry {
    use super::prompts::{
        BackupVerifyPrompt, DeployPrompt, DockerHealthPrompt, K8sOverviewPrompt,
        SecurityAuditPrompt, SystemHealthPrompt, TroubleshootPrompt,
    };

    let mut registry = PromptRegistry::new();

    registry.register(Arc::new(SystemHealthPrompt));
    registry.register(Arc::new(DeployPrompt));
    registry.register(Arc::new(SecurityAuditPrompt));
    registry.register(Arc::new(TroubleshootPrompt));
    registry.register(Arc::new(DockerHealthPrompt));
    registry.register(Arc::new(K8sOverviewPrompt));
    registry.register(Arc::new(BackupVerifyPrompt));

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_registry_new() {
        let registry = PromptRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_prompt_registry_default() {
        let registry = PromptRegistry::default();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_default_prompt_registry_has_all_prompts() {
        let registry = create_default_prompt_registry();

        assert_eq!(registry.len(), 7);
        assert!(!registry.is_empty());

        // Verify all prompts are registered
        assert!(registry.get("system-health").is_some());
        assert!(registry.get("deploy").is_some());
        assert!(registry.get("security-audit").is_some());
        assert!(registry.get("troubleshoot").is_some());
        assert!(registry.get("docker-health").is_some());
        assert!(registry.get("k8s-overview").is_some());
        assert!(registry.get("backup-verify").is_some());
    }

    #[test]
    fn test_prompt_registry_list() {
        let registry = create_default_prompt_registry();
        let prompts = registry.list();

        assert_eq!(prompts.len(), 7);

        let names: Vec<&str> = prompts.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"system-health"));
        assert!(names.contains(&"deploy"));
        assert!(names.contains(&"security-audit"));
        assert!(names.contains(&"troubleshoot"));
        assert!(names.contains(&"docker-health"));
        assert!(names.contains(&"k8s-overview"));
        assert!(names.contains(&"backup-verify"));
    }

    #[test]
    fn test_prompt_registry_get_nonexistent() {
        let registry = create_default_prompt_registry();
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_prompts_have_descriptions() {
        let registry = create_default_prompt_registry();
        let prompts = registry.list();

        for prompt in prompts {
            assert!(
                !prompt.description.is_empty(),
                "Prompt {} has no description",
                prompt.name
            );
        }
    }

    #[test]
    fn test_system_health_prompt_has_host_argument() {
        let registry = create_default_prompt_registry();
        let prompts = registry.list();

        let system_health = prompts.iter().find(|p| p.name == "system-health").unwrap();
        assert_eq!(system_health.arguments.len(), 1);
        assert_eq!(system_health.arguments[0].name, "host");
        assert!(system_health.arguments[0].required);
    }

    #[test]
    fn test_deploy_prompt_has_correct_arguments() {
        let registry = create_default_prompt_registry();
        let prompts = registry.list();

        let deploy = prompts.iter().find(|p| p.name == "deploy").unwrap();
        assert_eq!(deploy.arguments.len(), 3);

        let arg_names: Vec<&str> = deploy.arguments.iter().map(|a| a.name.as_str()).collect();
        assert!(arg_names.contains(&"host"));
        assert!(arg_names.contains(&"app"));
        assert!(arg_names.contains(&"version"));
    }

    #[test]
    fn test_security_audit_prompt_has_correct_arguments() {
        let registry = create_default_prompt_registry();
        let prompts = registry.list();

        let audit = prompts.iter().find(|p| p.name == "security-audit").unwrap();
        assert_eq!(audit.arguments.len(), 2);

        let arg_names: Vec<&str> = audit.arguments.iter().map(|a| a.name.as_str()).collect();
        assert!(arg_names.contains(&"host"));
        assert!(arg_names.contains(&"scope"));
    }
}
