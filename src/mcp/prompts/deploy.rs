//! Deploy Prompt Handler
//!
//! Provides a prompt for deploying applications to a remote host.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::Result;
use crate::mcp::protocol::{PromptArgument, PromptMessage};
use crate::ports::{PromptHandler, ToolContext};

/// Application deployment prompt
pub struct DeployPrompt;

#[async_trait]
impl PromptHandler for DeployPrompt {
    fn name(&self) -> &'static str {
        "deploy"
    }

    fn description(&self) -> &'static str {
        "Deploy or update an application on a remote host"
    }

    fn arguments(&self) -> Vec<PromptArgument> {
        vec![
            PromptArgument {
                name: "host".to_string(),
                description: "SSH host alias to deploy to".to_string(),
                required: true,
            },
            PromptArgument {
                name: "app".to_string(),
                description: "Application or service name".to_string(),
                required: true,
            },
            PromptArgument {
                name: "version".to_string(),
                description: "Version to deploy (optional, defaults to latest)".to_string(),
                required: false,
            },
        ]
    }

    async fn get(
        &self,
        args: HashMap<String, String>,
        _ctx: &ToolContext,
    ) -> Result<Vec<PromptMessage>> {
        let host = args.get("host").map_or("the target host", String::as_str);
        let app = args.get("app").map_or("the application", String::as_str);
        let version = args.get("version").map_or("latest", String::as_str);

        Ok(vec![PromptMessage::user(format!(
            r"Please help me deploy '{app}' version '{version}' to host '{host}'.

Before deploying, please:

1. **Check current deployment status:**
   - Is '{app}' already running?
   - What version is currently deployed?
   - Are there any running processes or containers?

2. **Verify prerequisites:**
   - Check disk space availability
   - Verify network connectivity
   - Ensure required dependencies are present

3. **Perform the deployment:**
   - Pull/download the new version
   - Stop the current version gracefully
   - Deploy the new version
   - Start the service
   - Verify the service is healthy

4. **Post-deployment verification:**
   - Check service status
   - Verify logs for startup errors
   - Confirm the correct version is running

Please provide clear status updates at each step and alert me immediately if any issues occur.

If this is a Docker/container deployment, use appropriate docker commands.
If this is a systemd service, use appropriate systemctl commands.
If this is a Kubernetes deployment, use appropriate kubectl commands."
        ))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::PromptHandler;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_deploy_name() {
        let prompt = DeployPrompt;
        assert_eq!(prompt.name(), "deploy");
    }

    #[test]
    fn test_deploy_description() {
        let prompt = DeployPrompt;
        assert!(prompt.description().contains("Deploy"));
    }

    #[test]
    fn test_deploy_arguments() {
        let prompt = DeployPrompt;
        let args = prompt.arguments();
        assert_eq!(args.len(), 3);

        // Check required arguments
        let host_arg = args.iter().find(|a| a.name == "host").unwrap();
        assert!(host_arg.required);

        let app_arg = args.iter().find(|a| a.name == "app").unwrap();
        assert!(app_arg.required);

        let version_arg = args.iter().find(|a| a.name == "version").unwrap();
        assert!(!version_arg.required);
    }

    #[tokio::test]
    async fn test_deploy_prompt_with_all_args() {
        let prompt = DeployPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "production".to_string());
        args.insert("app".to_string(), "my-api".to_string());
        args.insert("version".to_string(), "v2.1.0".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert_eq!(messages.len(), 1);
        let text = &messages[0].content.text;
        assert!(text.contains("my-api"));
        assert!(text.contains("v2.1.0"));
        assert!(text.contains("production"));
    }

    #[tokio::test]
    async fn test_deploy_prompt_defaults_to_latest() {
        let prompt = DeployPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "staging".to_string());
        args.insert("app".to_string(), "web-service".to_string());
        // No version specified

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        let text = &messages[0].content.text;
        assert!(text.contains("latest"));
    }

    #[tokio::test]
    async fn test_deploy_prompt_contains_deployment_steps() {
        let prompt = DeployPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "server".to_string());
        args.insert("app".to_string(), "app".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        let text = &messages[0].content.text;
        assert!(text.contains("Check current deployment"));
        assert!(text.contains("Verify prerequisites"));
        assert!(text.contains("Perform the deployment"));
        assert!(text.contains("Post-deployment verification"));
    }

    #[tokio::test]
    async fn test_deploy_prompt_mentions_container_options() {
        let prompt = DeployPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "host".to_string());
        args.insert("app".to_string(), "app".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        let text = &messages[0].content.text;
        assert!(text.contains("Docker"));
        assert!(text.contains("systemd"));
        assert!(text.contains("Kubernetes"));
    }
}
