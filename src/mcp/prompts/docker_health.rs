//! Docker Health Prompt Handler
//!
//! Provides a comprehensive Docker health audit prompt for a remote host.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::Result;
use crate::mcp::protocol::{PromptArgument, PromptMessage};
use crate::ports::{PromptHandler, ToolContext};

/// Docker health audit prompt
pub struct DockerHealthPrompt;

#[async_trait]
impl PromptHandler for DockerHealthPrompt {
    fn name(&self) -> &'static str {
        "docker-health"
    }

    fn description(&self) -> &'static str {
        "Comprehensive Docker health audit: containers, images, stats, and recent logs"
    }

    fn arguments(&self) -> Vec<PromptArgument> {
        vec![PromptArgument {
            name: "host".to_string(),
            description: "SSH host alias running Docker".to_string(),
            required: true,
        }]
    }

    async fn get(
        &self,
        args: HashMap<String, String>,
        _ctx: &ToolContext,
    ) -> Result<Vec<PromptMessage>> {
        let host = args.get("host").map_or("the target host", String::as_str);

        Ok(vec![PromptMessage::user(format!(
            r"Please perform a comprehensive Docker health audit on host '{host}':

1. **Running containers** — Use `ssh_docker_ps` to list all containers with their status, ports, and uptime.

2. **Container resource usage** — Use `ssh_docker_stats` to check CPU, memory, and network I/O per container.

3. **Image inventory** — Use `ssh_docker_images` to list images. Flag any dangling or very old images that could be cleaned up.

4. **Recent logs from unhealthy containers** — For any container that is restarting, unhealthy, or exited, use `ssh_docker_logs` with `tail: 50` to check recent output.

5. **Disk usage** — Run `ssh_exec` with `docker system df` to check Docker's disk consumption (images, containers, volumes, build cache).

After collecting all data, provide:
- Overall Docker health status (healthy / warning / critical)
- Containers that need attention (restarting, high resource usage, errors in logs)
- Disk space recommendations (unused images, stopped containers to prune)
- Security observations (containers running as root, exposed ports, outdated images)"
        ))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_name() {
        let prompt = DockerHealthPrompt;
        assert_eq!(prompt.name(), "docker-health");
    }

    #[test]
    fn test_description() {
        let prompt = DockerHealthPrompt;
        assert!(prompt.description().contains("Docker"));
    }

    #[test]
    fn test_arguments() {
        let prompt = DockerHealthPrompt;
        let args = prompt.arguments();
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].name, "host");
        assert!(args[0].required);
    }

    #[tokio::test]
    async fn test_prompt_with_host() {
        let prompt = DockerHealthPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "docker-host".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].role, "user");
        assert!(messages[0].content.text.contains("docker-host"));
        assert!(messages[0].content.text.contains("ssh_docker_ps"));
        assert!(messages[0].content.text.contains("ssh_docker_stats"));
    }

    #[tokio::test]
    async fn test_prompt_without_host() {
        let prompt = DockerHealthPrompt;
        let args = HashMap::new();

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert!(messages[0].content.text.contains("the target host"));
    }
}
