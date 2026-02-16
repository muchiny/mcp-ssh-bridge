//! System Health Prompt Handler
//!
//! Provides a prompt for checking system health on a remote host.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::Result;
use crate::mcp::protocol::{PromptArgument, PromptMessage};
use crate::ports::{PromptHandler, ToolContext};

/// System health check prompt
pub struct SystemHealthPrompt;

#[async_trait]
impl PromptHandler for SystemHealthPrompt {
    fn name(&self) -> &'static str {
        "system-health"
    }

    fn description(&self) -> &'static str {
        "Check system health on a remote host (CPU, memory, disk, services)"
    }

    fn arguments(&self) -> Vec<PromptArgument> {
        vec![PromptArgument {
            name: "host".to_string(),
            description: "SSH host alias to check".to_string(),
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
            r#"Please check the health of host '{host}'. Run these diagnostic commands in order:

1. **System uptime and load:**
   ```
   uptime
   ```

2. **Memory usage:**
   ```
   free -h
   ```

3. **Disk usage:**
   ```
   df -h
   ```

4. **Failed systemd services (if applicable):**
   ```
   systemctl --failed 2>/dev/null || echo "systemctl not available"
   ```

5. **Top CPU-consuming processes:**
   ```
   ps aux --sort=-%cpu | head -10
   ```

After running these commands, provide a summary of:
- Overall system health status (healthy/warning/critical)
- Any concerning metrics (high CPU, low memory, disk space issues)
- Failed services that need attention
- Recommendations for any issues found"#
        ))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::PromptHandler;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_system_health_name() {
        let prompt = SystemHealthPrompt;
        assert_eq!(prompt.name(), "system-health");
    }

    #[test]
    fn test_system_health_description() {
        let prompt = SystemHealthPrompt;
        assert!(prompt.description().contains("health"));
    }

    #[test]
    fn test_system_health_arguments() {
        let prompt = SystemHealthPrompt;
        let args = prompt.arguments();
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].name, "host");
        assert!(args[0].required);
    }

    #[tokio::test]
    async fn test_system_health_prompt_with_host() {
        let prompt = SystemHealthPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "server1".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].role, "user");
        assert!(messages[0].content.text.contains("server1"));
        assert!(messages[0].content.text.contains("uptime"));
        assert!(messages[0].content.text.contains("free -h"));
    }

    #[tokio::test]
    async fn test_system_health_prompt_without_host() {
        let prompt = SystemHealthPrompt;
        let args = HashMap::new();

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert_eq!(messages.len(), 1);
        assert!(messages[0].content.text.contains("the target host"));
    }

    #[tokio::test]
    async fn test_system_health_prompt_contains_diagnostic_commands() {
        let prompt = SystemHealthPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "test-host".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        let text = &messages[0].content.text;
        assert!(text.contains("df -h"));
        assert!(text.contains("ps aux"));
        assert!(text.contains("systemctl"));
    }
}
