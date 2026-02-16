//! Troubleshoot Prompt Handler
//!
//! Provides a systematic diagnostic prompt for a remote host.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::Result;
use crate::mcp::protocol::{PromptArgument, PromptMessage};
use crate::ports::{PromptHandler, ToolContext};

/// Systematic troubleshooting prompt
pub struct TroubleshootPrompt;

#[async_trait]
impl PromptHandler for TroubleshootPrompt {
    fn name(&self) -> &'static str {
        "troubleshoot"
    }

    fn description(&self) -> &'static str {
        "Systematic diagnostic: logs, metrics, processes, and network on a remote host"
    }

    fn arguments(&self) -> Vec<PromptArgument> {
        vec![PromptArgument {
            name: "host".to_string(),
            description: "SSH host alias to diagnose".to_string(),
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
            r#"Please perform a systematic diagnostic of host '{host}'. Follow these steps in order:

1. **System overview** — Use `ssh_metrics` to get CPU, memory, disk, and load.

2. **Recent logs** — Use `ssh_tail` on `/var/log/syslog` (or `/var/log/messages`) with `lines: 200` and `grep: "error|warn|crit|fail"` (case-insensitive).

3. **Running processes** — Use `ssh_process_top` to identify the top CPU and memory consumers.

4. **Network status** — Use `ssh_net_connections` to check listening ports and established connections.

5. **Service health** — Use `ssh_service_list` to find any failed or inactive services.

6. **Disk I/O** — Run `ssh_exec` with `iostat -x 1 3` (if available) to check for I/O bottlenecks.

After collecting all data, provide:
- A severity assessment (healthy / warning / critical)
- Root cause hypothesis for any issues found
- Prioritized remediation steps
- Anything that needs immediate attention"#
        ))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_name() {
        let prompt = TroubleshootPrompt;
        assert_eq!(prompt.name(), "troubleshoot");
    }

    #[test]
    fn test_description() {
        let prompt = TroubleshootPrompt;
        assert!(prompt.description().contains("diagnostic"));
    }

    #[test]
    fn test_arguments() {
        let prompt = TroubleshootPrompt;
        let args = prompt.arguments();
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].name, "host");
        assert!(args[0].required);
    }

    #[tokio::test]
    async fn test_prompt_with_host() {
        let prompt = TroubleshootPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "web-server".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].role, "user");
        assert!(messages[0].content.text.contains("web-server"));
        assert!(messages[0].content.text.contains("ssh_metrics"));
        assert!(messages[0].content.text.contains("ssh_tail"));
    }

    #[tokio::test]
    async fn test_prompt_without_host() {
        let prompt = TroubleshootPrompt;
        let args = HashMap::new();

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert!(messages[0].content.text.contains("the target host"));
    }
}
