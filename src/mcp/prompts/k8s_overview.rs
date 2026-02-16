//! Kubernetes Overview Prompt Handler
//!
//! Provides a Kubernetes cluster overview prompt for a remote host.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::error::Result;
use crate::mcp::protocol::{PromptArgument, PromptMessage};
use crate::ports::{PromptHandler, ToolContext};

/// Kubernetes cluster overview prompt
pub struct K8sOverviewPrompt;

#[async_trait]
impl PromptHandler for K8sOverviewPrompt {
    fn name(&self) -> &'static str {
        "k8s-overview"
    }

    fn description(&self) -> &'static str {
        "Kubernetes cluster overview: pods, services, events, and resource usage"
    }

    fn arguments(&self) -> Vec<PromptArgument> {
        vec![
            PromptArgument {
                name: "host".to_string(),
                description: "SSH host alias with kubectl access".to_string(),
                required: true,
            },
            PromptArgument {
                name: "namespace".to_string(),
                description: "Kubernetes namespace (default: all namespaces)".to_string(),
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
        let ns_hint = args.get("namespace").map_or_else(
            || "across all namespaces (use `--all-namespaces` or `-A`)".to_string(),
            |ns| format!("in namespace '{ns}'"),
        );

        Ok(vec![PromptMessage::user(format!(
            r#"Please provide a Kubernetes cluster overview on host '{host}' {ns_hint}:

1. **Pod status** — Use `ssh_k8s_get` with `resource: "pods"` to list all pods, their status, restarts, and age.

2. **Services and endpoints** — Use `ssh_k8s_get` with `resource: "services"` to list services, types, and cluster IPs.

3. **Recent events** — Use `ssh_k8s_get` with `resource: "events"` and `extra_args: "--sort-by=.lastTimestamp"` to find warnings and errors.

4. **Resource usage** — Use `ssh_k8s_top` with `resource: "pods"` to check CPU and memory consumption per pod.

5. **Node health** — Use `ssh_k8s_get` with `resource: "nodes"` to check node status and conditions.

6. **Problem pods** — For any pod in CrashLoopBackOff or Error state, use `ssh_k8s_logs` with `tail: 50` to check recent logs, and `ssh_k8s_describe` for events.

After collecting all data, provide:
- Cluster health summary (healthy / degraded / critical)
- Pods needing attention (crash loops, high restarts, pending)
- Resource pressure warnings (nodes or pods near limits)
- Recent concerning events and their likely causes
- Recommended actions prioritized by urgency"#
        ))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock::create_test_context;

    #[test]
    fn test_name() {
        let prompt = K8sOverviewPrompt;
        assert_eq!(prompt.name(), "k8s-overview");
    }

    #[test]
    fn test_description() {
        let prompt = K8sOverviewPrompt;
        assert!(prompt.description().contains("Kubernetes"));
    }

    #[test]
    fn test_arguments() {
        let prompt = K8sOverviewPrompt;
        let args = prompt.arguments();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].name, "host");
        assert!(args[0].required);
        assert_eq!(args[1].name, "namespace");
        assert!(!args[1].required);
    }

    #[tokio::test]
    async fn test_prompt_with_host() {
        let prompt = K8sOverviewPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "k8s-master".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].role, "user");
        assert!(messages[0].content.text.contains("k8s-master"));
        assert!(messages[0].content.text.contains("ssh_k8s_get"));
        assert!(messages[0].content.text.contains("all namespaces"));
    }

    #[tokio::test]
    async fn test_prompt_with_namespace() {
        let prompt = K8sOverviewPrompt;
        let mut args = HashMap::new();
        args.insert("host".to_string(), "k8s-master".to_string());
        args.insert("namespace".to_string(), "production".to_string());

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert!(messages[0].content.text.contains("production"));
        assert!(!messages[0].content.text.contains("all namespaces"));
    }

    #[tokio::test]
    async fn test_prompt_without_host() {
        let prompt = K8sOverviewPrompt;
        let args = HashMap::new();

        let ctx = create_test_context();
        let messages = prompt.get(args, &ctx).await.unwrap();

        assert!(messages[0].content.text.contains("the target host"));
    }
}
