//! SSH Kubernetes Rollout Tool Handler
//!
//! Manages Kubernetes rollouts via `kubectl` on a remote host.
//! Supports status, restart, undo, and history actions.
//! Auto-detects `kubectl` binary (k8s, k3s, microk8s).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshK8sRolloutArgs {
    host: String,
    action: String,
    resource: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    to_revision: Option<u64>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sRolloutArgs);

pub struct K8sRolloutTool;

impl StandardTool for K8sRolloutTool {
    type Args = SshK8sRolloutArgs;

    const NAME: &'static str = "ssh_k8s_rollout";

    const DESCRIPTION: &'static str = "Manage Kubernetes rollouts via kubectl on a remote host. Actions: status (check \
        progress), restart (rolling restart), undo (rollback to previous revision), history \
        (view revision history). Use after ssh_k8s_apply to monitor deployments. Resource \
        format: 'deployment/myapp'. Auto-detects kubectl binary (k8s, k3s, microk8s).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "action": {
                "type": "string",
                "enum": ["status", "restart", "undo", "history"],
                "description": "Rollout action to perform"
            },
            "resource": {
                "type": "string",
                "description": "Resource path e.g. deployment/myapp"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace"
            },
            "to_revision": {
                "type": "integer",
                "description": "Revision to rollback to (for undo action)"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "Custom kubectl binary path (default: auto-detect kubectl, k3s kubectl, microk8s kubectl)"
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Optional timeout in seconds (default: from config)",
                "minimum": 1,
                "maximum": 3600
            },
            "max_output": {
                "type": "integer",
                "description": "Max output characters (default: from server config, typically 20000, 0 = no limit). Truncated output includes an output_id for retrieval via ssh_output_fetch.",
                "minimum": 0
            }
        },
        "required": ["host", "action", "resource"]
    }"#;

    fn build_command(args: &SshK8sRolloutArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(KubernetesCommandBuilder::build_rollout_command(
            args.kubectl_bin.as_deref(),
            &args.action,
            &args.resource,
            args.namespace.as_deref(),
            args.to_revision,
        ))
    }

    fn validate(args: &SshK8sRolloutArgs, _host_config: &HostConfig) -> Result<()> {
        KubernetesCommandBuilder::validate_rollout_action(&args.action)?;
        Ok(())
    }
}

/// Handler for the `ssh_k8s_rollout` tool.
pub type SshK8sRolloutHandler = StandardToolHandler<K8sRolloutTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshK8sRolloutHandler::new();
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshK8sRolloutHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "action": "status",
                    "resource": "deployment/myapp"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => {
                assert_eq!(host, "nonexistent");
            }
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK8sRolloutHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_rollout");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_rollout");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("action")));
        assert!(required.contains(&json!("resource")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "action": "undo",
            "resource": "deployment/myapp",
            "namespace": "production",
            "to_revision": 3,
            "kubectl_bin": "k3s kubectl",
            "timeout_seconds": 120,
            "max_output": 10000
        });

        let args: SshK8sRolloutArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.action, "undo");
        assert_eq!(args.resource, "deployment/myapp");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.to_revision, Some(3));
        assert_eq!(args.kubectl_bin, Some("k3s kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "action": "status",
            "resource": "deployment/myapp"
        });

        let args: SshK8sRolloutArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.action, "status");
        assert_eq!(args.resource, "deployment/myapp");
        assert!(args.namespace.is_none());
        assert!(args.to_revision.is_none());
        assert!(args.kubectl_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sRolloutHandler::new();
        let ctx = create_test_context();

        // Missing resource field
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "action": "status"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_rollout_action() {
        let handler = SshK8sRolloutHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "action": "pause",
                    "resource": "deployment/myapp"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { .. } => {}
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sRolloutHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("to_revision"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "action": "status", "resource": "deployment/myapp"});
        let args: SshK8sRolloutArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sRolloutArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sRolloutHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host
        let result = handler
            .execute(
                Some(json!({"host": 123, "action": "status", "resource": "deployment/myapp"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
