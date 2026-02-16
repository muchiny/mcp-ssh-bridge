//! SSH Kubernetes Delete Tool Handler
//!
//! Deletes a Kubernetes resource via `kubectl` on a remote host.
//! Includes safety validation to prevent deletion of protected namespaces.
//! Auto-detects `kubectl` binary (k8s, k3s, microk8s).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshK8sDeleteArgs {
    host: String,
    resource: String,
    name: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    grace_period: Option<u64>,
    #[serde(default)]
    force: Option<bool>,
    #[serde(default)]
    dry_run: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sDeleteArgs);

pub struct K8sDeleteTool;

impl StandardTool for K8sDeleteTool {
    type Args = SshK8sDeleteArgs;

    const NAME: &'static str = "ssh_k8s_delete";

    const DESCRIPTION: &'static str = "Delete a Kubernetes resource via kubectl on a remote host. Protected namespaces \
        (kube-system, kube-public, default) cannot be deleted. Supports dry-run to preview \
        deletions safely. Use ssh_k8s_get first to verify the resource exists. Auto-detects \
        kubectl binary (k8s, k3s, microk8s).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "resource": {
                "type": "string",
                "description": "Kubernetes resource type (e.g., pod, deployment, service, namespace)"
            },
            "name": {
                "type": "string",
                "description": "Name of the resource to delete"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace"
            },
            "grace_period": {
                "type": "integer",
                "description": "Grace period in seconds before force deletion"
            },
            "force": {
                "type": "boolean",
                "description": "Force deletion without waiting for graceful termination"
            },
            "dry_run": {
                "type": "string",
                "enum": ["none", "client", "server"],
                "description": "Dry-run mode: none (actually delete), client (local validation), server (server-side validation)"
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
        "required": ["host", "resource", "name"]
    }"#;

    fn build_command(args: &SshK8sDeleteArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(KubernetesCommandBuilder::build_delete_command(
            args.kubectl_bin.as_deref(),
            &args.resource,
            &args.name,
            args.namespace.as_deref(),
            args.grace_period,
            args.force.unwrap_or(false),
            args.dry_run.as_deref(),
        ))
    }

    fn validate(args: &SshK8sDeleteArgs, _host_config: &HostConfig) -> Result<()> {
        KubernetesCommandBuilder::validate_delete(&args.resource, &args.name)?;
        Ok(())
    }
}

/// Handler for the `ssh_k8s_delete` tool.
pub type SshK8sDeleteHandler = StandardToolHandler<K8sDeleteTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshK8sDeleteHandler::new();
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
        let handler = SshK8sDeleteHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "resource": "pod",
                    "name": "my-pod"
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
        let handler = SshK8sDeleteHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_delete");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_delete");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("resource")));
        assert!(required.contains(&json!("name")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "resource": "deployment",
            "name": "my-app",
            "namespace": "production",
            "grace_period": 30,
            "force": true,
            "dry_run": "client",
            "kubectl_bin": "k3s kubectl",
            "timeout_seconds": 60,
            "max_output": 5000
        });

        let args: SshK8sDeleteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "deployment");
        assert_eq!(args.name, "my-app");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.grace_period, Some(30));
        assert_eq!(args.force, Some(true));
        assert_eq!(args.dry_run, Some("client".to_string()));
        assert_eq!(args.kubectl_bin, Some("k3s kubectl".to_string()));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "resource": "pod",
            "name": "my-pod"
        });

        let args: SshK8sDeleteArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "pod");
        assert_eq!(args.name, "my-pod");
        assert!(args.namespace.is_none());
        assert!(args.grace_period.is_none());
        assert!(args.force.is_none());
        assert!(args.dry_run.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sDeleteHandler::new();
        let ctx = create_test_context();

        // Missing name field
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "resource": "pod"
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
    async fn test_delete_protected_namespace() {
        let handler = SshK8sDeleteHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "resource": "namespace",
                    "name": "kube-system"
                })),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::CommandDenied { reason } => {
                assert!(reason.contains("kube-system"));
            }
            e => panic!("Expected CommandDenied, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sDeleteHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("grace_period"));
        assert!(properties.contains_key("force"));
        assert!(properties.contains_key("dry_run"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "resource": "pod", "name": "my-pod"});
        let args: SshK8sDeleteArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sDeleteArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sDeleteHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host
        let result = handler
            .execute(
                Some(json!({"host": 123, "resource": "pod", "name": "my-pod"})),
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
