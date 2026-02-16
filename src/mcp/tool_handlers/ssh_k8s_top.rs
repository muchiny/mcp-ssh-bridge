//! SSH Kubernetes Top Tool Handler
//!
//! Displays resource usage (CPU/memory) of pods or nodes via `kubectl` top on a remote host.
//! Requires metrics-server. Auto-detects `kubectl` binary (k8s, k3s, microk8s).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshK8sTopArgs {
    host: String,
    resource_type: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    sort_by: Option<String>,
    #[serde(default)]
    containers: Option<bool>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sTopArgs);

pub struct K8sTopTool;

impl StandardTool for K8sTopTool {
    type Args = SshK8sTopArgs;

    const NAME: &'static str = "ssh_k8s_top";

    const DESCRIPTION: &'static str = "Display real-time CPU and memory usage of pods or nodes via kubectl top on a remote \
        host. Requires metrics-server to be installed in the cluster. Set resource_type to \
        'pods' or 'nodes'. Sort by 'cpu' or 'memory' to find resource-intensive workloads. \
        For host-level metrics (outside k8s), use ssh_metrics instead. Auto-detects kubectl \
        binary (k8s, k3s, microk8s).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "resource_type": {
                "type": "string",
                "enum": ["pods", "nodes"],
                "description": "Resource type to show metrics for"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (for pods only)"
            },
            "sort_by": {
                "type": "string",
                "enum": ["cpu", "memory"],
                "description": "Sort output by CPU or memory usage"
            },
            "containers": {
                "type": "boolean",
                "description": "Show container-level metrics (for pods only)"
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
        "required": ["host", "resource_type"]
    }"#;

    fn build_command(args: &SshK8sTopArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(KubernetesCommandBuilder::build_top_command(
            args.kubectl_bin.as_deref(),
            &args.resource_type,
            args.namespace.as_deref(),
            args.sort_by.as_deref(),
            args.containers.unwrap_or(false),
        ))
    }

    fn validate(args: &SshK8sTopArgs, _host_config: &HostConfig) -> Result<()> {
        KubernetesCommandBuilder::validate_top_resource(&args.resource_type)?;
        Ok(())
    }
}

/// Handler for the `ssh_k8s_top` tool.
pub type SshK8sTopHandler = StandardToolHandler<K8sTopTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::{create_test_context, create_test_context_with_host};
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshK8sTopHandler::new();
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
        let handler = SshK8sTopHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "resource_type": "pods"
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
        let handler = SshK8sTopHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_top");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_top");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("resource_type")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "resource_type": "pods",
            "namespace": "production",
            "sort_by": "cpu",
            "containers": true,
            "kubectl_bin": "k3s kubectl",
            "timeout_seconds": 30,
            "max_output": 10000
        });

        let args: SshK8sTopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource_type, "pods");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.sort_by, Some("cpu".to_string()));
        assert_eq!(args.containers, Some(true));
        assert_eq!(args.kubectl_bin, Some("k3s kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "resource_type": "nodes"
        });

        let args: SshK8sTopArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource_type, "nodes");
        assert!(args.namespace.is_none());
        assert!(args.sort_by.is_none());
        assert!(args.containers.is_none());
        assert!(args.kubectl_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sTopHandler::new();
        let ctx = create_test_context();

        // Missing resource_type field
        let result = handler
            .execute(Some(json!({"host": "server1"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_resource_type() {
        let handler = SshK8sTopHandler::new();
        let ctx = create_test_context_with_host();

        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "resource_type": "deployments"
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
        let handler = SshK8sTopHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("sort_by"));
        assert!(properties.contains_key("containers"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "resource_type": "pods"});
        let args: SshK8sTopArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sTopArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sTopHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host
        let result = handler
            .execute(Some(json!({"host": 123, "resource_type": "pods"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
