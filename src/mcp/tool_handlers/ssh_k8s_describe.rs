//! SSH Kubernetes Describe Tool Handler
//!
//! Describes a Kubernetes resource in detail via `kubectl` on a remote host.
//! Auto-detects kubectl binary (k8s, k3s, microk8s).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshK8sDescribeArgs {
    host: String,
    resource: String,
    name: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshK8sDescribeArgs);

pub struct K8sDescribeTool;

impl StandardTool for K8sDescribeTool {
    type Args = SshK8sDescribeArgs;

    const NAME: &'static str = "ssh_k8s_describe";

    const DESCRIPTION: &'static str = "Describe a Kubernetes resource in detail via kubectl on a remote host. Use \
        ssh_k8s_get first to find resource names. Returns detailed text output including \
        events, conditions, status, labels, annotations, and full specification. Useful for \
        debugging pod failures or understanding resource configuration. Auto-detects kubectl \
        binary (k8s, k3s, microk8s).";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "resource": {
                "type": "string",
                "description": "Kubernetes resource type (pod, deployment, service, node, etc.)"
            },
            "name": {
                "type": "string",
                "description": "Name of the resource to describe"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace"
            },
            "kubectl_bin": {
                "type": "string",
                "description": "kubectl binary path or command (default: auto-detect k8s/k3s/microk8s)"
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
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "resource", "name"]
    }"#;

    fn build_command(args: &SshK8sDescribeArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(KubernetesCommandBuilder::build_describe_command(
            args.kubectl_bin.as_deref(),
            &args.resource,
            &args.name,
            args.namespace.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_describe` tool.
pub type SshK8sDescribeHandler = StandardToolHandler<K8sDescribeTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshK8sDescribeHandler::new();
        let ctx = create_test_context();

        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => {
                assert_eq!(param, "arguments");
            }
            e => panic!("Expected McpMissingParam error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshK8sDescribeHandler::new();
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
            e => panic!("Expected UnknownHost error, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshK8sDescribeHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_describe");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_describe");

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
            "kubectl_bin": "/usr/local/bin/kubectl",
            "timeout_seconds": 120,
            "max_output": 5000
        });

        let args: SshK8sDescribeArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "deployment");
        assert_eq!(args.name, "my-app");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.kubectl_bin, Some("/usr/local/bin/kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "resource": "pod",
            "name": "my-pod"
        });

        let args: SshK8sDescribeArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.resource, "pod");
        assert_eq!(args.name, "my-pod");
        assert!(args.namespace.is_none());
        assert!(args.kubectl_bin.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sDescribeHandler::new();
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
            e => panic!("Expected McpInvalidRequest error, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sDescribeHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "resource": "pod", "name": "my-pod"});
        let args: SshK8sDescribeArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sDescribeArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sDescribeHandler::new();
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
