//! SSH Kubernetes Exec Tool Handler
//!
//! Executes a command inside a Kubernetes pod via `kubectl` on a remote host.
//! Runs commands in a specified container within the pod.
//! Auto-detects `kubectl` binary (k8s, k3s, microk8s).

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::KubernetesCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshK8sExecArgs {
    host: String,
    pod: String,
    command: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    container: Option<String>,
    #[serde(default)]
    kubectl_bin: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshK8sExecArgs);

pub struct K8sExecTool;

impl StandardTool for K8sExecTool {
    type Args = SshK8sExecArgs;

    const NAME: &'static str = "ssh_k8s_exec";

    const DESCRIPTION: &'static str = "Execute a command inside a Kubernetes pod via kubectl exec on a remote host. Use \
        ssh_k8s_get with resource 'pods' first to find pod names. The command runs inside the \
        pod container (e.g., 'cat /etc/config' or 'env'). For multi-container pods, specify \
        the container parameter. Auto-detects kubectl binary (k8s, k3s, microk8s). Returns \
        command stdout/stderr.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "pod": {
                "type": "string",
                "description": "Pod name to execute the command in"
            },
            "command": {
                "type": "string",
                "description": "Command to execute inside the pod"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace"
            },
            "container": {
                "type": "string",
                "description": "Container name for multi-container pods"
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
        "required": ["host", "pod", "command"]
    }"#;

    fn build_command(args: &SshK8sExecArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(KubernetesCommandBuilder::build_exec_command(
            args.kubectl_bin.as_deref(),
            &args.pod,
            &args.command,
            args.namespace.as_deref(),
            args.container.as_deref(),
        ))
    }
}

/// Handler for the `ssh_k8s_exec` tool.
pub type SshK8sExecHandler = StandardToolHandler<K8sExecTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshK8sExecHandler::new();
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
        let handler = SshK8sExecHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "pod": "my-pod",
                    "command": "ls -la"
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
        let handler = SshK8sExecHandler::new();
        assert_eq!(handler.name(), "ssh_k8s_exec");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_k8s_exec");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("pod")));
        assert!(required.contains(&json!("command")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "pod": "my-pod",
            "command": "cat /etc/hostname",
            "namespace": "production",
            "container": "app",
            "kubectl_bin": "k3s kubectl",
            "timeout_seconds": 30,
            "max_output": 5000
        });

        let args: SshK8sExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pod, "my-pod");
        assert_eq!(args.command, "cat /etc/hostname");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.container, Some("app".to_string()));
        assert_eq!(args.kubectl_bin, Some("k3s kubectl".to_string()));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "pod": "my-pod",
            "command": "ls -la"
        });

        let args: SshK8sExecArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.pod, "my-pod");
        assert_eq!(args.command, "ls -la");
        assert!(args.namespace.is_none());
        assert!(args.container.is_none());
        assert!(args.kubectl_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshK8sExecHandler::new();
        let ctx = create_test_context();

        // Missing command field
        let result = handler
            .execute(
                Some(json!({
                    "host": "server1",
                    "pod": "my-pod"
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

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshK8sExecHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();

        // Check ALL optional fields exist in schema
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("container"));
        assert!(properties.contains_key("kubectl_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "pod": "my-pod", "command": "ls -la"});
        let args: SshK8sExecArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshK8sExecArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshK8sExecHandler::new();
        let ctx = create_test_context();
        // Pass integer where string is expected for host
        let result = handler
            .execute(
                Some(json!({"host": 123, "pod": "my-pod", "command": "ls -la"})),
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
