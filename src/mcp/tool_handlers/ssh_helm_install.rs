//! SSH Helm Install Tool Handler
//!
//! Installs a Helm chart on a remote host via SSH.
//! Supports set values, values files, dry-run, wait, and namespace creation.
//! Auto-detects helm binary.

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::HelmCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshHelmInstallArgs {
    host: String,
    release: String,
    chart: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    set_values: Option<HashMap<String, String>>,
    #[serde(default)]
    values_files: Option<Vec<String>>,
    #[serde(default)]
    dry_run: Option<String>,
    #[serde(default)]
    wait: Option<bool>,
    #[serde(default)]
    create_namespace: Option<bool>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    helm_bin: Option<String>,
    #[serde(default)]
    kubeconfig: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshHelmInstallArgs);

pub struct HelmInstallTool;

impl StandardTool for HelmInstallTool {
    type Args = SshHelmInstallArgs;

    const NAME: &'static str = "ssh_helm_install";

    const DESCRIPTION: &'static str = "Install a new Helm chart on a remote host. For upgrading an existing release, use \
        ssh_helm_upgrade instead. Supports custom values (--set and values files), dry-run \
        validation, wait for readiness, and automatic namespace creation. Use ssh_helm_list \
        to verify the release was created. Auto-detects helm binary.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "release": {
                "type": "string",
                "description": "Helm release name"
            },
            "chart": {
                "type": "string",
                "description": "Chart reference (repo/chart or local path)"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (default: current context namespace)"
            },
            "set_values": {
                "type": "object",
                "description": "Key-value pairs for --set",
                "additionalProperties": { "type": "string" }
            },
            "values_files": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Paths to values YAML files on the remote host"
            },
            "dry_run": {
                "type": "string",
                "enum": ["none", "client", "server"],
                "description": "Dry-run mode: none (actually apply), client (local validation), server (server-side validation)"
            },
            "wait": {
                "type": "boolean",
                "description": "Wait for resources to be ready before marking release as successful"
            },
            "create_namespace": {
                "type": "boolean",
                "description": "Create namespace if it doesn't exist"
            },
            "version": {
                "type": "string",
                "description": "Chart version constraint"
            },
            "helm_bin": {
                "type": "string",
                "description": "Custom helm binary path (default: auto-detect)"
            },
            "kubeconfig": {
                "type": "string",
                "description": "Path to kubeconfig file (e.g., /etc/rancher/k3s/k3s.yaml for K3s)"
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
        "required": ["host", "release", "chart"]
    }"#;

    fn build_command(args: &SshHelmInstallArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(HelmCommandBuilder::build_install_command(
            args.helm_bin.as_deref(),
            args.kubeconfig.as_deref(),
            &args.release,
            &args.chart,
            args.namespace.as_deref(),
            args.set_values.as_ref(),
            args.values_files.as_deref(),
            args.dry_run.as_deref(),
            args.wait.unwrap_or(false),
            args.create_namespace.unwrap_or(false),
            args.version.as_deref(),
        ))
    }
}

/// Handler for the `ssh_helm_install` tool.
pub type SshHelmInstallHandler = StandardToolHandler<HelmInstallTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmInstallHandler::new();
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
        let handler = SshHelmInstallHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(
                Some(json!({
                    "host": "nonexistent",
                    "release": "my-app",
                    "chart": "stable/nginx"
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
        let handler = SshHelmInstallHandler::new();
        assert_eq!(handler.name(), "ssh_helm_install");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_install");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("release")));
        assert!(required.contains(&json!("chart")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "release": "my-app",
            "chart": "stable/nginx",
            "namespace": "production",
            "set_values": {"replicaCount": "3", "image.tag": "v2.0"},
            "values_files": ["/tmp/values.yaml"],
            "dry_run": "client",
            "wait": true,
            "create_namespace": true,
            "version": "1.2.3",
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 120,
            "max_output": 10000
        });

        let args: SshHelmInstallArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "my-app");
        assert_eq!(args.chart, "stable/nginx");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert!(args.set_values.is_some());
        let sv = args.set_values.unwrap();
        assert_eq!(sv.get("replicaCount"), Some(&"3".to_string()));
        assert_eq!(sv.get("image.tag"), Some(&"v2.0".to_string()));
        assert_eq!(
            args.values_files,
            Some(vec!["/tmp/values.yaml".to_string()])
        );
        assert_eq!(args.dry_run, Some("client".to_string()));
        assert_eq!(args.wait, Some(true));
        assert_eq!(args.create_namespace, Some(true));
        assert_eq!(args.version, Some("1.2.3".to_string()));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({
            "host": "server1",
            "release": "my-app",
            "chart": "stable/nginx"
        });

        let args: SshHelmInstallArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.release, "my-app");
        assert_eq!(args.chart, "stable/nginx");
        assert!(args.namespace.is_none());
        assert!(args.set_values.is_none());
        assert!(args.values_files.is_none());
        assert!(args.dry_run.is_none());
        assert!(args.wait.is_none());
        assert!(args.create_namespace.is_none());
        assert!(args.version.is_none());
        assert!(args.helm_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHelmInstallHandler::new();
        let ctx = create_test_context();

        // Missing chart field
        let result = handler
            .execute(Some(json!({"host": "server1", "release": "my-app"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmInstallHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("set_values"));
        assert!(properties.contains_key("values_files"));
        assert!(properties.contains_key("dry_run"));
        assert!(properties.contains_key("wait"));
        assert!(properties.contains_key("create_namespace"));
        assert!(properties.contains_key("version"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "release": "my-app", "chart": "stable/nginx"});
        let args: SshHelmInstallArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmInstallArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmInstallHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": 123, "release": "my-app", "chart": "stable/nginx"})),
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
