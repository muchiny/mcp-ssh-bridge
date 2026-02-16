//! SSH Helm List Tool Handler
//!
//! Lists Helm releases on a remote host via SSH.
//! Supports filtering by namespace, name pattern, and output format.
//! Auto-detects helm binary.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::kubernetes::HelmCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshHelmListArgs {
    host: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    all_namespaces: Option<bool>,
    #[serde(default)]
    all: Option<bool>,
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    output: Option<String>,
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

impl_common_args!(SshHelmListArgs);

pub struct HelmListTool;

impl StandardTool for HelmListTool {
    type Args = SshHelmListArgs;

    const NAME: &'static str = "ssh_helm_list";

    const DESCRIPTION: &'static str = "List Helm releases on a remote host. Start here to discover installed releases before \
        using ssh_helm_status, ssh_helm_upgrade, or ssh_helm_rollback. Supports filtering by \
        namespace and name pattern. Output as table, JSON, or YAML. Auto-detects helm binary.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "The SSH host alias as defined in the configuration"
            },
            "namespace": {
                "type": "string",
                "description": "Kubernetes namespace (default: current context namespace)"
            },
            "all_namespaces": {
                "type": "boolean",
                "description": "List across all namespaces"
            },
            "all": {
                "type": "boolean",
                "description": "Show all releases including failed/pending"
            },
            "filter": {
                "type": "string",
                "description": "Filter by release name regex"
            },
            "output": {
                "type": "string",
                "enum": ["table", "json", "yaml"],
                "description": "Output format (default: table)"
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
        "required": ["host"]
    }"#;

    fn build_command(args: &SshHelmListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(HelmCommandBuilder::build_list_command(
            args.helm_bin.as_deref(),
            args.kubeconfig.as_deref(),
            args.namespace.as_deref(),
            args.all_namespaces.unwrap_or(false),
            args.all.unwrap_or(false),
            args.filter.as_deref(),
            args.output.as_deref(),
        ))
    }
}

/// Handler for the `ssh_helm_list` tool.
pub type SshHelmListHandler = StandardToolHandler<HelmListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshHelmListHandler::new();
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
        let handler = SshHelmListHandler::new();
        let ctx = create_test_context();

        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
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
        let handler = SshHelmListHandler::new();
        assert_eq!(handler.name(), "ssh_helm_list");
        assert!(!handler.description().is_empty());

        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_helm_list");

        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "namespace": "production",
            "all_namespaces": true,
            "all": true,
            "filter": "my-app.*",
            "output": "json",
            "helm_bin": "/usr/local/bin/helm",
            "timeout_seconds": 60,
            "max_output": 10000
        });

        let args: SshHelmListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.namespace, Some("production".to_string()));
        assert_eq!(args.all_namespaces, Some(true));
        assert_eq!(args.all, Some(true));
        assert_eq!(args.filter, Some("my-app.*".to_string()));
        assert_eq!(args.output, Some("json".to_string()));
        assert_eq!(args.helm_bin, Some("/usr/local/bin/helm".to_string()));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(10000));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});

        let args: SshHelmListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.namespace.is_none());
        assert!(args.all_namespaces.is_none());
        assert!(args.all.is_none());
        assert!(args.filter.is_none());
        assert!(args.output.is_none());
        assert!(args.helm_bin.is_none());
    }

    #[tokio::test]
    async fn test_missing_required_field() {
        let handler = SshHelmListHandler::new();
        let ctx = create_test_context();

        // Missing host field
        let result = handler
            .execute(Some(json!({"namespace": "default"})), &ctx)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshHelmListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("namespace"));
        assert!(properties.contains_key("all_namespaces"));
        assert!(properties.contains_key("all"));
        assert!(properties.contains_key("filter"));
        assert!(properties.contains_key("output"));
        assert!(properties.contains_key("helm_bin"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshHelmListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshHelmListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshHelmListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
