//! Handler for the `ssh_pkg_list` tool.
//!
//! Lists installed packages on a remote host with optional filtering.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::package::PackageCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshPkgListArgs {
    /// Target host name from configuration.
    host: String,
    /// Filter packages by name pattern.
    filter: Option<String>,
    /// Override auto-detected package manager (apt/dnf/yum/apk).
    pkg_manager: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshPkgListArgs);

pub struct PkgListTool;

impl StandardTool for PkgListTool {
    type Args = SshPkgListArgs;

    const NAME: &'static str = "ssh_pkg_list";

    const DESCRIPTION: &'static str = "List installed packages on a remote host. Prefer this over ssh_exec as it \
        auto-detects the package manager (apt/dnf/yum/apk) and provides consistent output. \
        Filter results by package name pattern. Use ssh_pkg_search to find available \
        packages.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "filter": {
                        "type": "string",
                        "description": "Filter packages by name pattern"
                    },
                    "pkg_manager": {
                        "type": "string",
                        "description": "Override auto-detected package manager (apt/dnf/yum/apk)"
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Override default command timeout in seconds",
                        "minimum": 1
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters before truncation",
                        "minimum": 100
                    },
                    "save_output": {
                        "type": "string",
                        "description": "Save full output to a local file path"
                    }
                },
                "required": ["host"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshPkgListArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PackageCommandBuilder::build_list_command(
            args.pkg_manager.as_deref(),
            args.filter.as_deref(),
        ))
    }
}

/// Handler for the `ssh_pkg_list` tool.
pub type SshPkgListHandler = StandardToolHandler<PkgListTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPkgListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpMissingParam { param } => assert_eq!(param, "arguments"),
            e => panic!("Expected McpMissingParam, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshPkgListHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshPkgListHandler::new();
        assert_eq!(handler.name(), "ssh_pkg_list");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_pkg_list");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "filter": "nginx",
            "pkg_manager": "apt",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/pkgs.txt"
        });
        let args: SshPkgListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.filter.as_deref(), Some("nginx"));
        assert_eq!(args.pkg_manager.as_deref(), Some("apt"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/pkgs.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshPkgListArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.filter.is_none());
        assert!(args.pkg_manager.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshPkgListHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("filter"));
        assert!(props.contains_key("pkg_manager"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshPkgListArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshPkgListArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshPkgListHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
