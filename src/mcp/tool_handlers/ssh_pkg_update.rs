//! Handler for the `ssh_pkg_update` tool.
//!
//! Updates packages on a remote host, either all or a specific package.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::package::{PackageCommandBuilder, validate_package_name};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshPkgUpdateArgs {
    /// Target host name from configuration.
    host: String,
    /// Specific package to update (omit to update all).
    package: Option<String>,
    /// Override auto-detected package manager (apt/dnf/yum/apk).
    pkg_manager: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshPkgUpdateArgs);

pub struct PkgUpdateTool;

impl StandardTool for PkgUpdateTool {
    type Args = SshPkgUpdateArgs;

    const NAME: &'static str = "ssh_pkg_update";

    const DESCRIPTION: &'static str = "Update package manager cache or upgrade installed packages on a remote Linux host. \
        Auto-detects the package manager (apt/dnf/yum/apk). Without a specific package name, \
        upgrades all packages which may cause breaking changes. Specify a package name to \
        update only that package.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "package": {
                        "type": "string",
                        "description": "Specific package to update (omit to update all)"
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

    fn validate(args: &SshPkgUpdateArgs, _host_config: &HostConfig) -> Result<()> {
        if let Some(ref pkg) = args.package {
            validate_package_name(pkg)?;
        }
        Ok(())
    }

    fn build_command(args: &SshPkgUpdateArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PackageCommandBuilder::build_update_command(
            args.pkg_manager.as_deref(),
            args.package.as_deref(),
        ))
    }
}

/// Handler for the `ssh_pkg_update` tool.
pub type SshPkgUpdateHandler = StandardToolHandler<PkgUpdateTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPkgUpdateHandler::new();
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
        let handler = SshPkgUpdateHandler::new();
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
        let handler = SshPkgUpdateHandler::new();
        assert_eq!(handler.name(), "ssh_pkg_update");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_pkg_update");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "package": "nginx",
            "pkg_manager": "yum",
            "timeout_seconds": 300,
            "max_output": 10000,
            "save_output": "/tmp/update.txt"
        });
        let args: SshPkgUpdateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.package.as_deref(), Some("nginx"));
        assert_eq!(args.pkg_manager.as_deref(), Some("yum"));
        assert_eq!(args.timeout_seconds, Some(300));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/update.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshPkgUpdateArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.package.is_none());
        assert!(args.pkg_manager.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshPkgUpdateHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("package"));
        assert!(props.contains_key("pkg_manager"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshPkgUpdateArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshPkgUpdateArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshPkgUpdateHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
