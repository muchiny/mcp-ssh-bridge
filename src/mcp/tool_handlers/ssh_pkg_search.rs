//! Handler for the `ssh_pkg_search` tool.
//!
//! Searches for available packages on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::package::{PackageCommandBuilder, validate_search_query};
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshPkgSearchArgs {
    /// Target host name from configuration.
    host: String,
    /// Search query string.
    query: String,
    /// Override auto-detected package manager (apt/dnf/yum/apk).
    pkg_manager: Option<String>,
    /// Override default command timeout in seconds.
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    max_output: Option<u64>,
    /// Save full output to a local file path.
    save_output: Option<String>,
}

impl_common_args!(SshPkgSearchArgs);

pub struct PkgSearchTool;

impl StandardTool for PkgSearchTool {
    type Args = SshPkgSearchArgs;

    const NAME: &'static str = "ssh_pkg_search";

    const DESCRIPTION: &'static str = "Search for available (not yet installed) packages on a remote Linux host. \
        Auto-detects the package manager (apt/dnf/yum/apk). Returns matching package names \
        and descriptions. Use before ssh_pkg_install to verify a package exists. For listing \
        already installed packages, use ssh_pkg_list instead.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target host name from configuration"
                    },
                    "query": {
                        "type": "string",
                        "description": "Search query string"
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
                "required": ["host", "query"]
            }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn validate(args: &SshPkgSearchArgs, _host_config: &HostConfig) -> Result<()> {
        validate_search_query(&args.query)?;
        Ok(())
    }

    fn build_command(args: &SshPkgSearchArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PackageCommandBuilder::build_search_command(
            args.pkg_manager.as_deref(),
            &args.query,
        ))
    }
}

/// Handler for the `ssh_pkg_search` tool.
pub type SshPkgSearchHandler = StandardToolHandler<PkgSearchTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshPkgSearchHandler::new();
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
        let handler = SshPkgSearchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": "nonexistent", "query": "nginx"})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshPkgSearchHandler::new();
        assert_eq!(handler.name(), "ssh_pkg_search");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_pkg_search");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("query")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "query": "nginx",
            "pkg_manager": "dnf",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/search.txt"
        });
        let args: SshPkgSearchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.query, "nginx");
        assert_eq!(args.pkg_manager.as_deref(), Some("dnf"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/search.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1", "query": "curl"});
        let args: SshPkgSearchArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.query, "curl");
        assert!(args.pkg_manager.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshPkgSearchHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("pkg_manager"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1", "query": "nginx"});
        let args: SshPkgSearchArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshPkgSearchArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshPkgSearchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "query": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
