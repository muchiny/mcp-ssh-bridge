//! Handler for the `ssh_cloud_cost` tool.
//!
//! Retrieves AWS cloud cost and usage data on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::cloud::CloudCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshCloudCostArgs {
    /// Target host name from configuration.
    host: String,
    /// Filter by specific AWS service name (e.g. "Amazon S3").
    #[serde(default)]
    service: Option<String>,
    /// Time period for cost data (e.g. "7d", "30d"). Defaults to "7d".
    #[serde(default)]
    period: Option<String>,
    /// Override default command timeout in seconds.
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// Maximum output characters before truncation.
    #[serde(default)]
    max_output: Option<u64>,
    /// Save full output to a local file path.
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshCloudCostArgs);

pub struct CloudCostTool;

impl StandardTool for CloudCostTool {
    type Args = SshCloudCostArgs;

    const NAME: &'static str = "ssh_cloud_cost";

    const DESCRIPTION: &'static str = "Retrieve AWS cloud cost and usage data on a remote host. \
        Uses AWS Cost Explorer to fetch daily blended cost metrics. Optionally filter by \
        service and time period. Requires AWS CLI with appropriate IAM permissions.";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
                    },
                    "service": {
                        "type": "string",
                        "description": "Filter by AWS service name (e.g. 'Amazon S3', 'Amazon EC2')"
                    },
                    "period": {
                        "type": "string",
                        "description": "Time period for cost data (e.g. '7d', '30d'). Default: '7d'"
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

    fn build_command(args: &SshCloudCostArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(CloudCommandBuilder::build_cloud_cost_command(
            args.service.as_deref(),
            args.period.as_deref(),
        ))
    }
}

/// Handler for the `ssh_cloud_cost` tool.
pub type SshCloudCostHandler = StandardToolHandler<CloudCostTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshCloudCostHandler::new();
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
        let handler = SshCloudCostHandler::new();
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
        let handler = SshCloudCostHandler::new();
        assert_eq!(handler.name(), "ssh_cloud_cost");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_cloud_cost");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "server1",
            "service": "Amazon S3",
            "period": "30d",
            "timeout_seconds": 60,
            "max_output": 20000,
            "save_output": "/tmp/costs.json"
        });
        let args: SshCloudCostArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.service.as_deref(), Some("Amazon S3"));
        assert_eq!(args.period.as_deref(), Some("30d"));
        assert_eq!(args.timeout_seconds, Some(60));
        assert_eq!(args.max_output, Some(20000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/costs.json"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "server1"});
        let args: SshCloudCostArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert!(args.service.is_none());
        assert!(args.period.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshCloudCostHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("service"));
        assert!(props.contains_key("period"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "server1"});
        let args: SshCloudCostArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshCloudCostArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshCloudCostHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema_has_type_object() {
        let handler = SshCloudCostHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn test_description_not_empty() {
        let handler = SshCloudCostHandler::new();
        assert!(handler.description().len() > 10);
    }
}
