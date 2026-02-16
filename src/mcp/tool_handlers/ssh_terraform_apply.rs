use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::terraform::TerraformCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshTerraformApplyArgs {
    host: String,
    dir: String,
    auto_approve: Option<bool>,
    vars: Option<Vec<String>>,
    var_file: Option<String>,
    targets: Option<Vec<String>>,
    plan_file: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshTerraformApplyArgs);

pub struct TerraformApplyTool;

impl StandardTool for TerraformApplyTool {
    type Args = SshTerraformApplyArgs;

    const NAME: &'static str = "ssh_terraform_apply";

    const DESCRIPTION: &'static str = "Apply Terraform infrastructure changes on a remote host. Executes planned changes to \
        create, update, or destroy resources. Use ssh_terraform_plan first to preview \
        changes. Use auto_approve=true to skip confirmation (use only for trusted, tested \
        configurations).";

    const SCHEMA: &'static str = r#"{
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "SSH host to connect through"
                    },
                    "dir": {
                        "type": "string",
                        "description": "Path to Terraform directory"
                    },
                    "auto_approve": {
                        "type": "boolean",
                        "description": "Skip interactive approval (default: false)"
                    },
                    "vars": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Variable assignments (e.g., 'key=value')"
                    },
                    "var_file": {
                        "type": "string",
                        "description": "Path to variable file"
                    },
                    "targets": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Resource targets to apply"
                    },
                    "plan_file": {
                        "type": "string",
                        "description": "Path to a saved plan file"
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Command timeout in seconds"
                    },
                    "max_output": {
                        "type": "integer",
                        "description": "Maximum output characters"
                    },
                    "save_output": {
                        "type": "string",
                        "description": "File path to save full output"
                    }
                },
                "required": ["host", "dir"]
            }"#;

    fn build_command(args: &SshTerraformApplyArgs, _host_config: &HostConfig) -> Result<String> {
        TerraformCommandBuilder::build_apply_command(
            &args.dir,
            args.auto_approve.unwrap_or(false),
            args.vars.as_deref(),
            args.var_file.as_deref(),
            args.targets.as_deref(),
            args.plan_file.as_deref(),
        )
    }
}

/// Handler for the `ssh_terraform_apply` tool.
pub type SshTerraformApplyHandler = StandardToolHandler<TerraformApplyTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTerraformApplyHandler::new();
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
        let handler = SshTerraformApplyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "dir": "/opt/terraform"})),
                &ctx,
            )
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::UnknownHost { host } => assert_eq!(host, "nonexistent"),
            e => panic!("Expected UnknownHost, got: {e:?}"),
        }
    }

    #[test]
    fn test_schema() {
        let handler = SshTerraformApplyHandler::new();
        assert_eq!(handler.name(), "ssh_terraform_apply");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_terraform_apply");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("dir")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "dir": "/opt/terraform",
            "auto_approve": true,
            "vars": ["region=us-east-1"],
            "var_file": "prod.tfvars",
            "targets": ["aws_instance.web"],
            "plan_file": "plan.tfplan",
            "timeout_seconds": 600,
            "max_output": 20000,
            "save_output": "/tmp/tf_apply.txt"
        });
        let args: SshTerraformApplyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.dir, "/opt/terraform");
        assert_eq!(args.auto_approve, Some(true));
        assert_eq!(
            args.vars.as_deref(),
            Some(&["region=us-east-1".to_string()][..])
        );
        assert_eq!(args.var_file.as_deref(), Some("prod.tfvars"));
        assert_eq!(
            args.targets.as_deref(),
            Some(&["aws_instance.web".to_string()][..])
        );
        assert_eq!(args.plan_file.as_deref(), Some("plan.tfplan"));
        assert_eq!(args.timeout_seconds, Some(600));
        assert_eq!(args.max_output, Some(20000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/tf_apply.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "dir": "/opt/terraform"});
        let args: SshTerraformApplyArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.dir, "/opt/terraform");
        assert!(args.auto_approve.is_none());
        assert!(args.vars.is_none());
        assert!(args.var_file.is_none());
        assert!(args.targets.is_none());
        assert!(args.plan_file.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTerraformApplyHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("auto_approve"));
        assert!(properties.contains_key("vars"));
        assert!(properties.contains_key("var_file"));
        assert!(properties.contains_key("targets"));
        assert!(properties.contains_key("plan_file"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "dir": "/opt/terraform"});
        let args: SshTerraformApplyArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshTerraformApplyArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshTerraformApplyHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(Some(json!({"host": 123, "dir": 456})), &ctx)
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
