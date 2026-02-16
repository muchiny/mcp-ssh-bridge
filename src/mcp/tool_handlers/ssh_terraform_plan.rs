use serde::Deserialize;

use crate::config::HostConfig;
use crate::domain::use_cases::terraform::TerraformCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

#[derive(Debug, Deserialize)]
pub struct SshTerraformPlanArgs {
    host: String,
    dir: String,
    vars: Option<Vec<String>>,
    var_file: Option<String>,
    targets: Option<Vec<String>>,
    out: Option<String>,
    destroy: Option<bool>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshTerraformPlanArgs);

pub struct TerraformPlanTool;

impl StandardTool for TerraformPlanTool {
    type Args = SshTerraformPlanArgs;

    const NAME: &'static str = "ssh_terraform_plan";

    const DESCRIPTION: &'static str = "Generate a Terraform execution plan on a remote host. Shows what changes will be made \
        without applying them. Always run this before ssh_terraform_apply to preview resource \
        creation, modification, or destruction.";

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
                        "description": "Resource targets to plan"
                    },
                    "out": {
                        "type": "string",
                        "description": "Path to save the plan file"
                    },
                    "destroy": {
                        "type": "boolean",
                        "description": "Create a destroy plan"
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

    fn build_command(args: &SshTerraformPlanArgs, _host_config: &HostConfig) -> Result<String> {
        TerraformCommandBuilder::build_plan_command(
            &args.dir,
            args.vars.as_deref(),
            args.var_file.as_deref(),
            args.targets.as_deref(),
            args.out.as_deref(),
            args.destroy.unwrap_or(false),
        )
    }
}

/// Handler for the `ssh_terraform_plan` tool.
pub type SshTerraformPlanHandler = StandardToolHandler<TerraformPlanTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshTerraformPlanHandler::new();
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
        let handler = SshTerraformPlanHandler::new();
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
        let handler = SshTerraformPlanHandler::new();
        assert_eq!(handler.name(), "ssh_terraform_plan");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_terraform_plan");
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
            "vars": ["region=us-east-1", "env=prod"],
            "var_file": "prod.tfvars",
            "targets": ["aws_instance.web"],
            "out": "plan.tfplan",
            "destroy": false,
            "timeout_seconds": 300,
            "max_output": 20000,
            "save_output": "/tmp/tf_plan.txt"
        });
        let args: SshTerraformPlanArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.dir, "/opt/terraform");
        assert_eq!(
            args.vars.as_deref(),
            Some(&["region=us-east-1".to_string(), "env=prod".to_string()][..])
        );
        assert_eq!(args.var_file.as_deref(), Some("prod.tfvars"));
        assert_eq!(
            args.targets.as_deref(),
            Some(&["aws_instance.web".to_string()][..])
        );
        assert_eq!(args.out.as_deref(), Some("plan.tfplan"));
        assert_eq!(args.destroy, Some(false));
        assert_eq!(args.timeout_seconds, Some(300));
        assert_eq!(args.max_output, Some(20000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/tf_plan.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "dir": "/opt/terraform"});
        let args: SshTerraformPlanArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.dir, "/opt/terraform");
        assert!(args.vars.is_none());
        assert!(args.var_file.is_none());
        assert!(args.targets.is_none());
        assert!(args.out.is_none());
        assert!(args.destroy.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshTerraformPlanHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("vars"));
        assert!(properties.contains_key("var_file"));
        assert!(properties.contains_key("targets"));
        assert!(properties.contains_key("out"));
        assert!(properties.contains_key("destroy"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "dir": "/opt/terraform"});
        let args: SshTerraformPlanArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshTerraformPlanArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshTerraformPlanHandler::new();
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
