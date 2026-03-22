//! Handler for the `ssh_benchmark` tool.
//!
//! Runs a quick performance benchmark on a remote host.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::config::OsType;
use crate::domain::use_cases::performance::PerformanceCommandBuilder;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

/// Arguments for the `ssh_benchmark` tool.
#[derive(Debug, Deserialize)]
pub struct SshBenchmarkArgs {
    host: String,
    bench_type: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshBenchmarkArgs);

pub struct BenchmarkTool;

impl StandardTool for BenchmarkTool {
    type Args = SshBenchmarkArgs;

    const NAME: &'static str = "ssh_benchmark";

    const DESCRIPTION: &'static str = "Run a quick performance benchmark on a remote host. \
        Supports CPU (md5sum throughput), I/O (dd write speed), and memory (throughput) \
        benchmarks. Results are approximate and suitable for quick comparisons between hosts.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "required": ["host", "bench_type"],
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "bench_type": {
                "type": "string",
                "description": "Type of benchmark to run: 'cpu', 'io', or 'memory'",
                "enum": ["cpu", "io", "memory"]
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds (overrides default)"
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters (overrides default)"
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to this file path on the local machine"
            }
        }
    }"#;

    const OS_GUARD: Option<OsType> = Some(OsType::Linux);

    fn build_command(args: &SshBenchmarkArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(PerformanceCommandBuilder::build_benchmark_command(
            &args.bench_type,
        ))
    }

    fn validate(args: &SshBenchmarkArgs, _host_config: &HostConfig) -> Result<()> {
        PerformanceCommandBuilder::validate_bench_type(&args.bench_type)?;
        Ok(())
    }
}

/// Handler for the `ssh_benchmark` tool.
pub type SshBenchmarkHandler = StandardToolHandler<BenchmarkTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshBenchmarkHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(None, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unknown_host() {
        let handler = SshBenchmarkHandler::new();
        let ctx = create_test_context();
        let args = json!({"host": "nonexistent", "bench_type": "cpu"});
        let result = handler.execute(Some(args), &ctx).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_schema() {
        let handler = SshBenchmarkHandler::new();
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_benchmark");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("host")));
        assert!(required.iter().any(|v| v.as_str() == Some("bench_type")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({"host": "myhost", "bench_type": "cpu"});
        let args: SshBenchmarkArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.bench_type, "cpu");
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "bench_type": "io"});
        let args: SshBenchmarkArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.bench_type, "io");
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshBenchmarkHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let props = schema_json["properties"].as_object().unwrap();
        assert!(props.contains_key("bench_type"));
        assert!(props.contains_key("timeout_seconds"));
        assert!(props.contains_key("max_output"));
        assert!(props.contains_key("save_output"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "h", "bench_type": "cpu"});
        let args: SshBenchmarkArgs = serde_json::from_value(json).unwrap();
        let debug = format!("{args:?}");
        assert!(debug.contains("SshBenchmarkArgs"));
    }

    #[test]
    fn test_invalid_json_type() {
        let json = json!({"host": 123, "bench_type": "cpu"});
        let result = serde_json::from_value::<SshBenchmarkArgs>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_args_full_deserialization() {
        let json = json!({
            "host": "server1",
            "bench_type": "memory",
            "timeout_seconds": 120,
            "max_output": 10000,
            "save_output": "/tmp/bench.txt"
        });
        let args: SshBenchmarkArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "server1");
        assert_eq!(args.bench_type, "memory");
        assert_eq!(args.timeout_seconds, Some(120));
        assert_eq!(args.max_output, Some(10000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/bench.txt"));
    }

    #[test]
    fn test_schema_bench_type_enum() {
        let handler = SshBenchmarkHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let bench_type = &schema_json["properties"]["bench_type"];
        let enum_values = bench_type["enum"].as_array().unwrap();
        assert!(enum_values.contains(&json!("cpu")));
        assert!(enum_values.contains(&json!("io")));
        assert!(enum_values.contains(&json!("memory")));
    }

    #[test]
    fn test_missing_bench_type() {
        let json = json!({"host": "myhost"});
        let result = serde_json::from_value::<SshBenchmarkArgs>(json);
        assert!(result.is_err());
    }
}
