//! SSH `MySQL` Query Tool Handler
//!
//! Execute SQL queries on remote `MySQL` databases.

use serde::Deserialize;

use crate::config::HostConfig;
use crate::error::Result;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};

use super::utils::shell_escape;

#[derive(Debug, Deserialize)]
pub struct SshMysqlQueryArgs {
    host: String,
    query: String,
    database: Option<String>,
    db_user: Option<String>,
    db_port: Option<u16>,
    format: Option<String>,
    timeout_seconds: Option<u64>,
    max_output: Option<u64>,
    save_output: Option<String>,
}

impl_common_args!(SshMysqlQueryArgs);

pub struct MysqlQueryTool;

impl StandardTool for MysqlQueryTool {
    type Args = SshMysqlQueryArgs;

    const NAME: &'static str = "ssh_mysql_query";

    const DESCRIPTION: &'static str = "Execute a SQL query on a remote MySQL database via the \
        mysql client. Returns query results in table, CSV, or JSON format. Prefer this over \
        ssh_exec for MySQL interactions as it handles connection parameters automatically.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "query": {
                "type": "string",
                "description": "SQL query to execute"
            },
            "database": {
                "type": "string",
                "description": "Database name"
            },
            "db_user": {
                "type": "string",
                "description": "Database user (default: root)"
            },
            "db_port": {
                "type": "integer",
                "description": "Database port (default: 3306)",
                "minimum": 1,
                "maximum": 65535
            },
            "format": {
                "type": "string",
                "description": "Output format: table, csv, json (default: table)",
                "enum": ["table", "csv", "json"]
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Command timeout in seconds",
                "minimum": 1
            },
            "max_output": {
                "type": "integer",
                "description": "Maximum output characters",
                "minimum": 100
            },
            "save_output": {
                "type": "string",
                "description": "File path to save full output"
            }
        },
        "required": ["host", "query"]
    }"#;

    const OUTPUT_KIND: crate::domain::output_kind::OutputKind = crate::domain::output_kind::OutputKind::Auto;

    fn build_command(args: &SshMysqlQueryArgs, _host_config: &HostConfig) -> Result<String> {
        let user = args.db_user.as_deref().unwrap_or("root");
        let port = args.db_port.unwrap_or(3306);

        let format_flag = match args.format.as_deref() {
            Some("csv") => " -B",
            Some("json") => " --json",
            _ => "",
        };

        let db_part = match args.database.as_deref() {
            Some(db) => format!(" {}", shell_escape(db)),
            None => String::new(),
        };

        Ok(format!(
            "mysql -h localhost -P {port} -u {user}{db_part}{format_flag} -e {query}",
            port = port,
            user = shell_escape(user),
            db_part = db_part,
            format_flag = format_flag,
            query = shell_escape(&args.query),
        ))
    }
}

/// Handler for the `ssh_mysql_query` tool.
pub type SshMysqlQueryHandler = StandardToolHandler<MysqlQueryTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshMysqlQueryHandler::new();
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
        let handler = SshMysqlQueryHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "query": "SELECT 1"})),
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
        let handler = SshMysqlQueryHandler::new();
        assert_eq!(handler.name(), "ssh_mysql_query");
        assert!(!handler.description().is_empty());
        let schema = handler.schema();
        assert_eq!(schema.name, "ssh_mysql_query");
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("query")));
    }

    #[test]
    fn test_args_deserialization() {
        let json = json!({
            "host": "myhost",
            "query": "SELECT * FROM users",
            "database": "mydb",
            "db_user": "admin",
            "db_port": 3307,
            "format": "csv",
            "timeout_seconds": 30,
            "max_output": 5000,
            "save_output": "/tmp/mysql_query.txt"
        });
        let args: SshMysqlQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.query, "SELECT * FROM users");
        assert_eq!(args.database.as_deref(), Some("mydb"));
        assert_eq!(args.db_user.as_deref(), Some("admin"));
        assert_eq!(args.db_port, Some(3307));
        assert_eq!(args.format.as_deref(), Some("csv"));
        assert_eq!(args.timeout_seconds, Some(30));
        assert_eq!(args.max_output, Some(5000));
        assert_eq!(args.save_output.as_deref(), Some("/tmp/mysql_query.txt"));
    }

    #[test]
    fn test_args_minimal_deserialization() {
        let json = json!({"host": "myhost", "query": "SELECT 1"});
        let args: SshMysqlQueryArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.host, "myhost");
        assert_eq!(args.query, "SELECT 1");
        assert!(args.database.is_none());
        assert!(args.db_user.is_none());
        assert!(args.db_port.is_none());
        assert!(args.format.is_none());
        assert!(args.timeout_seconds.is_none());
        assert!(args.max_output.is_none());
        assert!(args.save_output.is_none());
    }

    #[test]
    fn test_schema_optional_fields() {
        let handler = SshMysqlQueryHandler::new();
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("timeout_seconds"));
        assert!(properties.contains_key("max_output"));
        assert!(properties.contains_key("save_output"));
        assert!(properties.contains_key("database"));
        assert!(properties.contains_key("db_user"));
        assert!(properties.contains_key("db_port"));
        assert!(properties.contains_key("format"));
    }

    #[test]
    fn test_args_debug() {
        let json = json!({"host": "myhost", "query": "SELECT 1"});
        let args: SshMysqlQueryArgs = serde_json::from_value(json).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("SshMysqlQueryArgs"));
    }

    #[tokio::test]
    async fn test_invalid_json_type() {
        let handler = SshMysqlQueryHandler::new();
        let ctx = create_test_context();
        let result = handler.execute(Some(json!({"host": 123})), &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpInvalidRequest(_) => {}
            e => panic!("Expected McpInvalidRequest, got: {e:?}"),
        }
    }
}
