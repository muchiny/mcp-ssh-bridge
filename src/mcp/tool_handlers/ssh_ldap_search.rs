//! SSH LDAP Search Tool Handler
//!
//! Searches an LDAP directory on a remote host via SSH using ldapsearch.

use serde::Deserialize;
use serde_json::json;

use crate::config::HostConfig;
use crate::domain::use_cases::ldap::LdapCommandBuilder;
use crate::error::Result;
use crate::mcp::apps::table;
use crate::mcp::standard_tool::{StandardTool, StandardToolHandler, impl_common_args};
use crate::ports::protocol::ToolCallResult;

#[derive(Debug, Deserialize)]
pub struct SshLdapSearchArgs {
    host: String,
    base_dn: String,
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    attributes: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    max_output: Option<u64>,
    #[serde(default)]
    save_output: Option<String>,
}

impl_common_args!(SshLdapSearchArgs);

pub struct LdapSearchTool;

impl StandardTool for LdapSearchTool {
    type Args = SshLdapSearchArgs;

    const NAME: &'static str = "ssh_ldap_search";

    const DESCRIPTION: &'static str = "Search an LDAP directory on a remote host using \
        ldapsearch. Specify base DN and optional filter, attributes, and scope.";

    const SCHEMA: &'static str = r#"{
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host alias from config.yaml (use ssh_status to list available hosts)"
            },
            "base_dn": {
                "type": "string",
                "description": "Base DN to search from (e.g. 'dc=example,dc=com')"
            },
            "filter": {
                "type": "string",
                "description": "LDAP search filter (e.g. '(objectClass=person)')"
            },
            "attributes": {
                "type": "string",
                "description": "Space-separated list of attributes to return (e.g. 'cn mail uid')"
            },
            "scope": {
                "type": "string",
                "description": "Search scope: base, one, sub (default: sub)"
            },
            "uri": {
                "type": "string",
                "description": "LDAP URI (e.g. 'ldap://ldap.example.com'). Uses system default if omitted."
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
            },
            "save_output": {
                "type": "string",
                "description": "Save full output to a local file (on MCP server). Claude Code can then read this file directly with its Read tool."
            }
        },
        "required": ["host", "base_dn"]
    }"#;

    fn build_command(args: &SshLdapSearchArgs, _host_config: &HostConfig) -> Result<String> {
        Ok(LdapCommandBuilder::build_search_command(
            &args.base_dn,
            args.filter.as_deref(),
            args.attributes.as_deref(),
            args.scope.as_deref(),
            args.uri.as_deref(),
        ))
    }

    fn post_process(
        result: ToolCallResult,
        args: &SshLdapSearchArgs,
        output: &str,
    ) -> ToolCallResult {
        let Some(parsed) = super::utils::parse_columnar_output(output) else {
            return result;
        };
        let mut tbl = table("LDAP Results");
        for h in &parsed.headers {
            tbl = tbl.column(h, h.to_uppercase());
        }
        for row in &parsed.rows {
            let first = row.first().map_or("", String::as_str);
            if first.is_empty() {
                continue;
            }
            let mut obj = serde_json::Map::new();
            for (i, h) in parsed.headers.iter().enumerate() {
                obj.insert(
                    h.clone(),
                    serde_json::Value::String(
                        row.get(i).map_or_else(String::new, Clone::clone),
                    ),
                );
            }
            tbl = tbl.row(serde_json::Value::Object(obj));
        }
        tbl = tbl.action(
            "refresh",
            "Refresh",
            "ssh_ldap_search",
            Some(json!({"host": args.host, "base_dn": args.base_dn})),
        );
        ToolCallResult::text(parsed.to_tsv()).with_app(tbl.build())
    }
}

/// Handler for the `ssh_ldap_search` tool.
pub type SshLdapSearchHandler = StandardToolHandler<LdapSearchTool>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::ports::ToolHandler;
    use crate::ports::mock::create_test_context;
    use serde_json::json;

    #[tokio::test]
    async fn test_missing_arguments() {
        let handler = SshLdapSearchHandler::new();
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
        let handler = SshLdapSearchHandler::new();
        let ctx = create_test_context();
        let result = handler
            .execute(
                Some(json!({"host": "nonexistent", "base_dn": "dc=example,dc=com"})),
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
        let handler = SshLdapSearchHandler::new();
        assert_eq!(handler.name(), "ssh_ldap_search");
        let schema = handler.schema();
        let schema_json: serde_json::Value = serde_json::from_str(schema.input_schema).unwrap();
        let required = schema_json["required"].as_array().unwrap();
        assert!(required.contains(&json!("host")));
        assert!(required.contains(&json!("base_dn")));
    }
}
