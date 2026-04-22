//! Progressive-discovery meta-tools.
//!
//! 338 tools is enough to overflow the context window of a small client when
//! `tools/list` is called eagerly. These three meta-tools let a client
//! discover the registry on demand: browse groups, search by keyword, then
//! fetch the full schema only for the one tool it actually needs.
//!
//! The logic here is pure (takes a `ToolRegistry` reference and plain
//! arguments, returns a `ToolCallResult`) so the `McpServer` dispatch can
//! call it without threading the registry through `ToolContext`.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::protocol::{Tool, ToolExecution};
use super::registry::{ToolRegistry, inject_reduction_schema, tool_group};
use crate::ports::{ToolAnnotations, ToolCallResult, ToolContent};

/// Tool name for the group-listing meta-tool.
pub const LIST_TOOL_GROUPS: &str = "mcp_list_tool_groups";
/// Tool name for the search meta-tool.
pub const SEARCH_TOOLS: &str = "mcp_search_tools";
/// Tool name for the describe meta-tool.
pub const DESCRIBE_TOOL: &str = "mcp_describe_tool";

/// Returns `true` when `name` matches one of the three meta-tools.
#[must_use]
pub fn is_meta_tool(name: &str) -> bool {
    matches!(name, LIST_TOOL_GROUPS | SEARCH_TOOLS | DESCRIBE_TOOL)
}

/// Build the three virtual `Tool` entries for `tools/list`.
///
/// These are surfaced alongside the registry so clients can discover them
/// without a separate mechanism. The schemas are tiny (no data-reduction
/// params) and the annotations mark them as read-only so clients are free
/// to call them in parallel.
#[must_use]
pub fn definitions() -> Vec<Tool> {
    vec![
        Tool {
            name: LIST_TOOL_GROUPS.to_string(),
            description:
                "List all tool groups (docker, k8s, cloud, serial, winrm, …) with their tool \
                 counts. Call this first to see the broad landscape, then `mcp_search_tools` \
                 to narrow in, then `mcp_describe_tool` to fetch the one schema you need."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            annotations: Some(ToolAnnotations::read_only("List tool groups")),
            execution: Some(ToolExecution {
                task_support: "optional".to_string(),
            }),
            output_schema: None,
            meta: None,
        },
        Tool {
            name: SEARCH_TOOLS.to_string(),
            description:
                "Search the tool registry by keyword (case-insensitive substring on name and \
                 description). Returns compact entries (name + group + short description) \
                 without the full schema, so the AI can scan hundreds of tools without \
                 saturating context. Filter further with `group` or cap results with `limit`."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Case-insensitive substring matched against tool name and description"
                    },
                    "group": {
                        "type": "string",
                        "description": "Restrict results to this tool group (e.g. 'docker', 'k8s')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results (default 20, max 200)",
                        "minimum": 1,
                        "maximum": 200,
                        "default": 20
                    }
                },
                "required": ["query"],
                "additionalProperties": false
            }),
            annotations: Some(ToolAnnotations::read_only("Search tools")),
            execution: Some(ToolExecution {
                task_support: "optional".to_string(),
            }),
            output_schema: None,
            meta: None,
        },
        Tool {
            name: DESCRIBE_TOOL.to_string(),
            description:
                "Return the full schema and reduction strategy for a single tool. Use after \
                 `mcp_search_tools` to fetch the one schema you need; avoids the ~100 K-token \
                 cost of loading all 338 schemas up front."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Exact tool name (use mcp_search_tools to find it)"
                    }
                },
                "required": ["name"],
                "additionalProperties": false
            }),
            annotations: Some(ToolAnnotations::read_only("Describe a tool")),
            execution: Some(ToolExecution {
                task_support: "optional".to_string(),
            }),
            output_schema: None,
            meta: None,
        },
    ]
}

/// Execute one of the three meta-tools. Returns `None` when `tool_name` is
/// not a meta-tool (caller should then dispatch to the regular registry).
pub fn execute(
    tool_name: &str,
    args: Option<&Value>,
    registry: &ToolRegistry,
) -> Option<ToolCallResult> {
    match tool_name {
        LIST_TOOL_GROUPS => Some(list_groups(registry)),
        SEARCH_TOOLS => Some(search(args, registry)),
        DESCRIBE_TOOL => Some(describe(args, registry)),
        _ => None,
    }
}

fn list_groups(registry: &ToolRegistry) -> ToolCallResult {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for tool in registry.list_tools() {
        *counts.entry(tool_group(&tool.name)).or_insert(0) += 1;
    }

    let groups: Vec<Value> = counts
        .iter()
        .map(|(group, count)| json!({ "group": group, "count": count }))
        .collect();

    let payload = json!({
        "total_groups": groups.len(),
        "total_tools": counts.values().sum::<usize>(),
        "groups": groups,
    });

    success_json(payload)
}

fn search(args: Option<&Value>, registry: &ToolRegistry) -> ToolCallResult {
    let args = args.and_then(Value::as_object);
    let Some(query) = args
        .and_then(|o| o.get("query"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return ToolCallResult::error("mcp_search_tools: `query` (string, non-empty) is required");
    };
    let group_filter = args.and_then(|o| o.get("group")).and_then(Value::as_str);
    let limit = args
        .and_then(|o| o.get("limit"))
        .and_then(Value::as_u64)
        .map_or(20_usize, |n| n.min(200) as usize)
        .max(1);

    let query_lower = query.to_lowercase();
    let mut matches: Vec<Value> = registry
        .list_tools()
        .into_iter()
        .filter(|t| {
            group_filter.is_none_or(|g| tool_group(&t.name) == g)
                && (t.name.to_lowercase().contains(&query_lower)
                    || t.description.to_lowercase().contains(&query_lower))
        })
        .map(|t| {
            let group = tool_group(&t.name);
            let short = if t.description.len() > 160 {
                format!("{}…", &t.description[..160])
            } else {
                t.description.clone()
            };
            json!({
                "name": t.name,
                "group": group,
                "description": short,
            })
        })
        .collect();

    let total = matches.len();
    matches.truncate(limit);

    let payload = json!({
        "query": query,
        "group": group_filter,
        "returned": matches.len(),
        "total_matches": total,
        "limit": limit,
        "results": matches,
    });
    success_json(payload)
}

fn describe(args: Option<&Value>, registry: &ToolRegistry) -> ToolCallResult {
    let Some(name) = args
        .and_then(Value::as_object)
        .and_then(|o| o.get("name"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return ToolCallResult::error("mcp_describe_tool: `name` (string, non-empty) is required");
    };

    let Some(handler) = registry.get(name) else {
        return ToolCallResult::error(format!(
            "mcp_describe_tool: unknown tool `{name}`. Use mcp_search_tools to discover valid names."
        ));
    };

    let schema = handler.schema();
    let output_kind = handler.output_kind();
    let mut input_schema: Value =
        serde_json::from_str(schema.input_schema).unwrap_or_else(|_| json!({}));
    inject_reduction_schema(&mut input_schema, output_kind);

    let payload = json!({
        "name": schema.name,
        "group": tool_group(name),
        "description": schema.description,
        "output_kind": format!("{output_kind:?}"),
        "reduction_strategy": output_kind.strategy_hint(),
        "reduce_marker": output_kind.short_marker(),
        "input_schema": input_schema,
    });
    success_json(payload)
}

fn success_json(value: Value) -> ToolCallResult {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    ToolCallResult {
        content: vec![ToolContent::Text { text }],
        is_error: Some(false),
        structured_content: Some(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::registry::create_default_registry;

    #[test]
    fn is_meta_tool_recognises_all_three() {
        assert!(is_meta_tool(LIST_TOOL_GROUPS));
        assert!(is_meta_tool(SEARCH_TOOLS));
        assert!(is_meta_tool(DESCRIBE_TOOL));
        assert!(!is_meta_tool("ssh_exec"));
        assert!(!is_meta_tool(""));
    }

    #[test]
    fn definitions_contains_three_entries() {
        let defs = definitions();
        assert_eq!(defs.len(), 3);
        let names: Vec<&str> = defs.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&LIST_TOOL_GROUPS));
        assert!(names.contains(&SEARCH_TOOLS));
        assert!(names.contains(&DESCRIBE_TOOL));
    }

    #[test]
    fn list_groups_returns_structured_payload() {
        let registry = create_default_registry();
        let result = execute(LIST_TOOL_GROUPS, None, &registry).expect("meta tool");
        let payload = result.structured_content.expect("structured");
        assert!(payload["total_groups"].as_u64().unwrap() > 0);
        assert!(payload["total_tools"].as_u64().unwrap() > 0);
        assert!(payload["groups"].is_array());
    }

    #[test]
    fn search_requires_query() {
        let registry = create_default_registry();
        let result = execute(SEARCH_TOOLS, Some(&json!({})), &registry).expect("meta tool");
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn search_matches_on_name_substring() {
        let registry = create_default_registry();
        let result = execute(
            SEARCH_TOOLS,
            Some(&json!({"query": "docker", "limit": 5})),
            &registry,
        )
        .expect("meta tool");
        let payload = result.structured_content.expect("structured");
        let results = payload["results"].as_array().expect("array");
        assert!(!results.is_empty());
        for entry in results {
            let name = entry["name"].as_str().unwrap();
            let desc = entry["description"].as_str().unwrap();
            assert!(
                name.to_lowercase().contains("docker") || desc.to_lowercase().contains("docker"),
                "match {name} does not contain 'docker'"
            );
        }
    }

    #[test]
    fn search_respects_group_filter() {
        let registry = create_default_registry();
        let result = execute(
            SEARCH_TOOLS,
            Some(&json!({"query": "", "group": "docker", "limit": 50})),
            &registry,
        )
        .expect("meta tool");
        // Empty query is explicitly rejected — this asserts that guard.
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn describe_unknown_returns_error() {
        let registry = create_default_registry();
        let result = execute(
            DESCRIBE_TOOL,
            Some(&json!({"name": "nonexistent_xyz"})),
            &registry,
        )
        .expect("meta tool");
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn describe_known_returns_schema() {
        let registry = create_default_registry();
        // Pick any real tool from the registry.
        let some_tool = registry
            .list_tools()
            .into_iter()
            .find(|t| !is_meta_tool(&t.name))
            .expect("registry has tools");
        let result = execute(
            DESCRIBE_TOOL,
            Some(&json!({"name": some_tool.name})),
            &registry,
        )
        .expect("meta tool");
        let payload = result.structured_content.expect("structured");
        assert_eq!(payload["name"], some_tool.name);
        assert!(payload["input_schema"].is_object());
        assert!(payload["reduction_strategy"].is_string());
    }
}
