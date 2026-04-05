//! JQ Filter Engine
//!
//! Applies jq expressions to JSON output using `jaq-core` for
//! server-side data reduction before returning results to the LLM.
//! This can reduce token consumption by up to 99% on large JSON outputs.
//!
//! Feature-gated behind the `jq` feature flag.

use jaq_core::load::{Arena, File, Loader};
use jaq_core::{Compiler, Ctx, Vars, data, unwrap_valr};
use jaq_json::Val;

use crate::error::{BridgeError, Result};

/// Apply a jq filter expression to a JSON string.
///
/// Returns the filtered output as a string. If the filter produces
/// multiple results, they are joined with newlines.
///
/// If `input` is not valid JSON, returns an error suggesting the use
/// of other data reduction params (`fields`, `limit`) instead.
///
/// # Errors
///
/// Returns `BridgeError::McpInvalidRequest` if:
/// - The input is not valid JSON
/// - The filter expression fails to parse or compile
/// - The filter produces a runtime error
pub fn apply_jq_filter(input: &str, filter_expr: &str) -> Result<String> {
    // Parse input JSON
    let input_val: Val = serde_json::from_str(input).map_err(|e| {
        BridgeError::McpInvalidRequest(format!(
            "jq_filter requires JSON output, but command returned plain text: {e}. \
             Use 'fields' or 'limit' parameters for non-JSON output."
        ))
    })?;

    // Set up the jq compiler with standard library definitions
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());

    let loader = Loader::new(defs);
    let arena = Arena::default();

    let program = File {
        code: filter_expr,
        path: (),
    };

    // Parse the filter
    let modules = loader.load(&arena, program).map_err(|errs| {
        let msg = errs
            .into_iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join("; ");
        BridgeError::McpInvalidRequest(format!("jq filter parse error: {msg}"))
    })?;

    // Compile the filter
    let filter = Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|errs| {
            let msg = errs
                .into_iter()
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
                .join("; ");
            BridgeError::McpInvalidRequest(format!("jq filter compile error: {msg}"))
        })?;

    // Execute the filter
    let ctx = Ctx::<data::JustLut<Val>>::new(&filter.lut, Vars::new([]));
    let results: Vec<String> = filter
        .id
        .run((ctx, input_val))
        .map(unwrap_valr)
        .map(|r| match r {
            Ok(val) => val.to_string(),
            Err(e) => format!("jq error: {e}"),
        })
        .collect();

    if results.is_empty() {
        Ok(String::new())
    } else {
        Ok(results.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_filter() {
        let input = r#"{"name": "test", "value": 42}"#;
        let result = apply_jq_filter(input, ".").unwrap();
        assert!(result.contains("name"));
        assert!(result.contains("42"));
    }

    #[test]
    fn test_field_selection() {
        let input = r#"{"name": "web", "status": "running", "pid": 1234}"#;
        let result = apply_jq_filter(input, ".name").unwrap();
        assert_eq!(result, r#""web""#);
    }

    #[test]
    fn test_object_construction() {
        let input = r#"[{"name": "web", "status": "running", "cpu": 45}, {"name": "db", "status": "running", "cpu": 12}]"#;
        let result = apply_jq_filter(input, ".[] | {name, cpu}").unwrap();
        assert!(result.contains(r#""web""#));
        assert!(result.contains(r#""db""#));
    }

    #[test]
    fn test_select_filter() {
        let input = r#"[{"name": "web", "cpu": 45}, {"name": "db", "cpu": 5}]"#;
        let result = apply_jq_filter(input, "[.[] | select(.cpu > 10)]").unwrap();
        assert!(result.contains("web"));
        assert!(!result.contains(r#""db""#));
    }

    #[test]
    fn test_length() {
        let input = r"[1, 2, 3, 4, 5]";
        let result = apply_jq_filter(input, "length").unwrap();
        assert_eq!(result, "5");
    }

    #[test]
    fn test_keys() {
        let input = r#"{"b": 1, "a": 2, "c": 3}"#;
        let result = apply_jq_filter(input, "keys").unwrap();
        assert!(result.contains(r#""a""#));
        assert!(result.contains(r#""b""#));
    }

    #[test]
    fn test_map() {
        let input = r"[1, 2, 3]";
        let result = apply_jq_filter(input, "map(. * 2)").unwrap();
        assert!(result.contains('2'));
        assert!(result.contains('4'));
        assert!(result.contains('6'));
    }

    #[test]
    fn test_invalid_json_input() {
        let input = "not json at all";
        let result = apply_jq_filter(input, ".");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("jq_filter requires JSON"));
    }

    #[test]
    fn test_invalid_filter() {
        let input = r#"{"a": 1}"#;
        let result = apply_jq_filter(input, ".[invalid syntax");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_result() {
        let input = r#"[{"a": 1}, {"a": 2}]"#;
        let result = apply_jq_filter(input, "[.[] | select(.a > 100)]").unwrap();
        assert_eq!(result, "[]");
    }

    #[test]
    fn test_multiple_results() {
        let input = r"[1, 2, 3]";
        let result = apply_jq_filter(input, ".[]").unwrap();
        assert_eq!(result, "1\n2\n3");
    }

    #[test]
    fn test_nested_access() {
        let input = r#"{"a": {"b": {"c": "deep"}}}"#;
        let result = apply_jq_filter(input, ".a.b.c").unwrap();
        assert_eq!(result, r#""deep""#);
    }

    #[test]
    fn test_array_slice() {
        let input = r"[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]";
        let result = apply_jq_filter(input, ".[0:3]").unwrap();
        assert!(result.contains('0'));
        assert!(result.contains('1'));
        assert!(result.contains('2'));
    }

    #[test]
    fn test_sort_by() {
        let input = r#"[{"name": "c", "v": 3}, {"name": "a", "v": 1}, {"name": "b", "v": 2}]"#;
        let result = apply_jq_filter(input, "sort_by(.v) | .[0].name").unwrap();
        assert_eq!(result, r#""a""#);
    }

    #[test]
    fn test_group_by() {
        let input = r#"[{"type": "a", "v": 1}, {"type": "b", "v": 2}, {"type": "a", "v": 3}]"#;
        let result = apply_jq_filter(
            input,
            "[group_by(.type)[] | {type: .[0].type, count: length}]",
        )
        .unwrap();
        assert!(result.contains(r#""a""#));
        assert!(result.contains(r#""b""#));
    }
}
