//! Data Reduction Utilities
//!
//! Post-execution output reduction for tool results. These functions
//! are applied in the `StandardToolHandler` pipeline between SSH
//! execution and output truncation to reduce token consumption.

use serde::Deserialize;

/// Universal data reduction parameters extracted from tool arguments.
///
/// These parameters are available on ALL `StandardToolHandler` tools and are
/// extracted from the raw JSON before tool-specific argument parsing.
#[derive(Debug, Default, Deserialize)]
pub struct DataReductionArgs {
    /// jq filter expression for JSON output (requires `jq` feature).
    /// Example: `.[] | {name, status}`
    #[cfg(feature = "jq")]
    pub jq_filter: Option<String>,

    /// Maximum number of data rows to return (header is always kept).
    /// `0` means no limit.
    pub limit: Option<u64>,

    /// Column names to include in tabular output (case-insensitive).
    /// Unknown column names are silently ignored.
    pub fields: Option<Vec<String>>,

    /// Output mode: `"full"` (default) or `"compact"` (summary).
    pub output_mode: Option<String>,
}

impl DataReductionArgs {
    /// Extract data reduction params from a JSON value, removing them
    /// so they don't interfere with tool-specific argument parsing.
    pub fn extract(value: &mut serde_json::Value) -> Self {
        let Some(obj) = value.as_object_mut() else {
            return Self::default();
        };

        let mut args = Self::default();

        #[cfg(feature = "jq")]
        if let Some(v) = obj.remove("jq_filter") {
            args.jq_filter = v.as_str().map(String::from);
        }

        if let Some(v) = obj.remove("limit") {
            args.limit = v.as_u64();
        }

        if let Some(v) = obj.remove("fields") {
            args.fields = v.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });
        }

        if let Some(v) = obj.remove("output_mode") {
            args.output_mode = v.as_str().map(String::from);
        }

        args
    }

    /// Returns true if no data reduction is requested.
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "jq")]
        if self.jq_filter.is_some() {
            return false;
        }
        self.limit.is_none() && self.fields.is_none() && self.output_mode.is_none()
    }
}

/// Limit output to the first `n` data rows, keeping the first line (header).
///
/// If `n` is 0 or the output has fewer than `n+1` lines, returns unchanged.
#[must_use]
pub fn apply_row_limit(output: &str, n: u64) -> String {
    if n == 0 {
        return output.to_string();
    }
    #[allow(clippy::cast_possible_truncation)]
    let n = n as usize;
    let lines: Vec<&str> = output.lines().collect();

    // Need at least a header + 1 data row, and limit must actually truncate
    if lines.len() <= n + 1 {
        return output.to_string();
    }

    let total_data = lines.len() - 1;
    let mut result: Vec<&str> = lines[..=n].to_vec();
    let omitted = total_data - n;
    result.push(""); // blank line before summary
    // Use a heap-allocated string for the summary line
    let summary = format!("... {omitted} more rows ({total_data} total)");
    let mut output = result.join("\n");
    output.push_str(&summary);
    output
}

/// Generate a compact summary of the output.
///
/// Detects the output type (JSON array, free text) and returns a concise
/// summary instead of the full output. For tabular output, the caller
/// should use `generate_compact_tabular_summary` (in the adapter layer)
/// which has access to `parse_columnar_output`.
#[must_use]
pub fn generate_compact_summary(output: &str) -> String {
    // Try JSON array/object
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(output) {
        return compact_json_summary(&val);
    }

    // Free text — line count + first few lines
    let lines: Vec<&str> = output.lines().collect();
    let count = lines.len();
    let preview: Vec<&str> = lines.iter().take(5).copied().collect();
    if count <= 5 {
        output.to_string()
    } else {
        format!(
            "{count} lines:\n{}\n... +{} more lines",
            preview.join("\n"),
            count - 5
        )
    }
}

/// Summarize a JSON value compactly.
fn compact_json_summary(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Array(arr) => {
            let count = arr.len();
            if count == 0 {
                return "[] (empty array)".to_string();
            }
            // Summarize first element's keys if it's an object
            let keys_hint = if let Some(serde_json::Value::Object(obj)) = arr.first() {
                let keys: Vec<&str> = obj.keys().take(8).map(String::as_str).collect();
                format!(" | keys: {}", keys.join(", "))
            } else {
                String::new()
            };
            // Preview first 3 items compactly
            let preview: Vec<String> = arr.iter().take(3).map(|v| compact_value(v, 80)).collect();
            format!("{count} items{keys_hint}\n{}", preview.join("\n"))
        }
        serde_json::Value::Object(obj) => {
            let keys: Vec<&str> = obj.keys().take(10).map(String::as_str).collect();
            format!("object with {} keys: {}", obj.len(), keys.join(", "))
        }
        other => other.to_string(),
    }
}

/// Compact representation of a JSON value, truncated to `max_chars`.
fn compact_value(val: &serde_json::Value, max_chars: usize) -> String {
    let s = val.to_string();
    if s.len() <= max_chars {
        s
    } else {
        format!("{}...", &s[..max_chars.min(s.len())])
    }
}

/// JSON schema fragment for the universal data reduction parameters.
///
/// This is injected into every `StandardToolHandler` tool schema at runtime.
pub const DATA_REDUCTION_SCHEMA_PROPERTIES: &str = r#"
    "jq_filter": {
      "type": "string",
      "description": "jq expression applied server-side to JSON output before returning. Dramatically reduces tokens. Example: '.[] | {name, status}'. Use @tsv for tab-separated output: '[.[] | [.name, .status]] | .[] | @tsv' (requires jq feature)."
    },
    "limit": {
      "type": "integer",
      "minimum": 0,
      "description": "Maximum number of data rows to return (header always kept). 0 = no limit. Useful for listing tools (process_list, docker_ps, etc)."
    },
    "fields": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Column names to include in tabular output (case-insensitive). Unmatched names are ignored. Returns TSV for token efficiency."
    },
    "output_mode": {
      "type": "string",
      "enum": ["full", "compact"],
      "description": "full (default): complete output. compact: summary with counts and top items only."
    }"#;

#[cfg(test)]
mod tests {
    use super::*;

    // ---- DataReductionArgs::extract ----

    #[test]
    fn test_extract_empty() {
        let mut v = serde_json::json!({"host": "prod"});
        let args = DataReductionArgs::extract(&mut v);
        assert!(args.is_empty());
        assert!(v.get("host").is_some()); // host preserved
    }

    #[test]
    fn test_extract_limit() {
        let mut v = serde_json::json!({"host": "prod", "limit": 10});
        let args = DataReductionArgs::extract(&mut v);
        assert_eq!(args.limit, Some(10));
        assert!(v.get("limit").is_none()); // removed
        assert!(v.get("host").is_some()); // preserved
    }

    #[test]
    fn test_extract_fields() {
        let mut v = serde_json::json!({"host": "prod", "fields": ["name", "status"]});
        let args = DataReductionArgs::extract(&mut v);
        assert_eq!(
            args.fields.as_deref(),
            Some(&["name".to_string(), "status".to_string()][..])
        );
        assert!(v.get("fields").is_none());
    }

    #[test]
    fn test_extract_output_mode() {
        let mut v = serde_json::json!({"host": "prod", "output_mode": "compact"});
        let args = DataReductionArgs::extract(&mut v);
        assert_eq!(args.output_mode.as_deref(), Some("compact"));
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_extract_jq_filter() {
        let mut v = serde_json::json!({"host": "prod", "jq_filter": ".[] | {name}"});
        let args = DataReductionArgs::extract(&mut v);
        assert_eq!(args.jq_filter.as_deref(), Some(".[] | {name}"));
        assert!(v.get("jq_filter").is_none());
    }

    #[test]
    fn test_extract_non_object() {
        let mut v = serde_json::json!("string");
        let args = DataReductionArgs::extract(&mut v);
        assert!(args.is_empty());
    }

    // ---- apply_row_limit ----

    #[test]
    fn test_row_limit_no_truncation() {
        let output = "HEADER\nrow1\nrow2\nrow3";
        assert_eq!(apply_row_limit(output, 10), output);
    }

    #[test]
    fn test_row_limit_truncates() {
        let output = "NAME\tstatus\na\trunning\nb\tstopped\nc\trunning\nd\tstopped\ne\trunning";
        let result = apply_row_limit(output, 2);
        assert!(result.contains("NAME\tstatus"));
        assert!(result.contains("a\trunning"));
        assert!(result.contains("b\tstopped"));
        assert!(result.contains("3 more rows"));
        assert!(result.contains("5 total"));
        assert!(!result.contains("c\trunning"));
    }

    #[test]
    fn test_row_limit_zero_no_limit() {
        let output = "HEADER\nrow1\nrow2";
        assert_eq!(apply_row_limit(output, 0), output);
    }

    // ---- generate_compact_summary ----

    #[test]
    fn test_compact_json_array() {
        let input = r#"[{"name":"a","cpu":10},{"name":"b","cpu":20}]"#;
        let result = generate_compact_summary(input);
        assert!(result.contains("2 items"), "got: {result}");
        assert!(
            result.contains("name") && result.contains("cpu"),
            "got: {result}"
        );
    }

    #[test]
    fn test_compact_json_object() {
        let input = r#"{"name":"test","version":"1.0"}"#;
        let result = generate_compact_summary(input);
        assert!(result.contains("object with 2 keys"));
    }

    #[test]
    fn test_compact_free_text_short() {
        // Use single-word lines so they can't be parsed as tabular
        let input = "hello";
        let result = generate_compact_summary(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_compact_free_text_long() {
        // Use lines without consistent column structure
        let lines: Vec<String> = (0..20)
            .map(|i| format!("This is a log message number {i} with varying content"))
            .collect();
        let input = lines.join("\n");
        let result = generate_compact_summary(&input);
        assert!(
            result.contains("20 lines") || result.contains("20 rows"),
            "got: {result}"
        );
    }

    #[test]
    fn test_compact_empty_array() {
        let result = generate_compact_summary("[]");
        assert!(result.contains("empty array"));
    }
}
