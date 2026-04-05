//! Data Reduction Utilities
//!
//! Extracts universal data-reduction parameters (`jq_filter`, `columns`)
//! from tool arguments for server-side output filtering before returning
//! results to the LLM.

use serde::Deserialize;

/// Universal data reduction parameters extracted from tool arguments.
///
/// Extracted from the raw JSON before tool-specific argument parsing
/// so these keys don't cause deserialization errors.
#[derive(Debug, Default, Deserialize)]
pub struct DataReductionArgs {
    /// jq filter expression for JSON output (requires `jq` feature).
    /// Example: `.[] | {name, status}`
    #[cfg(feature = "jq")]
    pub jq_filter: Option<String>,

    /// Column filter for tabular output.
    /// Case-insensitive header match; unknown columns are silently ignored.
    /// Example: `["NAME", "STATUS", "CPU"]`
    pub columns: Option<Vec<String>>,
}

impl DataReductionArgs {
    /// Extract data reduction params from a JSON value, removing them
    /// so they don't interfere with tool-specific argument parsing.
    pub fn extract(value: &mut serde_json::Value) -> Self {
        let Some(obj) = value.as_object_mut() else {
            return Self::default();
        };

        #[cfg(feature = "jq")]
        let jq_filter = obj
            .remove("jq_filter")
            .and_then(|v| v.as_str().map(String::from));

        let columns = obj.remove("columns").and_then(|v| {
            v.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|item| item.as_str().map(String::from))
                    .collect()
            })
        });

        Self {
            #[cfg(feature = "jq")]
            jq_filter,
            columns,
        }
    }

    /// Returns true if no data reduction is requested.
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "jq")]
        if self.jq_filter.is_some() {
            return false;
        }
        if self.columns.is_some() {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_empty() {
        let mut v = serde_json::json!({"host": "prod"});
        let args = DataReductionArgs::extract(&mut v);
        assert!(args.is_empty());
        assert!(v.get("host").is_some());
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_extract_jq_filter() {
        let mut v = serde_json::json!({"host": "prod", "jq_filter": ".[] | {name}"});
        let args = DataReductionArgs::extract(&mut v);
        assert_eq!(args.jq_filter.as_deref(), Some(".[] | {name}"));
        assert!(v.get("jq_filter").is_none());
        assert!(v.get("host").is_some());
    }

    #[test]
    fn test_extract_non_object() {
        let mut v = serde_json::json!("string");
        let args = DataReductionArgs::extract(&mut v);
        assert!(args.is_empty());
    }

    #[cfg(feature = "jq")]
    #[test]
    fn test_is_empty_with_filter() {
        let mut v = serde_json::json!({"jq_filter": ".name"});
        let args = DataReductionArgs::extract(&mut v);
        assert!(!args.is_empty());
    }

    #[test]
    fn test_extract_columns() {
        let mut v = serde_json::json!({"host": "prod", "columns": ["NAME", "STATUS"]});
        let args = DataReductionArgs::extract(&mut v);
        assert_eq!(
            args.columns.as_deref(),
            Some(&["NAME".to_string(), "STATUS".to_string()][..])
        );
        assert!(v.get("columns").is_none());
        assert!(v.get("host").is_some());
    }

    #[test]
    fn test_is_empty_with_columns() {
        let mut v = serde_json::json!({"columns": ["PID"]});
        let args = DataReductionArgs::extract(&mut v);
        assert!(!args.is_empty());
    }

    #[test]
    fn test_extract_columns_non_string_items_ignored() {
        let mut v = serde_json::json!({"columns": ["NAME", 42, "STATUS", null]});
        let args = DataReductionArgs::extract(&mut v);
        let cols = args.columns.unwrap();
        assert_eq!(cols, vec!["NAME", "STATUS"]);
    }

    #[test]
    fn test_extract_columns_not_array() {
        let mut v = serde_json::json!({"columns": "NAME"});
        let args = DataReductionArgs::extract(&mut v);
        assert!(args.columns.is_none());
    }
}
