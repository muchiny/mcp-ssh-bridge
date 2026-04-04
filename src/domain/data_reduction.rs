//! Data Reduction Utilities
//!
//! Extracts the `jq_filter` parameter from tool arguments for server-side
//! JSON filtering before returning results to the LLM.

use serde::Deserialize;

/// Universal data reduction parameters extracted from tool arguments.
///
/// Extracted from the raw JSON before tool-specific argument parsing
/// so the `jq_filter` key doesn't cause deserialization errors.
#[derive(Debug, Default, Deserialize)]
pub struct DataReductionArgs {
    /// jq filter expression for JSON output (requires `jq` feature).
    /// Example: `.[] | {name, status}`
    #[cfg(feature = "jq")]
    pub jq_filter: Option<String>,
}

impl DataReductionArgs {
    /// Extract data reduction params from a JSON value, removing them
    /// so they don't interfere with tool-specific argument parsing.
    pub fn extract(value: &mut serde_json::Value) -> Self {
        #[cfg(not(feature = "jq"))]
        {
            let _ = value;
            Self::default()
        }

        #[cfg(feature = "jq")]
        {
            let Some(obj) = value.as_object_mut() else {
                return Self::default();
            };
            let jq_filter = obj
                .remove("jq_filter")
                .and_then(|v| v.as_str().map(String::from));
            Self { jq_filter }
        }
    }

    /// Returns true if no data reduction is requested.
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "jq")]
        if self.jq_filter.is_some() {
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
}
