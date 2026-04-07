//! Output Kind Classification
//!
//! Declares the expected output format of a tool, enabling type-aware
//! data reduction (jq filtering for JSON, column selection for tabular)
//! and schema injection (only expose relevant params per tool).

/// Declares the expected output format of a tool.
///
/// Used by `StandardToolHandler` to:
/// 1. Inject the right data-reduction params into the tool schema
///    (`jq_filter` for JSON, `columns` for tabular, both for auto).
/// 2. Apply the correct reduction pipeline at runtime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputKind {
    /// Raw text passthrough — no data reduction available.
    #[default]
    RawText,

    /// Columnar CLI output — supports `columns` filter.
    ///
    /// For tools whose commands produce fixed-width columnar text
    /// (like `ps`, `df`, `ss`).
    Tabular,

    /// Guaranteed JSON output — supports `jq_filter`.
    ///
    /// For tools whose commands always return JSON.
    Json,

    /// Guaranteed YAML output — supports `yq_filter`.
    ///
    /// For tools whose commands always return YAML (e.g., kubectl/helm
    /// with `-o yaml`, ansible-navigator, ansible-inventory --yaml).
    /// At runtime the YAML is parsed via serde-saphyr to a generic value
    /// tree and the same jaq-core engine is used to filter it.
    Yaml,

    /// Output may be JSON or tabular depending on parameters —
    /// supports both `jq_filter` and `columns`.
    ///
    /// At runtime the pipeline tries JSON first, then falls back to tabular.
    Auto,
}

impl OutputKind {
    /// Whether this kind supports `jq_filter`.
    #[must_use]
    pub const fn supports_jq(&self) -> bool {
        matches!(self, Self::Json | Self::Auto)
    }

    /// Whether this kind supports `yq_filter`.
    #[must_use]
    pub const fn supports_yq(&self) -> bool {
        matches!(self, Self::Yaml)
    }

    /// Whether this kind supports `columns`.
    #[must_use]
    pub const fn supports_columns(&self) -> bool {
        matches!(self, Self::Tabular | Self::Auto)
    }

    /// Whether this kind supports `limit`.
    #[must_use]
    pub const fn supports_limit(&self) -> bool {
        matches!(self, Self::Tabular | Self::Auto | Self::Json | Self::Yaml)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_raw_text() {
        assert_eq!(OutputKind::default(), OutputKind::RawText);
    }

    #[test]
    fn test_supports_jq() {
        assert!(!OutputKind::RawText.supports_jq());
        assert!(!OutputKind::Tabular.supports_jq());
        assert!(OutputKind::Json.supports_jq());
        assert!(!OutputKind::Yaml.supports_jq());
        assert!(OutputKind::Auto.supports_jq());
    }

    #[test]
    fn test_supports_yq() {
        assert!(!OutputKind::RawText.supports_yq());
        assert!(!OutputKind::Tabular.supports_yq());
        assert!(!OutputKind::Json.supports_yq());
        assert!(OutputKind::Yaml.supports_yq());
        assert!(!OutputKind::Auto.supports_yq());
    }

    #[test]
    fn test_supports_columns() {
        assert!(!OutputKind::RawText.supports_columns());
        assert!(OutputKind::Tabular.supports_columns());
        assert!(!OutputKind::Json.supports_columns());
        assert!(!OutputKind::Yaml.supports_columns());
        assert!(OutputKind::Auto.supports_columns());
    }

    #[test]
    fn test_supports_limit() {
        assert!(!OutputKind::RawText.supports_limit());
        assert!(OutputKind::Tabular.supports_limit());
        assert!(OutputKind::Json.supports_limit());
        assert!(OutputKind::Yaml.supports_limit());
        assert!(OutputKind::Auto.supports_limit());
    }

    #[test]
    fn test_debug_display() {
        assert_eq!(format!("{:?}", OutputKind::Auto), "Auto");
    }

    #[test]
    fn test_clone_copy() {
        let kind = OutputKind::Json;
        let cloned = kind;
        assert_eq!(kind, cloned);
    }
}
