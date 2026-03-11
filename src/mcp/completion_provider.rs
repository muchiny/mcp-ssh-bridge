//! Default Completion Provider
//!
//! Provides argument auto-completion for MCP prompts and resources
//! based on configuration data (host names, enum values, etc.).

use crate::error::Result;
use crate::ports::ToolContext;
use crate::ports::completions::CompletionProvider;

/// Maximum number of completion values returned.
const MAX_COMPLETIONS: usize = 100;

/// Default completion provider that reads from config.
pub struct DefaultCompletionProvider;

impl CompletionProvider for DefaultCompletionProvider {
    fn complete_prompt_argument(
        &self,
        _prompt_name: &str,
        arg_name: &str,
        prefix: &str,
        ctx: &ToolContext,
    ) -> Result<Vec<String>> {
        match arg_name {
            "host" => Ok(complete_hosts(prefix, ctx)),
            "scope" => Ok(complete_from_list(
                prefix,
                &["quick", "standard", "thorough"],
            )),
            "environment" => Ok(complete_from_list(
                prefix,
                &["dev", "staging", "production"],
            )),
            "issue" => Ok(complete_from_list(
                prefix,
                &["high-cpu", "disk-full", "network", "memory", "service-down"],
            )),
            _ => Ok(Vec::new()),
        }
    }

    fn complete_resource_argument(
        &self,
        _uri: &str,
        arg_name: &str,
        prefix: &str,
        ctx: &ToolContext,
    ) -> Result<Vec<String>> {
        match arg_name {
            "host" => Ok(complete_hosts(prefix, ctx)),
            _ => Ok(Vec::new()),
        }
    }
}

/// Complete host names from config, filtered by prefix.
fn complete_hosts(prefix: &str, ctx: &ToolContext) -> Vec<String> {
    let mut hosts: Vec<String> = ctx
        .config
        .hosts
        .keys()
        .filter(|h| h.starts_with(prefix))
        .cloned()
        .collect();
    hosts.sort();
    hosts.truncate(MAX_COMPLETIONS);
    hosts
}

/// Complete from a static list, filtered by prefix.
fn complete_from_list(prefix: &str, values: &[&str]) -> Vec<String> {
    values
        .iter()
        .filter(|v| v.starts_with(prefix))
        .map(|v| (*v).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::mock;

    #[test]
    fn test_complete_host_empty_prefix() {
        let ctx = mock::create_test_context_with_host();
        let provider = DefaultCompletionProvider;
        let result = provider
            .complete_prompt_argument("system-health", "host", "", &ctx)
            .unwrap();
        assert!(!result.is_empty());
        assert!(result.contains(&"server1".to_string()));
    }

    #[test]
    fn test_complete_host_with_prefix() {
        let ctx = mock::create_test_context();
        let provider = DefaultCompletionProvider;
        // Use a prefix that likely won't match any test host
        let result = provider
            .complete_prompt_argument("system-health", "host", "zzz-nonexistent", &ctx)
            .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_complete_scope_argument() {
        let ctx = mock::create_test_context();
        let provider = DefaultCompletionProvider;
        let result = provider
            .complete_prompt_argument("security-audit", "scope", "s", &ctx)
            .unwrap();
        assert!(result.contains(&"standard".to_string()));
    }

    #[test]
    fn test_complete_environment_argument() {
        let ctx = mock::create_test_context();
        let provider = DefaultCompletionProvider;
        let result = provider
            .complete_prompt_argument("deploy", "environment", "p", &ctx)
            .unwrap();
        assert_eq!(result, vec!["production"]);
    }

    #[test]
    fn test_complete_issue_argument() {
        let ctx = mock::create_test_context();
        let provider = DefaultCompletionProvider;
        let result = provider
            .complete_prompt_argument("troubleshoot", "issue", "d", &ctx)
            .unwrap();
        assert!(result.contains(&"disk-full".to_string()));
    }

    #[test]
    fn test_complete_unknown_argument_returns_empty() {
        let ctx = mock::create_test_context();
        let provider = DefaultCompletionProvider;
        let result = provider
            .complete_prompt_argument("system-health", "nonexistent", "", &ctx)
            .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_complete_resource_host() {
        let ctx = mock::create_test_context_with_host();
        let provider = DefaultCompletionProvider;
        let result = provider
            .complete_resource_argument("metrics://", "host", "", &ctx)
            .unwrap();
        assert!(!result.is_empty());
        assert!(result.contains(&"server1".to_string()));
    }

    #[test]
    fn test_complete_resource_unknown_arg() {
        let ctx = mock::create_test_context();
        let provider = DefaultCompletionProvider;
        let result = provider
            .complete_resource_argument("metrics://", "path", "", &ctx)
            .unwrap();
        assert!(result.is_empty());
    }
}
