//! Completion Provider Port
//!
//! This module defines the trait for MCP argument completion,
//! enabling auto-completion of prompt and resource arguments.

use crate::error::Result;
use crate::ports::ToolContext;

/// Trait for providing argument completions.
///
/// Completions are synchronous config-based lookups (no SSH calls needed).
pub trait CompletionProvider: Send + Sync {
    /// Return completions for a prompt argument.
    fn complete_prompt_argument(
        &self,
        prompt_name: &str,
        arg_name: &str,
        prefix: &str,
        ctx: &ToolContext,
    ) -> Result<Vec<String>>;

    /// Return completions for a resource argument.
    fn complete_resource_argument(
        &self,
        uri: &str,
        arg_name: &str,
        prefix: &str,
        ctx: &ToolContext,
    ) -> Result<Vec<String>>;
}
