//! Prompt Handler Port
//!
//! This module defines the trait for MCP prompt handlers,
//! enabling a plugin-like architecture where each prompt
//! can be implemented independently.

use std::collections::HashMap;

use async_trait::async_trait;

use super::protocol::{PromptArgument, PromptMessage};
use crate::error::Result;
use crate::ports::ToolContext;

/// Trait for prompt handlers
///
/// Each prompt in the MCP server implements this trait, providing
/// a consistent interface for prompt registration and execution.
#[async_trait]
pub trait PromptHandler: Send + Sync {
    /// Get the prompt's name (used for routing)
    fn name(&self) -> &'static str;

    /// Get the prompt's description
    fn description(&self) -> &'static str;

    /// Get the prompt's arguments definition
    fn arguments(&self) -> Vec<PromptArgument>;

    /// Get the prompt messages with the given arguments
    ///
    /// # Arguments
    /// * `args` - The prompt arguments as key-value pairs
    /// * `ctx` - The execution context with dependencies
    ///
    /// # Returns
    /// The prompt messages to send to the LLM
    async fn get(
        &self,
        args: HashMap<String, String>,
        ctx: &ToolContext,
    ) -> Result<Vec<PromptMessage>>;
}
