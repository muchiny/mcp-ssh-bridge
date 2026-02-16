//! Resource Handler Port
//!
//! This module defines the trait for MCP resource handlers,
//! enabling a plugin-like architecture where each resource type
//! can be implemented independently.

use async_trait::async_trait;

use super::protocol::{ResourceContent, ResourceDefinition};
use crate::error::Result;
use crate::ports::ToolContext;

/// Trait for resource handlers
///
/// Each resource type in the MCP server implements this trait, providing
/// a consistent interface for resource registration and reading.
#[async_trait]
pub trait ResourceHandler: Send + Sync {
    /// Get the URI scheme this handler supports (e.g., "file", "log", "metrics")
    fn scheme(&self) -> &'static str;

    /// Get a description of this resource type
    fn description(&self) -> &'static str;

    /// List available resources of this type
    ///
    /// Returns concrete resources that can be listed upfront.
    /// Resource types that are template-based (like file://) may return
    /// an empty list.
    async fn list(&self, ctx: &ToolContext) -> Result<Vec<ResourceDefinition>>;

    /// Read a resource by URI
    ///
    /// # Arguments
    /// * `uri` - The full resource URI (e.g., `metrics://server1`)
    /// * `ctx` - The execution context with dependencies
    async fn read(&self, uri: &str, ctx: &ToolContext) -> Result<Vec<ResourceContent>>;
}
