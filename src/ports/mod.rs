//! Ports module - Trait definitions for hexagonal architecture
//!
//! This module contains the trait definitions (ports) that define
//! the boundaries between the domain logic and external adapters.

mod connector;
mod prompts;
pub mod protocol;
mod resources;
mod ssh;
mod tools;

pub use connector::{SshClientTrait, SshConnector};
pub use prompts::PromptHandler;
pub use protocol::{
    EmbeddedResource, PromptArgument, PromptContent, PromptMessage, ResourceContent,
    ResourceDefinition, ToolAnnotations, ToolCallResult, ToolContent,
};
pub use resources::ResourceHandler;
pub use ssh::{CommandOutput, SshExecutor};
pub use tools::{ToolContext, ToolHandler, ToolSchema};

#[cfg(test)]
pub use connector::mock::{MockSshClient, MockSshConnector};

#[cfg(test)]
pub use tools::mock;
