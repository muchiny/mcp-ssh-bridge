pub mod history;
pub mod prompt_registry;
pub mod prompts;
pub mod protocol;
pub mod registry;
pub mod resource_registry;
pub mod resources;
mod server;
pub mod standard_tool;
pub mod tool_handlers;

pub use history::{CommandHistory, HistoryConfig, HistoryEntry};
pub use prompt_registry::{PromptRegistry, create_default_prompt_registry};
pub use protocol::*;
pub use registry::{ToolRegistry, create_default_registry};
pub use resource_registry::{ResourceRegistry, create_default_resource_registry};
pub use server::McpServer;

// Re-export utils functions for fuzzing
#[doc(hidden)]
pub use tool_handlers::utils::{shell_escape, validate_path};
