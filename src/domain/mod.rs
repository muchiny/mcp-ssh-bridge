//! Domain module - Core business logic
//!
//! This module contains the use cases and domain entities that
//! represent the core business logic of the MCP SSH Bridge.

pub mod history;
pub mod output_cache;
pub mod output_truncator;
pub mod use_cases;

pub use history::{CommandHistory, HistoryConfig, HistoryEntry};
pub use output_cache::OutputCache;
pub use use_cases::database::{DatabaseCommandBuilder, DatabaseType};
pub use use_cases::execute_command::{
    ExecuteCommandRequest, ExecuteCommandResponse, ExecuteCommandUseCase,
};
pub use use_cases::tunnel::{TunnelDirection, TunnelInfo, TunnelManager};
