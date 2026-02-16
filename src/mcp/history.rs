//! Command history tracking — re-exported from domain layer
//!
//! The canonical implementation lives in [`crate::domain::history`].
//! This module re-exports for backward compatibility.

pub use crate::domain::history::{CommandHistory, HistoryConfig, HistoryEntry};
