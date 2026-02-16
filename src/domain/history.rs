//! Command history tracking
//!
//! This module lives in the domain layer because command history is a core
//! business concern used by `ExecuteCommandUseCase` for recording executions.

use std::collections::VecDeque;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::Serialize;

/// A record of an executed command
#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub command: String,
    pub exit_code: u32,
    pub duration_ms: u64,
    pub success: bool,
}

impl HistoryEntry {
    /// Create a new history entry
    #[must_use]
    pub fn new(host: &str, command: &str, exit_code: u32, duration_ms: u64) -> Self {
        Self {
            timestamp: Utc::now(),
            host: host.to_string(),
            command: command.to_string(),
            exit_code,
            duration_ms,
            success: exit_code == 0,
        }
    }

    /// Create a failed entry (for connection/execution errors)
    #[must_use]
    pub fn failed(host: &str, command: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            host: host.to_string(),
            command: command.to_string(),
            exit_code: u32::MAX,
            duration_ms: 0,
            success: false,
        }
    }
}

/// Configuration for command history
#[derive(Debug, Clone)]
pub struct HistoryConfig {
    /// Maximum number of entries to keep
    pub max_entries: usize,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self { max_entries: 100 }
    }
}

/// Command history manager
pub struct CommandHistory {
    entries: Mutex<VecDeque<HistoryEntry>>,
    max_entries: usize,
}

impl CommandHistory {
    /// Create a new command history
    #[must_use]
    pub fn new(config: &HistoryConfig) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(config.max_entries)),
            max_entries: config.max_entries,
        }
    }

    /// Create with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(&HistoryConfig::default())
    }

    /// Add an entry to the history
    pub fn add(&self, entry: HistoryEntry) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };

        // Remove oldest if at capacity
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }

        entries.push_back(entry);
    }

    /// Record a successful command execution
    pub fn record_success(&self, host: &str, command: &str, exit_code: u32, duration_ms: u64) {
        self.add(HistoryEntry::new(host, command, exit_code, duration_ms));
    }

    /// Record a failed command execution
    pub fn record_failure(&self, host: &str, command: &str) {
        self.add(HistoryEntry::failed(host, command));
    }

    /// Get the most recent entries
    pub fn recent(&self, limit: usize) -> Vec<HistoryEntry> {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };

        entries.iter().rev().take(limit).cloned().collect()
    }

    /// Get all entries for a specific host
    pub fn for_host(&self, host: &str, limit: usize) -> Vec<HistoryEntry> {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };

        entries
            .iter()
            .rev()
            .filter(|e| e.host == host)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get the total number of entries
    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// Check if history is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all history
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_entry_success() {
        let entry = HistoryEntry::new("test-host", "ls -la", 0, 100);
        assert!(entry.success);
        assert_eq!(entry.exit_code, 0);
        assert_eq!(entry.host, "test-host");
        assert_eq!(entry.command, "ls -la");
    }

    #[test]
    fn test_history_entry_failure() {
        let entry = HistoryEntry::failed("test-host", "bad-command");
        assert!(!entry.success);
        assert_eq!(entry.exit_code, u32::MAX);
    }

    #[test]
    fn test_history_add_and_recent() {
        let history = CommandHistory::with_defaults();

        history.record_success("host1", "cmd1", 0, 100);
        history.record_success("host2", "cmd2", 0, 200);
        history.record_success("host1", "cmd3", 1, 300);

        let recent = history.recent(10);
        assert_eq!(recent.len(), 3);
        // Most recent first
        assert_eq!(recent[0].command, "cmd3");
        assert_eq!(recent[1].command, "cmd2");
        assert_eq!(recent[2].command, "cmd1");
    }

    #[test]
    fn test_history_for_host() {
        let history = CommandHistory::with_defaults();

        history.record_success("host1", "cmd1", 0, 100);
        history.record_success("host2", "cmd2", 0, 200);
        history.record_success("host1", "cmd3", 0, 300);

        let host1_entries = history.for_host("host1", 10);
        assert_eq!(host1_entries.len(), 2);
        assert_eq!(host1_entries[0].command, "cmd3");
        assert_eq!(host1_entries[1].command, "cmd1");
    }

    #[test]
    fn test_history_max_entries() {
        let config = HistoryConfig { max_entries: 3 };
        let history = CommandHistory::new(&config);

        history.record_success("host", "cmd1", 0, 100);
        history.record_success("host", "cmd2", 0, 100);
        history.record_success("host", "cmd3", 0, 100);
        history.record_success("host", "cmd4", 0, 100);

        assert_eq!(history.len(), 3);

        let recent = history.recent(10);
        assert_eq!(recent[0].command, "cmd4");
        assert_eq!(recent[2].command, "cmd2");
        // cmd1 was evicted
    }

    #[test]
    fn test_history_clear() {
        let history = CommandHistory::with_defaults();

        history.record_success("host", "cmd1", 0, 100);
        history.record_success("host", "cmd2", 0, 100);

        assert_eq!(history.len(), 2);

        history.clear();
        assert!(history.is_empty());
    }
}
