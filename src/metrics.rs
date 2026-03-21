//! Application metrics for observability
//!
//! Provides counters and gauges for monitoring tool execution,
//! SSH connections, and request handling.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Application-wide metrics collector
pub struct Metrics {
    /// Total tool call count
    pub tool_calls_total: AtomicU64,
    /// Total tool call errors
    pub tool_errors_total: AtomicU64,
    /// Per-tool call counts
    tool_counts: RwLock<HashMap<String, u64>>,
    /// Per-host call counts
    host_counts: RwLock<HashMap<String, u64>>,
    /// Active SSH connections gauge
    pub ssh_connections_active: AtomicU64,
    /// Total SSH connection attempts
    pub ssh_connections_total: AtomicU64,
    /// Total SSH connection errors
    pub ssh_connection_errors: AtomicU64,
    /// Total requests processed
    pub requests_total: AtomicU64,
    /// Server start time (unix timestamp)
    pub start_time: u64,
}

impl Metrics {
    /// Create a new metrics collector
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_calls_total: AtomicU64::new(0),
            tool_errors_total: AtomicU64::new(0),
            tool_counts: RwLock::new(HashMap::new()),
            host_counts: RwLock::new(HashMap::new()),
            ssh_connections_active: AtomicU64::new(0),
            ssh_connections_total: AtomicU64::new(0),
            ssh_connection_errors: AtomicU64::new(0),
            requests_total: AtomicU64::new(0),
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Record a tool call
    pub fn record_tool_call(&self, tool_name: &str, host: &str) {
        self.tool_calls_total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut counts) = self.tool_counts.write() {
            *counts.entry(tool_name.to_string()).or_insert(0) += 1;
        }
        if let Ok(mut counts) = self.host_counts.write() {
            *counts.entry(host.to_string()).or_insert(0) += 1;
        }
    }

    /// Record a tool error
    pub fn record_tool_error(&self) {
        self.tool_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Render metrics in Prometheus text exposition format
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut output = String::new();

        // Uptime
        let uptime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.start_time);

        let _ = write!(
            output,
            "# HELP mcp_ssh_bridge_uptime_seconds Server uptime in seconds\n\
             # TYPE mcp_ssh_bridge_uptime_seconds gauge\n\
             mcp_ssh_bridge_uptime_seconds {uptime}\n\n"
        );

        let _ = write!(
            output,
            "# HELP mcp_ssh_bridge_requests_total Total requests processed\n\
             # TYPE mcp_ssh_bridge_requests_total counter\n\
             mcp_ssh_bridge_requests_total {}\n\n",
            self.requests_total.load(Ordering::Relaxed)
        );

        let _ = write!(
            output,
            "# HELP mcp_ssh_bridge_tool_calls_total Total tool calls\n\
             # TYPE mcp_ssh_bridge_tool_calls_total counter\n\
             mcp_ssh_bridge_tool_calls_total {}\n\n",
            self.tool_calls_total.load(Ordering::Relaxed)
        );

        let _ = write!(
            output,
            "# HELP mcp_ssh_bridge_tool_errors_total Total tool errors\n\
             # TYPE mcp_ssh_bridge_tool_errors_total counter\n\
             mcp_ssh_bridge_tool_errors_total {}\n\n",
            self.tool_errors_total.load(Ordering::Relaxed)
        );

        let _ = write!(
            output,
            "# HELP mcp_ssh_bridge_ssh_connections_active Active SSH connections\n\
             # TYPE mcp_ssh_bridge_ssh_connections_active gauge\n\
             mcp_ssh_bridge_ssh_connections_active {}\n\n",
            self.ssh_connections_active.load(Ordering::Relaxed)
        );

        let _ = write!(
            output,
            "# HELP mcp_ssh_bridge_ssh_connections_total Total SSH connection attempts\n\
             # TYPE mcp_ssh_bridge_ssh_connections_total counter\n\
             mcp_ssh_bridge_ssh_connections_total {}\n\n",
            self.ssh_connections_total.load(Ordering::Relaxed)
        );

        // Per-tool counts
        if let Ok(counts) = self.tool_counts.read() {
            output.push_str(
                "# HELP mcp_ssh_bridge_tool_calls_by_name Tool calls by tool name\n\
                 # TYPE mcp_ssh_bridge_tool_calls_by_name counter\n",
            );
            for (tool, count) in counts.iter() {
                let _ = writeln!(
                    output,
                    "mcp_ssh_bridge_tool_calls_by_name{{tool=\"{tool}\"}} {count}"
                );
            }
            output.push('\n');
        }

        // Per-host counts
        if let Ok(counts) = self.host_counts.read() {
            output.push_str(
                "# HELP mcp_ssh_bridge_tool_calls_by_host Tool calls by host\n\
                 # TYPE mcp_ssh_bridge_tool_calls_by_host counter\n",
            );
            for (host, count) in counts.iter() {
                let _ = writeln!(
                    output,
                    "mcp_ssh_bridge_tool_calls_by_host{{host=\"{host}\"}} {count}"
                );
            }
            output.push('\n');
        }

        output
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_new() {
        let m = Metrics::new();
        assert_eq!(m.tool_calls_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.tool_errors_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_tool_call() {
        let m = Metrics::new();
        m.record_tool_call("ssh_exec", "prod-1");
        m.record_tool_call("ssh_exec", "prod-2");
        m.record_tool_call("ssh_ls", "prod-1");
        assert_eq!(m.tool_calls_total.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_render_prometheus() {
        let m = Metrics::new();
        m.record_tool_call("ssh_exec", "prod-1");
        m.record_tool_error();
        let output = m.render_prometheus();
        assert!(output.contains("mcp_ssh_bridge_tool_calls_total 1"));
        assert!(output.contains("mcp_ssh_bridge_tool_errors_total 1"));
        assert!(output.contains("ssh_exec"));
        assert!(output.contains("prod-1"));
    }
}
