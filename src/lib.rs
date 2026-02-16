// The 197-handler vec! in create_filtered_registry exceeds 16 KiB on the stack
// during test compilation; suppress this lint for test builds.
#![cfg_attr(test, allow(clippy::large_stack_arrays))]

// Use mimalloc allocator when the feature is enabled (recommended for musl builds)
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "cli")]
pub mod cli;
pub mod config;
pub mod domain;
pub mod error;
pub mod mcp;
pub mod ports;
pub mod security;
pub mod ssh;

pub use config::Config;
pub use error::{BridgeError, Result};
pub use mcp::McpServer;
pub use ports::{SshExecutor, ToolAnnotations, ToolContext, ToolHandler, ToolSchema};
pub use security::{AuditLogger, Sanitizer};

// Re-exports for fuzzing
#[doc(hidden)]
pub use config::{HostConfig, SecurityConfig};
#[doc(hidden)]
pub use domain::output_truncator::{ceil_char_boundary, floor_char_boundary, truncate_output};
#[doc(hidden)]
pub use domain::use_cases::ansible::AnsibleCommandBuilder;
#[doc(hidden)]
pub use domain::use_cases::kubernetes::{
    HelmCommandBuilder, KubernetesCommandBuilder, helm_detect_prefix, kubectl_detect_prefix,
};
#[doc(hidden)]
pub use domain::use_cases::parse_metrics::{parse_cpu, parse_disk, parse_load, parse_memory};
#[doc(hidden)]
pub use mcp::protocol::{JsonRpcRequest, ToolCallParams};
#[doc(hidden)]
pub use security::{AuditEvent, CommandResult, CommandValidator, RateLimiter};
#[doc(hidden)]
pub use ssh::TransferMode;
