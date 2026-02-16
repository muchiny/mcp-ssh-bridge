//! MCP Prompt Handlers
//!
//! This module contains the built-in prompt handlers for the MCP server.

mod backup_verify;
mod deploy;
mod docker_health;
mod k8s_overview;
mod security_audit;
mod system_health;
mod troubleshoot;

pub use backup_verify::BackupVerifyPrompt;
pub use deploy::DeployPrompt;
pub use docker_health::DockerHealthPrompt;
pub use k8s_overview::K8sOverviewPrompt;
pub use security_audit::SecurityAuditPrompt;
pub use system_health::SystemHealthPrompt;
pub use troubleshoot::TroubleshootPrompt;
