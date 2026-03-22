//! Tool Registry
//!
//! This module provides a registry for tool handlers, enabling
//! dynamic registration and lookup of tools at runtime.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;

use crate::config::ToolGroupsConfig;
use crate::error::{BridgeError, Result};
use crate::mcp::protocol::{Tool, ToolAnnotations, ToolCallResult, ToolExecution};
#[cfg(test)]
use crate::ports::ToolSchema;
use crate::ports::{ToolContext, ToolHandler};

/// Registry for tool handlers
///
/// The registry maintains a collection of tool handlers and provides
/// methods for registering, looking up, and listing available tools.
#[derive(Default)]
pub struct ToolRegistry {
    handlers: HashMap<String, Arc<dyn ToolHandler>>,
}

impl ToolRegistry {
    /// Create a new empty registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a tool handler
    pub fn register(&mut self, handler: Arc<dyn ToolHandler>) {
        let name = handler.name().to_string();
        self.handlers.insert(name, handler);
    }

    /// Get a tool handler by name
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Arc<dyn ToolHandler>> {
        self.handlers.get(name)
    }

    /// Execute a tool by name
    ///
    /// # Errors
    ///
    /// Returns an error if the tool is not found or if the tool execution fails.
    pub async fn execute(
        &self,
        tool_name: &str,
        args: Option<serde_json::Value>,
        ctx: &ToolContext,
    ) -> Result<ToolCallResult> {
        let handler = self
            .get(tool_name)
            .ok_or_else(|| BridgeError::McpUnknownTool {
                tool: tool_name.to_string(),
            })?;

        handler.execute(args, ctx).await
    }

    /// Get all registered tools as MCP Tool definitions
    #[must_use]
    pub fn list_tools(&self) -> Vec<Tool> {
        self.handlers
            .values()
            .map(|handler| {
                let schema = handler.schema();
                let annotations = tool_annotations(schema.name);
                Tool {
                    name: schema.name.to_string(),
                    description: schema.description.to_string(),
                    input_schema: serde_json::from_str(schema.input_schema).unwrap_or_else(|e| {
                        tracing::error!(
                            tool = schema.name,
                            error = %e,
                            "Invalid tool input schema JSON, falling back to empty schema"
                        );
                        json!({})
                    }),
                    annotations: if annotations.is_empty() {
                        None
                    } else {
                        Some(annotations)
                    },
                    execution: Some(ToolExecution {
                        task_support: "optional".to_string(),
                    }),
                    output_schema: None,
                }
            })
            .collect()
    }

    /// Get the number of registered tools
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Check if the registry is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

/// Map a tool name to its group.
///
/// Tools are organized into logical groups that can be enabled/disabled
/// via the `tool_groups` configuration to reduce MCP context.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn tool_group(tool_name: &str) -> &'static str {
    match tool_name {
        "ssh_upload" | "ssh_download" | "ssh_sync" => "file_transfer",
        "ssh_session_create" | "ssh_session_exec" | "ssh_session_list" | "ssh_session_close" => {
            "sessions"
        }
        "ssh_metrics" | "ssh_metrics_multi" | "ssh_tail" | "ssh_disk_usage" => "monitoring",
        "ssh_tunnel_create" | "ssh_tunnel_list" | "ssh_tunnel_close" => "tunnels",
        "ssh_ls" | "ssh_find" => "directory",
        "ssh_db_query" | "ssh_db_dump" | "ssh_db_restore" => "database",
        "ssh_backup_create" | "ssh_backup_list" | "ssh_backup_restore" => "backup",
        "ssh_docker_ps"
        | "ssh_docker_logs"
        | "ssh_docker_inspect"
        | "ssh_docker_exec"
        | "ssh_docker_compose"
        | "ssh_docker_images"
        | "ssh_docker_stats"
        | "ssh_docker_volume_ls"
        | "ssh_docker_network_ls"
        | "ssh_docker_volume_inspect"
        | "ssh_docker_network_inspect" => "docker",
        "ssh_esxi_vm_list"
        | "ssh_esxi_vm_info"
        | "ssh_esxi_vm_power"
        | "ssh_esxi_snapshot"
        | "ssh_esxi_host_info"
        | "ssh_esxi_datastore_list"
        | "ssh_esxi_network_list" => "esxi",
        "ssh_git_status" | "ssh_git_log" | "ssh_git_diff" | "ssh_git_pull" | "ssh_git_clone"
        | "ssh_git_branch" | "ssh_git_checkout" => "git",
        "ssh_k8s_get" | "ssh_k8s_logs" | "ssh_k8s_describe" | "ssh_k8s_apply"
        | "ssh_k8s_delete" | "ssh_k8s_rollout" | "ssh_k8s_scale" | "ssh_k8s_exec"
        | "ssh_k8s_top" | "ssh_helm_list" | "ssh_helm_status" | "ssh_helm_upgrade"
        | "ssh_helm_install" | "ssh_helm_rollback" | "ssh_helm_history" | "ssh_helm_uninstall" => {
            "kubernetes"
        }
        "ssh_ansible_playbook" | "ssh_ansible_inventory" | "ssh_ansible_adhoc" => "ansible",
        // New groups
        "ssh_service_status"
        | "ssh_service_start"
        | "ssh_service_stop"
        | "ssh_service_restart"
        | "ssh_service_list"
        | "ssh_service_logs"
        | "ssh_service_enable"
        | "ssh_service_disable"
        | "ssh_service_daemon_reload" => "systemd",
        "ssh_net_connections"
        | "ssh_net_interfaces"
        | "ssh_net_routes"
        | "ssh_net_ping"
        | "ssh_net_traceroute"
        | "ssh_net_dns" => "network",
        "ssh_process_list" | "ssh_process_kill" | "ssh_process_top" => "process",
        "ssh_pkg_list" | "ssh_pkg_search" | "ssh_pkg_install" | "ssh_pkg_update"
        | "ssh_pkg_remove" => "package",
        "ssh_firewall_status"
        | "ssh_firewall_list"
        | "ssh_firewall_allow"
        | "ssh_firewall_deny" => "firewall",
        "ssh_cron_list" | "ssh_cron_add" | "ssh_cron_remove" => "cron",
        "ssh_cron_analyze" | "ssh_cron_history" | "ssh_at_jobs" => "cron_analysis",
        "ssh_perf_trace" | "ssh_io_trace" | "ssh_latency_test" | "ssh_benchmark" => "performance",
        "ssh_container_log_search"
        | "ssh_container_log_stats"
        | "ssh_container_events"
        | "ssh_container_health_history" => "container_logs",
        "ssh_port_scan" | "ssh_ssl_audit" | "ssh_network_capture" | "ssh_fail2ban_status" => {
            "network_security"
        }
        "ssh_cis_benchmark"
        | "ssh_stig_check"
        | "ssh_compliance_score"
        | "ssh_compliance_report" => "compliance",
        "ssh_alert_set" | "ssh_alert_list" | "ssh_alert_check" => "alerting",
        "ssh_capacity_collect" | "ssh_capacity_trend" | "ssh_capacity_predict" => "capacity",
        "ssh_incident_timeline" | "ssh_incident_correlate" => "incident",
        "ssh_log_search_multi" | "ssh_log_aggregate" | "ssh_log_tail_multi" => "log_aggregation",
        "ssh_key_generate" | "ssh_key_distribute" | "ssh_key_audit" => "key_management",
        "ssh_backup_snapshot" | "ssh_backup_verify" | "ssh_backup_schedule" => "backup",
        "ssh_webhook_send" | "ssh_notify" => "chatops",
        "ssh_aws_cli" | "ssh_cloud_metadata" | "ssh_cloud_tags" | "ssh_cloud_cost" => "cloud",
        "ssh_discover_hosts" | "ssh_inventory_sync" | "ssh_host_tags" => "inventory",
        "ssh_multicloud_list" | "ssh_multicloud_sync" | "ssh_multicloud_compare" => "multicloud",
        "ssh_cert_check" | "ssh_cert_info" | "ssh_cert_expiry" => "certificates",
        "ssh_nginx_status" | "ssh_nginx_test" | "ssh_nginx_reload" | "ssh_nginx_list_sites" => {
            "nginx"
        }
        "ssh_redis_info" | "ssh_redis_cli" | "ssh_redis_keys" => "redis",
        "ssh_postgresql_query" | "ssh_postgresql_status" => "postgresql",
        "ssh_mysql_query" | "ssh_mysql_status" => "mysql",
        "ssh_apache_status" | "ssh_apache_vhosts" => "apache",
        "ssh_letsencrypt_status" => "letsencrypt",
        "ssh_mongodb_status" => "mongodb",
        "ssh_terraform_init"
        | "ssh_terraform_plan"
        | "ssh_terraform_apply"
        | "ssh_terraform_state"
        | "ssh_terraform_output" => "terraform",
        "ssh_vault_status" | "ssh_vault_read" | "ssh_vault_list" | "ssh_vault_write" => "vault",
        "ssh_config_get" | "ssh_config_set" => "config",
        // Diagnostics
        "ssh_diagnose" | "ssh_incident_triage" | "ssh_compare_state" => "diagnostics",
        // Runbooks
        "ssh_runbook_list" | "ssh_runbook_execute" | "ssh_runbook_validate" => "runbooks",
        // Recording / Compliance
        "ssh_recording_start"
        | "ssh_recording_stop"
        | "ssh_recording_list"
        | "ssh_recording_replay"
        | "ssh_recording_verify" => "recording",
        // Orchestration
        "ssh_canary_exec" | "ssh_rolling_exec" | "ssh_fleet_diff" => "orchestration",
        // Drift Detection
        "ssh_env_snapshot" | "ssh_env_diff" | "ssh_env_drift" => "drift",
        // Security Scanning
        "ssh_sbom_generate" | "ssh_vuln_scan" | "ssh_compliance_check" => "security_scan",
        // File Operations (including advanced)
        "ssh_file_read" | "ssh_file_write" | "ssh_file_chmod" | "ssh_file_chown"
        | "ssh_file_stat" | "ssh_file_diff" | "ssh_file_patch" | "ssh_file_template" => {
            "file_ops"
        }
        // User Management
        "ssh_user_list" | "ssh_user_info" | "ssh_user_add" | "ssh_user_modify"
        | "ssh_user_delete" | "ssh_group_list" | "ssh_group_add" | "ssh_group_delete" => {
            "user_management"
        }
        // Storage
        "ssh_storage_lsblk" | "ssh_storage_df" | "ssh_storage_mount" | "ssh_storage_umount"
        | "ssh_storage_lvm" | "ssh_storage_fdisk" | "ssh_storage_fstab" => "storage",
        // Journald
        "ssh_journal_query" | "ssh_journal_follow" | "ssh_journal_boots"
        | "ssh_journal_disk_usage" => "journald",
        // Systemd Timers
        "ssh_timer_list" | "ssh_timer_info" | "ssh_timer_enable" | "ssh_timer_disable"
        | "ssh_timer_trigger" => "systemd_timers",
        // Security Modules
        "ssh_selinux_status" | "ssh_selinux_booleans" | "ssh_apparmor_status"
        | "ssh_apparmor_profiles" | "ssh_security_audit" => "security_modules",
        // Network Equipment
        "ssh_net_equip_show_run" | "ssh_net_equip_show_interfaces"
        | "ssh_net_equip_show_routes" | "ssh_net_equip_show_arp"
        | "ssh_net_equip_show_version" | "ssh_net_equip_show_vlans" | "ssh_net_equip_config"
        | "ssh_net_equip_save" => "network_equipment",
        // Podman
        "ssh_podman_ps" | "ssh_podman_logs" | "ssh_podman_inspect" | "ssh_podman_exec"
        | "ssh_podman_images" | "ssh_podman_compose" => "podman",
        // LDAP
        "ssh_ldap_search" | "ssh_ldap_user_info" | "ssh_ldap_group_members" | "ssh_ldap_add"
        | "ssh_ldap_modify" => "ldap",
        // Windows Services
        "ssh_win_service_status"
        | "ssh_win_service_start"
        | "ssh_win_service_stop"
        | "ssh_win_service_restart"
        | "ssh_win_service_list"
        | "ssh_win_service_enable"
        | "ssh_win_service_disable"
        | "ssh_win_service_config" => "windows_services",
        // Windows Events
        "ssh_win_event_logs"
        | "ssh_win_event_query"
        | "ssh_win_event_sources"
        | "ssh_win_event_tail"
        | "ssh_win_event_export" => "windows_events",
        // Active Directory
        "ssh_ad_user_list"
        | "ssh_ad_user_info"
        | "ssh_ad_group_list"
        | "ssh_ad_group_members"
        | "ssh_ad_computer_list"
        | "ssh_ad_domain_info" => "active_directory",
        // Scheduled Tasks
        "ssh_schtask_list"
        | "ssh_schtask_info"
        | "ssh_schtask_run"
        | "ssh_schtask_enable"
        | "ssh_schtask_disable" => "scheduled_tasks",
        // Windows Firewall
        "ssh_win_firewall_status"
        | "ssh_win_firewall_list"
        | "ssh_win_firewall_allow"
        | "ssh_win_firewall_deny"
        | "ssh_win_firewall_remove" => "windows_firewall",
        // IIS
        "ssh_iis_status" | "ssh_iis_list_sites" | "ssh_iis_list_pools" | "ssh_iis_start"
        | "ssh_iis_stop" | "ssh_iis_restart" => "iis",
        // Windows Updates
        "ssh_win_update_list"
        | "ssh_win_update_history"
        | "ssh_win_update_install"
        | "ssh_win_update_search"
        | "ssh_win_update_reboot" => "windows_updates",
        // Windows Performance
        "ssh_win_perf_cpu"
        | "ssh_win_perf_memory"
        | "ssh_win_perf_disk"
        | "ssh_win_perf_network"
        | "ssh_win_perf_overview"
        | "ssh_win_disk_usage" => "windows_perf",
        // Hyper-V
        "ssh_hyperv_vm_list"
        | "ssh_hyperv_vm_info"
        | "ssh_hyperv_vm_start"
        | "ssh_hyperv_vm_stop"
        | "ssh_hyperv_snapshot_list"
        | "ssh_hyperv_snapshot_create"
        | "ssh_hyperv_host_info"
        | "ssh_hyperv_switch_list" => "hyperv",
        // Windows Registry
        "ssh_reg_query" | "ssh_reg_set" | "ssh_reg_list" | "ssh_reg_export" | "ssh_reg_delete" => {
            "windows_registry"
        }
        // Windows Features
        "ssh_win_feature_list"
        | "ssh_win_feature_info"
        | "ssh_win_feature_install"
        | "ssh_win_feature_remove" => "windows_features",
        // Windows Network
        "ssh_win_net_adapters"
        | "ssh_win_net_ip"
        | "ssh_win_net_routes"
        | "ssh_win_net_connections"
        | "ssh_win_net_ping"
        | "ssh_win_net_dns" => "windows_network",
        // Windows Process
        "ssh_win_process_list"
        | "ssh_win_process_info"
        | "ssh_win_process_kill"
        | "ssh_win_process_top"
        | "ssh_win_process_by_name" => "windows_process",
        // Core group: ssh_exec, ssh_exec_multi, ssh_status, ssh_health, ssh_history, ssh_output_fetch
        // Unknown tools also default to core
        _ => "core",
    }
}

/// Return MCP annotations for a tool (MCP 2025-03-26+).
///
/// Annotations provide behavioral hints to MCP clients. Claude Code uses
/// `readOnlyHint` to enable parallel execution and skip confirmation, and
/// `destructiveHint` to trigger confirmation dialogs.
///
/// Categories:
/// - **Read-only** (~62 tools): status, list, get, logs, info, check commands
/// - **Destructive** (8 tools): delete, kill, remove, uninstall, deny, stop
/// - **Idempotent mutating** (5 tools): apply, restart, init, reload, plan
/// - **Mutating** (~38 tools): exec, create, start, install, write, upload
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn tool_annotations(tool_name: &str) -> ToolAnnotations {
    match tool_name {
        // ================================================================
        // Read-only tools: safe for parallel execution
        // ================================================================

        // Core
        "ssh_status" => ToolAnnotations::read_only("SSH Connection Status"),
        "ssh_health" => ToolAnnotations::read_only("SSH Host Health Check"),
        "ssh_history" => ToolAnnotations::read_only("Command History"),
        "ssh_output_fetch" => ToolAnnotations::read_only("Fetch Cached Output"),

        // Monitoring
        "ssh_metrics" => ToolAnnotations::read_only("Host Metrics"),
        "ssh_metrics_multi" => ToolAnnotations::read_only("Multi-Host Metrics"),
        "ssh_tail" => ToolAnnotations::read_only("Tail Remote File"),

        // Directory
        "ssh_ls" => ToolAnnotations::read_only("List Directory"),
        "ssh_find" => ToolAnnotations::read_only("Find Files"),

        // Disk
        "ssh_disk_usage" => ToolAnnotations::read_only("Disk Usage"),

        // Docker read-only
        "ssh_docker_ps" => ToolAnnotations::read_only("List Docker Containers"),
        "ssh_docker_logs" => ToolAnnotations::read_only("Docker Container Logs"),
        "ssh_docker_inspect" => ToolAnnotations::read_only("Inspect Docker Container"),
        "ssh_docker_images" => ToolAnnotations::read_only("List Docker Images"),
        "ssh_docker_stats" => ToolAnnotations::read_only("Docker Container Stats"),
        "ssh_docker_volume_ls" => ToolAnnotations::read_only("List Docker Volumes"),
        "ssh_docker_network_ls" => ToolAnnotations::read_only("List Docker Networks"),
        "ssh_docker_volume_inspect" => ToolAnnotations::read_only("Inspect Docker Volume"),
        "ssh_docker_network_inspect" => ToolAnnotations::read_only("Inspect Docker Network"),

        // ESXi read-only
        "ssh_esxi_vm_list" => ToolAnnotations::read_only("List ESXi VMs"),
        "ssh_esxi_vm_info" => ToolAnnotations::read_only("ESXi VM Info"),
        "ssh_esxi_host_info" => ToolAnnotations::read_only("ESXi Host Info"),
        "ssh_esxi_datastore_list" => ToolAnnotations::read_only("List ESXi Datastores"),
        "ssh_esxi_network_list" => ToolAnnotations::read_only("List ESXi Networks"),

        // Git read-only
        "ssh_git_status" => ToolAnnotations::read_only("Git Status"),
        "ssh_git_log" => ToolAnnotations::read_only("Git Log"),
        "ssh_git_diff" => ToolAnnotations::read_only("Git Diff"),

        // Kubernetes read-only
        "ssh_k8s_get" => ToolAnnotations::read_only("Kubectl Get"),
        "ssh_k8s_logs" => ToolAnnotations::read_only("Kubectl Logs"),
        "ssh_k8s_describe" => ToolAnnotations::read_only("Kubectl Describe"),
        "ssh_k8s_top" => ToolAnnotations::read_only("Kubectl Top"),
        "ssh_helm_list" => ToolAnnotations::read_only("Helm Releases"),
        "ssh_helm_status" => ToolAnnotations::read_only("Helm Release Status"),
        "ssh_helm_history" => ToolAnnotations::read_only("Helm Release History"),

        // Ansible read-only
        "ssh_ansible_inventory" => ToolAnnotations::read_only("Ansible Inventory"),

        // Systemd read-only
        "ssh_service_status" => ToolAnnotations::read_only("Service Status"),
        "ssh_service_list" => ToolAnnotations::read_only("List Services"),
        "ssh_service_logs" => ToolAnnotations::read_only("Service Logs"),

        // Network read-only
        "ssh_net_connections" => ToolAnnotations::read_only("Network Connections"),
        "ssh_net_interfaces" => ToolAnnotations::read_only("Network Interfaces"),
        "ssh_net_routes" => ToolAnnotations::read_only("Network Routes"),
        "ssh_net_ping" => ToolAnnotations::read_only("Ping Host"),
        "ssh_net_traceroute" => ToolAnnotations::read_only("Traceroute"),
        "ssh_net_dns" => ToolAnnotations::read_only("DNS Lookup"),

        // Process read-only
        "ssh_process_list" => ToolAnnotations::read_only("List Processes"),
        "ssh_process_top" => ToolAnnotations::read_only("Process Top"),

        // Package read-only
        "ssh_pkg_list" => ToolAnnotations::read_only("List Packages"),
        "ssh_pkg_search" => ToolAnnotations::read_only("Search Packages"),

        // Firewall read-only
        "ssh_firewall_status" => ToolAnnotations::read_only("Firewall Status"),
        "ssh_firewall_list" => ToolAnnotations::read_only("List Firewall Rules"),

        // Cron read-only
        "ssh_cron_list" => ToolAnnotations::read_only("List Cron Jobs"),

        // Cron Analysis read-only
        "ssh_cron_analyze" => ToolAnnotations::read_only("Analyze Cron Jobs"),
        "ssh_cron_history" => ToolAnnotations::read_only("Cron Execution History"),
        "ssh_at_jobs" => ToolAnnotations::read_only("List At Jobs"),

        // Performance read-only
        "ssh_perf_trace" => ToolAnnotations::read_only("Performance Trace"),
        "ssh_io_trace" => ToolAnnotations::read_only("I/O Trace"),
        "ssh_latency_test" => ToolAnnotations::read_only("Latency Test"),
        "ssh_benchmark" => ToolAnnotations::read_only("Performance Benchmark"),

        // Container Logs read-only
        "ssh_container_log_search" => ToolAnnotations::read_only("Search Container Logs"),
        "ssh_container_log_stats" => ToolAnnotations::read_only("Container Log Stats"),
        "ssh_container_events" => ToolAnnotations::read_only("Container Events"),
        "ssh_container_health_history" => ToolAnnotations::read_only("Container Health History"),

        // Network Security read-only
        "ssh_port_scan" => ToolAnnotations::read_only("Port Scan"),
        "ssh_ssl_audit" => ToolAnnotations::read_only("SSL/TLS Audit"),
        "ssh_network_capture" => ToolAnnotations::read_only("Network Capture"),
        "ssh_fail2ban_status" => ToolAnnotations::read_only("Fail2ban Status"),

        // Compliance read-only
        "ssh_cis_benchmark" => ToolAnnotations::read_only("CIS Benchmark"),
        "ssh_stig_check" => ToolAnnotations::read_only("STIG Check"),
        "ssh_compliance_score" => ToolAnnotations::read_only("Compliance Score"),
        "ssh_compliance_report" => ToolAnnotations::read_only("Compliance Report"),

        // Alerting
        "ssh_alert_set" => ToolAnnotations::read_only("Alert Set"),
        "ssh_alert_list" => ToolAnnotations::read_only("Alert List"),
        "ssh_alert_check" => ToolAnnotations::read_only("Alert Check"),

        // Capacity read-only
        "ssh_capacity_collect" => ToolAnnotations::read_only("Capacity Collect"),
        "ssh_capacity_trend" => ToolAnnotations::read_only("Capacity Trend"),
        "ssh_capacity_predict" => ToolAnnotations::read_only("Capacity Predict"),

        // Incident read-only
        "ssh_incident_timeline" => ToolAnnotations::read_only("Incident Timeline"),
        "ssh_incident_correlate" => ToolAnnotations::read_only("Incident Correlate"),

        // Log Aggregation read-only
        "ssh_log_search_multi" => ToolAnnotations::read_only("Log Search Multi"),
        "ssh_log_aggregate" => ToolAnnotations::read_only("Log Aggregate"),
        "ssh_log_tail_multi" => ToolAnnotations::read_only("Log Tail Multi"),

        // Key Management
        "ssh_key_generate" => ToolAnnotations::mutating("Generate SSH Key"),
        "ssh_key_distribute" => ToolAnnotations::mutating("Distribute SSH Key"),
        "ssh_key_audit" => ToolAnnotations::read_only("SSH Key Audit"),

        // Backup Enhanced
        "ssh_backup_snapshot" => ToolAnnotations::mutating("Backup Snapshot"),
        "ssh_backup_verify" => ToolAnnotations::read_only("Backup Verify"),
        "ssh_backup_schedule" => ToolAnnotations::mutating("Backup Schedule"),

        // ChatOps
        "ssh_webhook_send" => ToolAnnotations::mutating("Webhook Send"),
        "ssh_notify" => ToolAnnotations::mutating("Notify"),

        // Cloud read-only
        "ssh_aws_cli" => ToolAnnotations::read_only("AWS CLI"),
        "ssh_cloud_metadata" => ToolAnnotations::read_only("Cloud Metadata"),
        "ssh_cloud_tags" => ToolAnnotations::read_only("Cloud Tags"),
        "ssh_cloud_cost" => ToolAnnotations::read_only("Cloud Cost"),

        // Inventory
        "ssh_discover_hosts" => ToolAnnotations::read_only("Discover Hosts"),
        "ssh_inventory_sync" => ToolAnnotations::read_only("Inventory Sync"),
        "ssh_host_tags" => ToolAnnotations::mutating("Host Tags"),

        // Multi-cloud read-only
        "ssh_multicloud_list" => ToolAnnotations::read_only("Multi-cloud List"),
        "ssh_multicloud_sync" => ToolAnnotations::read_only("Multi-cloud Sync"),
        "ssh_multicloud_compare" => ToolAnnotations::read_only("Multi-cloud Compare"),

        // Certificates read-only
        "ssh_cert_check" => ToolAnnotations::read_only("Check Remote Certificate"),
        "ssh_cert_info" => ToolAnnotations::read_only("Certificate File Info"),
        "ssh_cert_expiry" => ToolAnnotations::read_only("Certificate Expiry"),

        // Nginx read-only
        "ssh_nginx_status" => ToolAnnotations::read_only("Nginx Status"),
        "ssh_nginx_test" => ToolAnnotations::read_only("Nginx Config Test"),
        "ssh_nginx_list_sites" => ToolAnnotations::read_only("List Nginx Sites"),

        // Diagnostics
        "ssh_diagnose" => ToolAnnotations::read_only("Host Diagnostics"),
        "ssh_incident_triage" => ToolAnnotations::read_only("Incident Triage"),
        "ssh_compare_state" => ToolAnnotations::read_only("Capture System State"),

        // Runbooks
        "ssh_runbook_list" => ToolAnnotations::read_only("List Runbooks"),
        "ssh_runbook_validate" => ToolAnnotations::read_only("Validate Runbook"),
        "ssh_runbook_execute" => ToolAnnotations::destructive("Execute Runbook"),

        // Recording
        "ssh_recording_list" => ToolAnnotations::read_only("List Recordings"),
        "ssh_recording_replay" => ToolAnnotations::read_only("Replay Recording"),
        "ssh_recording_verify" => ToolAnnotations::read_only("Verify Recording Integrity"),
        "ssh_recording_start" => ToolAnnotations::mutating("Start Recording"),
        "ssh_recording_stop" => ToolAnnotations::mutating("Stop Recording"),

        // Redis read-only
        "ssh_redis_info" => ToolAnnotations::read_only("Redis Info"),
        "ssh_redis_keys" => ToolAnnotations::read_only("List Redis Keys"),

        // PostgreSQL
        "ssh_postgresql_status" => ToolAnnotations::read_only("PostgreSQL Status"),
        "ssh_postgresql_query" => ToolAnnotations::mutating("PostgreSQL Query"),

        // MySQL
        "ssh_mysql_status" => ToolAnnotations::read_only("MySQL Status"),
        "ssh_mysql_query" => ToolAnnotations::mutating("MySQL Query"),

        // Apache read-only
        "ssh_apache_status" => ToolAnnotations::read_only("Apache Status"),
        "ssh_apache_vhosts" => ToolAnnotations::read_only("Apache Virtual Hosts"),

        // Let's Encrypt read-only
        "ssh_letsencrypt_status" => ToolAnnotations::read_only("Let's Encrypt Status"),

        // MongoDB read-only
        "ssh_mongodb_status" => ToolAnnotations::read_only("MongoDB Status"),

        // Terraform read-only
        "ssh_terraform_state" => ToolAnnotations::read_only("Terraform State"),
        "ssh_terraform_output" => ToolAnnotations::read_only("Terraform Output"),

        // Vault read-only
        "ssh_vault_status" => ToolAnnotations::read_only("Vault Status"),
        "ssh_vault_read" => ToolAnnotations::read_only("Vault Read Secret"),
        "ssh_vault_list" => ToolAnnotations::read_only("List Vault Secrets"),

        // Config read-only
        "ssh_config_get" => ToolAnnotations::read_only("Get Runtime Config"),

        // Sessions/Tunnels/Backup read-only
        "ssh_session_list" => ToolAnnotations::read_only("List SSH Sessions"),
        "ssh_tunnel_list" => ToolAnnotations::read_only("List SSH Tunnels"),
        "ssh_backup_list" => ToolAnnotations::read_only("List Backups"),

        // ================================================================
        // Destructive tools: trigger confirmation dialogs
        // ================================================================
        "ssh_k8s_delete" => ToolAnnotations::destructive("Kubectl Delete"),
        "ssh_helm_uninstall" => ToolAnnotations::destructive("Helm Uninstall"),
        "ssh_process_kill" => ToolAnnotations::destructive("Kill Process"),
        "ssh_cron_remove" => ToolAnnotations::destructive("Remove Cron Job"),
        "ssh_session_close" => ToolAnnotations::destructive("Close SSH Session"),
        "ssh_tunnel_close" => ToolAnnotations::destructive("Close SSH Tunnel"),
        "ssh_firewall_deny" => ToolAnnotations::destructive("Deny Firewall Rule"),
        "ssh_service_stop" => ToolAnnotations::destructive("Stop Service"),
        "ssh_pkg_remove" => ToolAnnotations::destructive("Remove Package"),

        // ================================================================
        // Idempotent mutating tools: safe to retry
        // ================================================================
        "ssh_k8s_apply" => ToolAnnotations {
            title: Some("Kubectl Apply".to_string()),
            read_only_hint: Some(false),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(true),
        },
        "ssh_service_restart" => ToolAnnotations {
            title: Some("Restart Service".to_string()),
            read_only_hint: Some(false),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(true),
        },
        "ssh_terraform_plan" => ToolAnnotations {
            title: Some("Terraform Plan".to_string()),
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(true),
        },
        "ssh_terraform_init" => ToolAnnotations {
            title: Some("Terraform Init".to_string()),
            read_only_hint: Some(false),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(true),
        },
        "ssh_nginx_reload" => ToolAnnotations {
            title: Some("Reload Nginx".to_string()),
            read_only_hint: Some(false),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(true),
        },
        "ssh_service_daemon_reload" => ToolAnnotations {
            title: Some("Systemd Daemon Reload".to_string()),
            read_only_hint: Some(false),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(true),
        },

        // ================================================================
        // Mutating tools: non-destructive but modifying state
        // ================================================================
        "ssh_exec" => ToolAnnotations::mutating("Execute SSH Command"),
        "ssh_exec_multi" => ToolAnnotations::mutating("Execute on Multiple Hosts"),
        "ssh_session_create" => ToolAnnotations::mutating("Create SSH Session"),
        "ssh_session_exec" => ToolAnnotations::mutating("Execute in Session"),
        "ssh_docker_exec" => ToolAnnotations::mutating("Docker Exec"),
        "ssh_docker_compose" => ToolAnnotations::mutating("Docker Compose"),
        "ssh_git_pull" => ToolAnnotations::mutating("Git Pull"),
        "ssh_git_clone" => ToolAnnotations::mutating("Git Clone"),
        "ssh_git_branch" => ToolAnnotations::mutating("Git Branch"),
        "ssh_git_checkout" => ToolAnnotations::mutating("Git Checkout"),
        "ssh_k8s_rollout" => ToolAnnotations::mutating("Kubectl Rollout"),
        "ssh_k8s_scale" => ToolAnnotations::mutating("Kubectl Scale"),
        "ssh_k8s_exec" => ToolAnnotations::mutating("Kubectl Exec"),
        "ssh_helm_upgrade" => ToolAnnotations::mutating("Helm Upgrade"),
        "ssh_helm_install" => ToolAnnotations::mutating("Helm Install"),
        "ssh_helm_rollback" => ToolAnnotations::mutating("Helm Rollback"),
        "ssh_ansible_playbook" => ToolAnnotations::mutating("Run Ansible Playbook"),
        "ssh_ansible_adhoc" => ToolAnnotations::mutating("Ansible Ad-Hoc Command"),
        "ssh_service_start" => ToolAnnotations::mutating("Start Service"),
        "ssh_service_enable" => ToolAnnotations::mutating("Enable Service"),
        "ssh_service_disable" => ToolAnnotations::mutating("Disable Service"),
        "ssh_pkg_install" => ToolAnnotations::mutating("Install Package"),
        "ssh_pkg_update" => ToolAnnotations::mutating("Update Packages"),
        "ssh_firewall_allow" => ToolAnnotations::mutating("Allow Firewall Rule"),
        "ssh_cron_add" => ToolAnnotations::mutating("Add Cron Job"),
        "ssh_terraform_apply" => ToolAnnotations::mutating("Terraform Apply"),
        "ssh_vault_write" => ToolAnnotations::mutating("Vault Write Secret"),
        "ssh_config_set" => ToolAnnotations::mutating("Set Runtime Config"),
        "ssh_upload" => ToolAnnotations::mutating("Upload File"),
        "ssh_download" => ToolAnnotations::mutating("Download File"),
        "ssh_sync" => ToolAnnotations::mutating("Sync Files"),
        "ssh_tunnel_create" => ToolAnnotations::mutating("Create SSH Tunnel"),
        "ssh_backup_create" => ToolAnnotations::mutating("Create Backup"),
        "ssh_backup_restore" => ToolAnnotations::mutating("Restore Backup"),
        "ssh_db_query" => ToolAnnotations::mutating("Database Query"),
        "ssh_db_dump" => ToolAnnotations::mutating("Database Dump"),
        "ssh_db_restore" => ToolAnnotations::mutating("Database Restore"),
        "ssh_redis_cli" => ToolAnnotations::mutating("Redis CLI"),
        "ssh_esxi_vm_power" => ToolAnnotations::mutating("ESXi VM Power"),
        "ssh_esxi_snapshot" => ToolAnnotations::mutating("ESXi Snapshot"),

        // ================================================================
        // Windows Services
        // ================================================================
        "ssh_win_service_status" => ToolAnnotations::read_only("Windows Service Status"),
        "ssh_win_service_list" => ToolAnnotations::read_only("List Windows Services"),
        "ssh_win_service_config" => ToolAnnotations::read_only("Windows Service Config"),
        "ssh_win_event_logs" => ToolAnnotations::read_only("Windows Event Logs"),
        "ssh_win_service_start" => ToolAnnotations::mutating("Start Windows Service"),
        "ssh_win_service_restart" => ToolAnnotations {
            title: Some("Restart Windows Service".to_string()),
            read_only_hint: Some(false),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(true),
        },
        "ssh_win_service_enable" => ToolAnnotations::mutating("Enable Windows Service"),
        "ssh_win_service_disable" => ToolAnnotations::mutating("Disable Windows Service"),
        "ssh_win_service_stop" => ToolAnnotations::destructive("Stop Windows Service"),

        // ================================================================
        // Windows Events
        // ================================================================
        "ssh_win_event_query" => ToolAnnotations::read_only("Query Windows Events"),
        "ssh_win_event_sources" => ToolAnnotations::read_only("List Windows Event Sources"),
        "ssh_win_event_tail" => ToolAnnotations::read_only("Tail Windows Events"),
        "ssh_win_event_export" => ToolAnnotations::mutating("Export Windows Events"),

        // ================================================================
        // Active Directory
        // ================================================================
        "ssh_ad_user_list" => ToolAnnotations::read_only("List AD Users"),
        "ssh_ad_user_info" => ToolAnnotations::read_only("AD User Info"),
        "ssh_ad_group_list" => ToolAnnotations::read_only("List AD Groups"),
        "ssh_ad_group_members" => ToolAnnotations::read_only("AD Group Members"),
        "ssh_ad_computer_list" => ToolAnnotations::read_only("List AD Computers"),
        "ssh_ad_domain_info" => ToolAnnotations::read_only("AD Domain Info"),

        // ================================================================
        // Scheduled Tasks
        // ================================================================
        "ssh_schtask_list" => ToolAnnotations::read_only("List Scheduled Tasks"),
        "ssh_schtask_info" => ToolAnnotations::read_only("Scheduled Task Info"),
        "ssh_schtask_run" => ToolAnnotations::mutating("Run Scheduled Task"),
        "ssh_schtask_enable" => ToolAnnotations::mutating("Enable Scheduled Task"),
        "ssh_schtask_disable" => ToolAnnotations::mutating("Disable Scheduled Task"),

        // ================================================================
        // Windows Firewall
        // ================================================================
        "ssh_win_firewall_status" => ToolAnnotations::read_only("Windows Firewall Status"),
        "ssh_win_firewall_list" => ToolAnnotations::read_only("List Windows Firewall Rules"),
        "ssh_win_firewall_allow" => ToolAnnotations::mutating("Allow Windows Firewall Rule"),
        "ssh_win_firewall_deny" => ToolAnnotations::mutating("Deny Windows Firewall Rule"),
        "ssh_win_firewall_remove" => ToolAnnotations::destructive("Remove Windows Firewall Rule"),

        // ================================================================
        // IIS
        // ================================================================
        "ssh_iis_status" => ToolAnnotations::read_only("IIS Status"),
        "ssh_iis_list_sites" => ToolAnnotations::read_only("List IIS Sites"),
        "ssh_iis_list_pools" => ToolAnnotations::read_only("List IIS App Pools"),
        "ssh_iis_start" => ToolAnnotations::mutating("Start IIS Site"),
        "ssh_iis_stop" => ToolAnnotations::mutating("Stop IIS Site"),
        "ssh_iis_restart" => ToolAnnotations {
            title: Some("Restart IIS App Pool".to_string()),
            read_only_hint: Some(false),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(true),
        },

        // ================================================================
        // Windows Updates
        // ================================================================
        "ssh_win_update_list" => ToolAnnotations::read_only("List Windows Updates"),
        "ssh_win_update_history" => ToolAnnotations::read_only("Windows Update History"),
        "ssh_win_update_search" => ToolAnnotations::read_only("Search Windows Updates"),
        "ssh_win_update_reboot" => ToolAnnotations::read_only("Windows Reboot Status"),
        "ssh_win_update_install" => ToolAnnotations::mutating("Install Windows Update"),

        // ================================================================
        // Windows Performance
        // ================================================================
        "ssh_win_perf_cpu" => ToolAnnotations::read_only("Windows CPU Performance"),
        "ssh_win_perf_memory" => ToolAnnotations::read_only("Windows Memory Performance"),
        "ssh_win_perf_disk" => ToolAnnotations::read_only("Windows Disk Performance"),
        "ssh_win_perf_network" => ToolAnnotations::read_only("Windows Network Performance"),
        "ssh_win_perf_overview" => ToolAnnotations::read_only("Windows Performance Overview"),

        // ================================================================
        // Hyper-V
        // ================================================================
        "ssh_hyperv_vm_list" => ToolAnnotations::read_only("List Hyper-V VMs"),
        "ssh_hyperv_vm_info" => ToolAnnotations::read_only("Hyper-V VM Info"),
        "ssh_hyperv_vm_start" => ToolAnnotations::mutating("Start Hyper-V VM"),
        "ssh_hyperv_vm_stop" => ToolAnnotations::destructive("Stop Hyper-V VM"),
        "ssh_hyperv_snapshot_list" => ToolAnnotations::read_only("List Hyper-V Snapshots"),
        "ssh_hyperv_snapshot_create" => ToolAnnotations::mutating("Create Hyper-V Snapshot"),
        "ssh_hyperv_host_info" => ToolAnnotations::read_only("Hyper-V Host Info"),
        "ssh_hyperv_switch_list" => ToolAnnotations::read_only("List Hyper-V Switches"),

        // ================================================================
        // Windows Registry
        // ================================================================
        "ssh_reg_query" => ToolAnnotations::read_only("Query Registry"),
        "ssh_reg_list" => ToolAnnotations::read_only("List Registry Keys"),
        "ssh_reg_set" => ToolAnnotations::mutating("Set Registry Value"),
        "ssh_reg_export" => ToolAnnotations::mutating("Export Registry Key"),
        "ssh_reg_delete" => ToolAnnotations::destructive("Delete Registry Property"),

        // ================================================================
        // Windows Features
        // ================================================================
        "ssh_win_feature_list" => ToolAnnotations::read_only("List Windows Features"),
        "ssh_win_feature_info" => ToolAnnotations::read_only("Windows Feature Info"),
        "ssh_win_feature_install" => ToolAnnotations::mutating("Install Windows Feature"),
        "ssh_win_feature_remove" => ToolAnnotations::destructive("Remove Windows Feature"),

        // ================================================================
        // Windows Network
        // ================================================================
        "ssh_win_net_adapters" => ToolAnnotations::read_only("Windows Net Adapters"),
        "ssh_win_net_ip" => ToolAnnotations::read_only("Windows IP Addresses"),
        "ssh_win_net_routes" => ToolAnnotations::read_only("Windows Net Routes"),
        "ssh_win_net_connections" => ToolAnnotations::read_only("Windows Net Connections"),
        "ssh_win_net_ping" => ToolAnnotations::read_only("Windows Ping"),
        "ssh_win_net_dns" => ToolAnnotations::read_only("Windows DNS Lookup"),

        // ================================================================
        // Windows Process
        // ================================================================
        "ssh_win_process_list" => ToolAnnotations::read_only("List Windows Processes"),
        "ssh_win_process_info" => ToolAnnotations::read_only("Windows Process Info"),
        "ssh_win_process_kill" => ToolAnnotations::destructive("Kill Windows Process"),
        "ssh_win_process_top" => ToolAnnotations::read_only("Windows Process Top"),
        "ssh_win_process_by_name" => ToolAnnotations::read_only("Windows Process By Name"),
        "ssh_win_disk_usage" => ToolAnnotations::read_only("Windows Disk Usage"),

        // ================================================================
        // File Operations
        // ================================================================
        "ssh_file_read" => ToolAnnotations::read_only("Read Remote File"),
        "ssh_file_stat" => ToolAnnotations::read_only("File Info"),
        "ssh_file_write" => ToolAnnotations::destructive("Write Remote File"),
        "ssh_file_chmod" => ToolAnnotations::mutating("Change File Permissions"),
        "ssh_file_chown" => ToolAnnotations::mutating("Change File Ownership"),

        // ================================================================
        // User Management
        // ================================================================
        "ssh_user_list" => ToolAnnotations::read_only("List Users"),
        "ssh_user_info" => ToolAnnotations::read_only("User Info"),
        "ssh_group_list" => ToolAnnotations::read_only("List Groups"),
        "ssh_user_add" => ToolAnnotations::mutating("Create User"),
        "ssh_user_modify" => ToolAnnotations::mutating("Modify User"),
        "ssh_user_delete" => ToolAnnotations::destructive("Delete User"),
        "ssh_group_add" => ToolAnnotations::mutating("Create Group"),
        "ssh_group_delete" => ToolAnnotations::destructive("Delete Group"),

        // ================================================================
        // Storage
        // ================================================================
        "ssh_storage_lsblk" => ToolAnnotations::read_only("List Block Devices"),
        "ssh_storage_df" => ToolAnnotations::read_only("Disk Space Usage"),
        "ssh_storage_lvm" => ToolAnnotations::read_only("List LVM Volumes"),
        "ssh_storage_fdisk" => ToolAnnotations::read_only("Partition Info"),
        "ssh_storage_fstab" => ToolAnnotations::read_only("Read fstab"),
        "ssh_storage_mount" => ToolAnnotations::mutating("Mount Filesystem"),
        "ssh_storage_umount" => ToolAnnotations::mutating("Unmount Filesystem"),

        // ================================================================
        // Journald
        // ================================================================
        "ssh_journal_query" => ToolAnnotations::read_only("Query Journal Logs"),
        "ssh_journal_follow" => ToolAnnotations::read_only("Follow Journal"),
        "ssh_journal_boots" => ToolAnnotations::read_only("List Boot Entries"),
        "ssh_journal_disk_usage" => ToolAnnotations::read_only("Journal Disk Usage"),

        // ================================================================
        // Systemd Timers
        // ================================================================
        "ssh_timer_list" => ToolAnnotations::read_only("List Timers"),
        "ssh_timer_info" => ToolAnnotations::read_only("Timer Info"),
        "ssh_timer_enable" => ToolAnnotations::mutating("Enable Timer"),
        "ssh_timer_disable" => ToolAnnotations::mutating("Disable Timer"),
        "ssh_timer_trigger" => ToolAnnotations::mutating("Trigger Timer"),

        // ================================================================
        // Security Modules
        // ================================================================
        "ssh_selinux_status" => ToolAnnotations::read_only("SELinux Status"),
        "ssh_selinux_booleans" => ToolAnnotations::mutating("SELinux Booleans"),
        "ssh_apparmor_status" => ToolAnnotations::read_only("AppArmor Status"),
        "ssh_apparmor_profiles" => ToolAnnotations::read_only("AppArmor Profiles"),
        "ssh_security_audit" => ToolAnnotations::read_only("Security Audit"),

        // ================================================================
        // Network Equipment
        // ================================================================
        "ssh_net_equip_show_run" => ToolAnnotations::read_only("Show Running Config"),
        "ssh_net_equip_show_interfaces" => ToolAnnotations::read_only("Show Interfaces"),
        "ssh_net_equip_show_routes" => ToolAnnotations::read_only("Show Routes"),
        "ssh_net_equip_show_arp" => ToolAnnotations::read_only("Show ARP Table"),
        "ssh_net_equip_show_version" => ToolAnnotations::read_only("Show Version"),
        "ssh_net_equip_show_vlans" => ToolAnnotations::read_only("Show VLANs"),
        "ssh_net_equip_config" => ToolAnnotations::destructive("Configure Device"),
        "ssh_net_equip_save" => ToolAnnotations::mutating("Save Device Config"),

        // ================================================================
        // Podman
        // ================================================================
        "ssh_podman_ps" => ToolAnnotations::read_only("List Podman Containers"),
        "ssh_podman_logs" => ToolAnnotations::read_only("Podman Container Logs"),
        "ssh_podman_inspect" => ToolAnnotations::read_only("Inspect Podman Container"),
        "ssh_podman_images" => ToolAnnotations::read_only("List Podman Images"),
        "ssh_podman_exec" => ToolAnnotations::mutating("Podman Exec"),
        "ssh_podman_compose" => ToolAnnotations::mutating("Podman Compose"),

        // ================================================================
        // LDAP
        // ================================================================
        "ssh_ldap_search" => ToolAnnotations::read_only("LDAP Search"),
        "ssh_ldap_user_info" => ToolAnnotations::read_only("LDAP User Info"),
        "ssh_ldap_group_members" => ToolAnnotations::read_only("LDAP Group Members"),
        "ssh_ldap_add" => ToolAnnotations::mutating("LDAP Add Entry"),
        "ssh_ldap_modify" => ToolAnnotations::mutating("LDAP Modify Entry"),

        // ================================================================
        // Orchestration
        // ================================================================
        "ssh_canary_exec" => ToolAnnotations::mutating("Canary Exec"),
        "ssh_rolling_exec" => ToolAnnotations::mutating("Rolling Exec"),
        "ssh_fleet_diff" => ToolAnnotations::read_only("Fleet Diff"),

        // Drift Detection
        "ssh_env_snapshot" => ToolAnnotations::read_only("Environment Snapshot"),
        "ssh_env_diff" => ToolAnnotations::read_only("Environment Diff"),
        "ssh_env_drift" => ToolAnnotations::read_only("Drift Detection"),

        // File Advanced
        "ssh_file_diff" => ToolAnnotations::read_only("File Diff"),
        "ssh_file_patch" => ToolAnnotations::destructive("Apply Patch"),
        "ssh_file_template" => ToolAnnotations::mutating("Render Template"),

        // Security Scanning
        "ssh_sbom_generate" => ToolAnnotations::read_only("Generate SBOM"),
        "ssh_vuln_scan" => ToolAnnotations::read_only("Vulnerability Scan"),
        "ssh_compliance_check" => ToolAnnotations::read_only("Compliance Check"),

        // Fallback for unknown/future tools
        _ => ToolAnnotations::default(),
    }
}

/// Create a registry with all default tool handlers
#[must_use]
pub fn create_default_registry() -> ToolRegistry {
    create_filtered_registry(&ToolGroupsConfig::default())
}

/// Create a registry filtered by the tool groups configuration.
///
/// Only tools whose group is enabled in the config will be registered.
#[must_use]
#[allow(clippy::too_many_lines, clippy::large_stack_arrays)]
pub fn create_filtered_registry(tool_groups: &ToolGroupsConfig) -> ToolRegistry {
    use super::tool_handlers::{
        SshAlertCheckHandler,
        SshAlertListHandler,
        SshAlertSetHandler,
        SshApacheStatusHandler,
        SshApacheVhostsHandler,
        SshAdComputerListHandler,
        SshAdDomainInfoHandler,
        SshAdGroupListHandler,
        SshAdGroupMembersHandler,
        SshAdUserInfoHandler,
        SshAdUserListHandler,
        SshAnsibleAdhocHandler,
        SshAnsibleInventoryHandler,
        SshAnsiblePlaybookHandler,
        SshBackupCreateHandler,
        SshBackupListHandler,
        SshBackupRestoreHandler,
        SshAtJobsHandler,
        SshAwsCliHandler,
        SshBackupScheduleHandler,
        SshBackupSnapshotHandler,
        SshBackupVerifyHandler,
        SshBenchmarkHandler,
        SshCapacityCollectHandler,
        SshCapacityPredictHandler,
        SshCapacityTrendHandler,
        SshCanaryExecHandler,
        SshComplianceCheckHandler,
        SshCertCheckHandler,
        SshCertExpiryHandler,
        SshCertInfoHandler,
        SshCisBenchmarkHandler,
        SshCloudCostHandler,
        SshCloudMetadataHandler,
        SshCloudTagsHandler,
        SshComplianceReportHandler,
        SshComplianceScoreHandler,
        SshConfigGetHandler,
        SshConfigSetHandler,
        SshContainerEventsHandler,
        SshContainerHealthHistoryHandler,
        SshContainerLogSearchHandler,
        SshContainerLogStatsHandler,
        SshCronAddHandler,
        SshCronAnalyzeHandler,
        SshCronHistoryHandler,
        SshCronListHandler,
        SshCronRemoveHandler,
        SshDbDumpHandler,
        SshDbQueryHandler,
        SshDbRestoreHandler,
        SshDiscoverHostsHandler,
        SshDiskUsageHandler,
        SshDockerComposeHandler,
        SshDockerExecHandler,
        SshDockerImagesHandler,
        SshDockerInspectHandler,
        SshDockerLogsHandler,
        SshDockerNetworkInspectHandler,
        SshDockerNetworkLsHandler,
        SshDockerPsHandler,
        SshDockerStatsHandler,
        SshDockerVolumeInspectHandler,
        SshDockerVolumeLsHandler,
        SshDownloadHandler,
        SshEsxiDatastoreListHandler,
        SshEsxiHostInfoHandler,
        SshEsxiNetworkListHandler,
        SshEsxiSnapshotHandler,
        SshEsxiVmInfoHandler,
        SshEsxiVmListHandler,
        SshEsxiVmPowerHandler,
        SshExecHandler,
        SshExecMultiHandler,
        SshFail2banStatusHandler,
        SshFileChmodHandler,
        SshFileChownHandler,
        SshFileReadHandler,
        SshFileStatHandler,
        SshFileWriteHandler,
        SshFindHandler,
        SshFleetDiffHandler,
        SshFirewallAllowHandler,
        SshFirewallDenyHandler,
        SshFirewallListHandler,
        SshFirewallStatusHandler,
        SshGroupAddHandler,
        SshGroupDeleteHandler,
        SshGroupListHandler,
        SshGitBranchHandler,
        SshGitCheckoutHandler,
        SshGitCloneHandler,
        SshGitDiffHandler,
        SshGitLogHandler,
        SshGitPullHandler,
        SshGitStatusHandler,
        SshHealthHandler,
        SshHostTagsHandler,
        SshIncidentCorrelateHandler,
        SshIncidentTimelineHandler,
        SshKeyAuditHandler,
        SshKeyDistributeHandler,
        SshKeyGenerateHandler,
        SshHelmHistoryHandler,
        SshHelmInstallHandler,
        SshHelmListHandler,
        SshHelmRollbackHandler,
        SshHelmStatusHandler,
        SshHelmUninstallHandler,
        SshHelmUpgradeHandler,
        SshHistoryHandler,
        SshInventorySyncHandler,
        SshIoTraceHandler,
        SshJournalBootsHandler,
        SshJournalDiskUsageHandler,
        SshJournalFollowHandler,
        SshJournalQueryHandler,
        SshHypervHostInfoHandler,
        SshHypervSnapshotCreateHandler,
        SshHypervSnapshotListHandler,
        SshHypervSwitchListHandler,
        SshHypervVmInfoHandler,
        // Phase 3: Enterprise Windows
        SshHypervVmListHandler,
        SshHypervVmStartHandler,
        SshHypervVmStopHandler,
        SshIisListPoolsHandler,
        SshIisListSitesHandler,
        SshIisRestartHandler,
        SshIisStartHandler,
        SshIisStatusHandler,
        SshIisStopHandler,
        SshK8sApplyHandler,
        SshK8sDeleteHandler,
        SshK8sDescribeHandler,
        SshK8sExecHandler,
        SshK8sGetHandler,
        SshK8sLogsHandler,
        SshK8sRolloutHandler,
        SshK8sScaleHandler,
        SshK8sTopHandler,
        SshLatencyTestHandler,
        SshLetsencryptStatusHandler,
        SshLogAggregateHandler,
        SshLogSearchMultiHandler,
        SshLogTailMultiHandler,
        SshLdapAddHandler,
        SshLdapGroupMembersHandler,
        SshLdapModifyHandler,
        SshLdapSearchHandler,
        SshLdapUserInfoHandler,
        SshLsHandler,
        SshMongodbStatusHandler,
        SshMulticloudCompareHandler,
        SshMulticloudListHandler,
        SshMulticloudSyncHandler,
        SshMysqlQueryHandler,
        SshMysqlStatusHandler,
        SshMetricsHandler,
        SshMetricsMultiHandler,
        SshNetEquipConfigHandler,
        SshNetEquipSaveHandler,
        SshNetEquipShowArpHandler,
        SshNetEquipShowInterfacesHandler,
        SshNetEquipShowRoutesHandler,
        SshNetEquipShowRunHandler,
        SshNetEquipShowVersionHandler,
        SshNetEquipShowVlansHandler,
        SshNetConnectionsHandler,
        SshNetDnsHandler,
        SshNetworkCaptureHandler,
        SshNetInterfacesHandler,
        SshNetPingHandler,
        SshNetRoutesHandler,
        SshNetTracerouteHandler,
        SshNginxListSitesHandler,
        SshNotifyHandler,
        SshNginxReloadHandler,
        SshNginxStatusHandler,
        SshNginxTestHandler,
        SshOutputFetchHandler,
        SshPerfTraceHandler,
        SshPostgresqlQueryHandler,
        SshPostgresqlStatusHandler,
        SshPodmanComposeHandler,
        SshPodmanExecHandler,
        SshPodmanImagesHandler,
        SshPodmanInspectHandler,
        SshPodmanLogsHandler,
        SshPortScanHandler,
        SshPodmanPsHandler,
        SshPkgInstallHandler,
        SshPkgListHandler,
        SshPkgRemoveHandler,
        SshPkgSearchHandler,
        SshPkgUpdateHandler,
        SshProcessKillHandler,
        SshProcessListHandler,
        SshProcessTopHandler,
        SshRecordingListHandler,
        SshRecordingReplayHandler,
        SshCompareStateHandler,
        SshDiagnoseHandler,
        SshEnvDiffHandler,
        SshEnvDriftHandler,
        SshEnvSnapshotHandler,
        SshFileDiffHandler,
        SshFilePatchHandler,
        SshFileTemplateHandler,
        SshIncidentTriageHandler,
        SshRecordingStartHandler,
        SshRunbookExecuteHandler,
        SshRunbookListHandler,
        SshRunbookValidateHandler,
        SshRecordingStopHandler,
        SshRecordingVerifyHandler,
        SshRollingExecHandler,
        SshRedisCliHandler,
        SshRedisInfoHandler,
        SshRedisKeysHandler,
        SshRegDeleteHandler,
        SshSbomGenerateHandler,
        SshVulnScanHandler,
        SshRegExportHandler,
        SshRegListHandler,
        SshRegQueryHandler,
        SshRegSetHandler,
        SshApparmorProfilesHandler,
        SshApparmorStatusHandler,
        SshSchtaskDisableHandler,
        SshSchtaskEnableHandler,
        SshSchtaskInfoHandler,
        SshSchtaskListHandler,
        SshSchtaskRunHandler,
        SshSecurityAuditHandler,
        SshSelinuxBooleansHandler,
        SshSelinuxStatusHandler,
        SshSslAuditHandler,
        SshStigCheckHandler,
        SshServiceDaemonReloadHandler,
        SshServiceDisableHandler,
        SshServiceEnableHandler,
        SshServiceListHandler,
        SshServiceLogsHandler,
        SshServiceRestartHandler,
        SshServiceStartHandler,
        SshServiceStatusHandler,
        SshServiceStopHandler,
        SshSessionCloseHandler,
        SshSessionCreateHandler,
        SshSessionExecHandler,
        SshSessionListHandler,
        SshStatusHandler,
        SshStorageDfHandler,
        SshStorageFdiskHandler,
        SshStorageFstabHandler,
        SshStorageLsblkHandler,
        SshStorageLvmHandler,
        SshStorageMountHandler,
        SshStorageUmountHandler,
        SshSyncHandler,
        SshTailHandler,
        SshTerraformApplyHandler,
        SshTimerDisableHandler,
        SshTimerEnableHandler,
        SshTimerInfoHandler,
        SshTimerListHandler,
        SshTimerTriggerHandler,
        SshTerraformInitHandler,
        SshTerraformOutputHandler,
        SshTerraformPlanHandler,
        SshTerraformStateHandler,
        SshTunnelCloseHandler,
        SshTunnelCreateHandler,
        SshTunnelListHandler,
        SshUploadHandler,
        SshUserAddHandler,
        SshUserDeleteHandler,
        SshUserInfoHandler,
        SshUserListHandler,
        SshUserModifyHandler,
        SshVaultListHandler,
        SshVaultReadHandler,
        SshVaultStatusHandler,
        SshVaultWriteHandler,
        SshWebhookSendHandler,
        SshWinDiskUsageHandler,
        SshWinEventExportHandler,
        SshWinEventLogsHandler,
        SshWinEventQueryHandler,
        SshWinEventSourcesHandler,
        SshWinEventTailHandler,
        SshWinFeatureInfoHandler,
        SshWinFeatureInstallHandler,
        SshWinFeatureListHandler,
        SshWinFeatureRemoveHandler,
        SshWinFirewallAllowHandler,
        SshWinFirewallDenyHandler,
        SshWinFirewallListHandler,
        SshWinFirewallRemoveHandler,
        SshWinFirewallStatusHandler,
        SshWinNetAdaptersHandler,
        SshWinNetConnectionsHandler,
        SshWinNetDnsHandler,
        SshWinNetIpHandler,
        SshWinNetPingHandler,
        SshWinNetRoutesHandler,
        SshWinPerfCpuHandler,
        SshWinPerfDiskHandler,
        SshWinPerfMemoryHandler,
        SshWinPerfNetworkHandler,
        SshWinPerfOverviewHandler,
        SshWinProcessByNameHandler,
        SshWinProcessInfoHandler,
        SshWinProcessKillHandler,
        SshWinProcessListHandler,
        SshWinProcessTopHandler,
        SshWinServiceConfigHandler,
        SshWinServiceDisableHandler,
        SshWinServiceEnableHandler,
        SshWinServiceListHandler,
        SshWinServiceRestartHandler,
        SshWinServiceStartHandler,
        SshWinServiceStatusHandler,
        SshWinServiceStopHandler,
        SshWinUpdateHistoryHandler,
        SshWinUpdateInstallHandler,
        SshWinUpdateListHandler,
        SshWinUpdateRebootHandler,
        SshWinUpdateSearchHandler,
    };

    let mut registry = ToolRegistry::new();

    let all_handlers: Vec<Arc<dyn ToolHandler>> = vec![
        // Core
        Arc::new(SshExecHandler),
        Arc::new(SshExecMultiHandler),
        Arc::new(SshStatusHandler),
        Arc::new(SshHistoryHandler),
        Arc::new(SshHealthHandler),
        Arc::new(SshOutputFetchHandler),
        // Monitoring
        Arc::new(SshMetricsHandler),
        Arc::new(SshMetricsMultiHandler),
        Arc::new(SshTailHandler),
        Arc::new(SshDiskUsageHandler),
        // File transfer
        Arc::new(SshUploadHandler),
        Arc::new(SshDownloadHandler),
        Arc::new(SshSyncHandler),
        // Sessions
        Arc::new(SshSessionCreateHandler),
        Arc::new(SshSessionExecHandler),
        Arc::new(SshSessionListHandler),
        Arc::new(SshSessionCloseHandler),
        // Tunnels
        Arc::new(SshTunnelCreateHandler),
        Arc::new(SshTunnelListHandler),
        Arc::new(SshTunnelCloseHandler),
        // Directory
        Arc::new(SshLsHandler),
        Arc::new(SshFindHandler),
        // Database
        Arc::new(SshDbQueryHandler::new()),
        Arc::new(SshDbDumpHandler::new()),
        Arc::new(SshDbRestoreHandler::new()),
        // Backup
        Arc::new(SshBackupCreateHandler::new()),
        Arc::new(SshBackupListHandler::new()),
        Arc::new(SshBackupRestoreHandler::new()),
        // Docker
        Arc::new(SshDockerPsHandler::new()),
        Arc::new(SshDockerLogsHandler::new()),
        Arc::new(SshDockerInspectHandler::new()),
        Arc::new(SshDockerExecHandler::new()),
        Arc::new(SshDockerComposeHandler::new()),
        Arc::new(SshDockerImagesHandler::new()),
        Arc::new(SshDockerStatsHandler::new()),
        Arc::new(SshDockerVolumeLsHandler::new()),
        Arc::new(SshDockerNetworkLsHandler::new()),
        Arc::new(SshDockerVolumeInspectHandler::new()),
        Arc::new(SshDockerNetworkInspectHandler::new()),
        // ESXi
        Arc::new(SshEsxiVmListHandler::new()),
        Arc::new(SshEsxiVmInfoHandler::new()),
        Arc::new(SshEsxiVmPowerHandler::new()),
        Arc::new(SshEsxiSnapshotHandler::new()),
        Arc::new(SshEsxiHostInfoHandler::new()),
        Arc::new(SshEsxiDatastoreListHandler::new()),
        Arc::new(SshEsxiNetworkListHandler::new()),
        // Git
        Arc::new(SshGitStatusHandler::new()),
        Arc::new(SshGitLogHandler::new()),
        Arc::new(SshGitDiffHandler::new()),
        Arc::new(SshGitPullHandler::new()),
        Arc::new(SshGitCloneHandler::new()),
        Arc::new(SshGitBranchHandler::new()),
        Arc::new(SshGitCheckoutHandler::new()),
        // Kubernetes (kubectl)
        Arc::new(SshK8sGetHandler::new()),
        Arc::new(SshK8sLogsHandler::new()),
        Arc::new(SshK8sDescribeHandler::new()),
        Arc::new(SshK8sApplyHandler::new()),
        Arc::new(SshK8sDeleteHandler::new()),
        Arc::new(SshK8sRolloutHandler::new()),
        Arc::new(SshK8sScaleHandler::new()),
        Arc::new(SshK8sExecHandler::new()),
        Arc::new(SshK8sTopHandler::new()),
        // Kubernetes (helm)
        Arc::new(SshHelmListHandler::new()),
        Arc::new(SshHelmStatusHandler::new()),
        Arc::new(SshHelmUpgradeHandler::new()),
        Arc::new(SshHelmInstallHandler::new()),
        Arc::new(SshHelmRollbackHandler::new()),
        Arc::new(SshHelmHistoryHandler::new()),
        Arc::new(SshHelmUninstallHandler::new()),
        // Ansible
        Arc::new(SshAnsiblePlaybookHandler::new()),
        Arc::new(SshAnsibleInventoryHandler::new()),
        Arc::new(SshAnsibleAdhocHandler::new()),
        // Systemd
        Arc::new(SshServiceStatusHandler::new()),
        Arc::new(SshServiceStartHandler::new()),
        Arc::new(SshServiceStopHandler::new()),
        Arc::new(SshServiceRestartHandler::new()),
        Arc::new(SshServiceListHandler::new()),
        Arc::new(SshServiceLogsHandler::new()),
        Arc::new(SshServiceEnableHandler::new()),
        Arc::new(SshServiceDisableHandler::new()),
        Arc::new(SshServiceDaemonReloadHandler::new()),
        // Network
        Arc::new(SshNetConnectionsHandler::new()),
        Arc::new(SshNetInterfacesHandler::new()),
        Arc::new(SshNetRoutesHandler::new()),
        Arc::new(SshNetPingHandler::new()),
        Arc::new(SshNetTracerouteHandler::new()),
        Arc::new(SshNetDnsHandler::new()),
        // Process
        Arc::new(SshProcessListHandler::new()),
        Arc::new(SshProcessKillHandler::new()),
        Arc::new(SshProcessTopHandler::new()),
        // Package
        Arc::new(SshPkgListHandler::new()),
        Arc::new(SshPkgSearchHandler::new()),
        Arc::new(SshPkgInstallHandler::new()),
        Arc::new(SshPkgUpdateHandler::new()),
        Arc::new(SshPkgRemoveHandler::new()),
        // Firewall
        Arc::new(SshFirewallStatusHandler::new()),
        Arc::new(SshFirewallListHandler::new()),
        Arc::new(SshFirewallAllowHandler::new()),
        Arc::new(SshFirewallDenyHandler::new()),
        // Cron
        Arc::new(SshCronListHandler::new()),
        Arc::new(SshCronAddHandler::new()),
        Arc::new(SshCronRemoveHandler::new()),
        // Cron Analysis
        Arc::new(SshCronAnalyzeHandler::new()),
        Arc::new(SshCronHistoryHandler::new()),
        Arc::new(SshAtJobsHandler::new()),
        // Performance Profiling
        Arc::new(SshPerfTraceHandler::new()),
        Arc::new(SshIoTraceHandler::new()),
        Arc::new(SshLatencyTestHandler::new()),
        Arc::new(SshBenchmarkHandler::new()),
        // Container Log Analysis
        Arc::new(SshContainerLogSearchHandler::new()),
        Arc::new(SshContainerLogStatsHandler::new()),
        Arc::new(SshContainerEventsHandler::new()),
        Arc::new(SshContainerHealthHistoryHandler::new()),
        // Network Security
        Arc::new(SshPortScanHandler::new()),
        Arc::new(SshSslAuditHandler::new()),
        Arc::new(SshNetworkCaptureHandler::new()),
        Arc::new(SshFail2banStatusHandler::new()),
        // Compliance
        Arc::new(SshCisBenchmarkHandler::new()),
        Arc::new(SshStigCheckHandler::new()),
        Arc::new(SshComplianceScoreHandler::new()),
        Arc::new(SshComplianceReportHandler::new()),
        // Cloud
        Arc::new(SshAwsCliHandler::new()),
        Arc::new(SshCloudMetadataHandler::new()),
        Arc::new(SshCloudTagsHandler::new()),
        Arc::new(SshCloudCostHandler::new()),
        // Inventory
        Arc::new(SshDiscoverHostsHandler::new()),
        Arc::new(SshInventorySyncHandler::new()),
        Arc::new(SshHostTagsHandler::new()),
        // Multi-cloud
        Arc::new(SshMulticloudListHandler::new()),
        Arc::new(SshMulticloudSyncHandler::new()),
        Arc::new(SshMulticloudCompareHandler::new()),
        // Alerting
        Arc::new(SshAlertSetHandler::new()),
        Arc::new(SshAlertListHandler::new()),
        Arc::new(SshAlertCheckHandler::new()),
        // Capacity
        Arc::new(SshCapacityCollectHandler::new()),
        Arc::new(SshCapacityTrendHandler::new()),
        Arc::new(SshCapacityPredictHandler::new()),
        // Incident
        Arc::new(SshIncidentTimelineHandler::new()),
        Arc::new(SshIncidentCorrelateHandler::new()),
        // Log Aggregation
        Arc::new(SshLogSearchMultiHandler::new()),
        Arc::new(SshLogAggregateHandler::new()),
        Arc::new(SshLogTailMultiHandler::new()),
        // Key Management
        Arc::new(SshKeyGenerateHandler::new()),
        Arc::new(SshKeyDistributeHandler::new()),
        Arc::new(SshKeyAuditHandler::new()),
        // Backup Enhanced
        Arc::new(SshBackupSnapshotHandler::new()),
        Arc::new(SshBackupVerifyHandler::new()),
        Arc::new(SshBackupScheduleHandler::new()),
        // ChatOps
        Arc::new(SshWebhookSendHandler::new()),
        Arc::new(SshNotifyHandler::new()),
        // Certificates
        Arc::new(SshCertCheckHandler::new()),
        Arc::new(SshCertInfoHandler::new()),
        Arc::new(SshCertExpiryHandler::new()),
        // Nginx
        Arc::new(SshNginxStatusHandler::new()),
        Arc::new(SshNginxTestHandler::new()),
        Arc::new(SshNginxReloadHandler::new()),
        Arc::new(SshNginxListSitesHandler::new()),
        // Diagnostics
        Arc::new(SshDiagnoseHandler::new()),
        Arc::new(SshIncidentTriageHandler::new()),
        Arc::new(SshCompareStateHandler::new()),
        // Orchestration
        Arc::new(SshCanaryExecHandler::new()),
        Arc::new(SshRollingExecHandler::new()),
        Arc::new(SshFleetDiffHandler::new()),
        // Drift Detection
        Arc::new(SshEnvSnapshotHandler::new()),
        Arc::new(SshEnvDiffHandler::new()),
        Arc::new(SshEnvDriftHandler::new()),
        // File Advanced (added to file_ops group)
        Arc::new(SshFileDiffHandler::new()),
        Arc::new(SshFilePatchHandler::new()),
        Arc::new(SshFileTemplateHandler::new()),
        // Security Scanning
        Arc::new(SshSbomGenerateHandler::new()),
        Arc::new(SshVulnScanHandler::new()),
        Arc::new(SshComplianceCheckHandler::new()),
        // Runbooks
        Arc::new(SshRunbookListHandler),
        Arc::new(SshRunbookExecuteHandler),
        Arc::new(SshRunbookValidateHandler),
        // Recording / Compliance
        Arc::new(SshRecordingStartHandler),
        Arc::new(SshRecordingStopHandler),
        Arc::new(SshRecordingListHandler),
        Arc::new(SshRecordingReplayHandler),
        Arc::new(SshRecordingVerifyHandler),
        // Redis
        Arc::new(SshRedisInfoHandler::new()),
        Arc::new(SshRedisCliHandler::new()),
        Arc::new(SshRedisKeysHandler::new()),
        // PostgreSQL
        Arc::new(SshPostgresqlQueryHandler::new()),
        Arc::new(SshPostgresqlStatusHandler::new()),
        // MySQL
        Arc::new(SshMysqlQueryHandler::new()),
        Arc::new(SshMysqlStatusHandler::new()),
        // Apache
        Arc::new(SshApacheStatusHandler::new()),
        Arc::new(SshApacheVhostsHandler::new()),
        // Let's Encrypt
        Arc::new(SshLetsencryptStatusHandler::new()),
        // MongoDB
        Arc::new(SshMongodbStatusHandler::new()),
        // Terraform
        Arc::new(SshTerraformInitHandler::new()),
        Arc::new(SshTerraformPlanHandler::new()),
        Arc::new(SshTerraformApplyHandler::new()),
        Arc::new(SshTerraformStateHandler::new()),
        Arc::new(SshTerraformOutputHandler::new()),
        // Vault
        Arc::new(SshVaultStatusHandler::new()),
        Arc::new(SshVaultReadHandler::new()),
        Arc::new(SshVaultListHandler::new()),
        Arc::new(SshVaultWriteHandler::new()),
        // Config
        Arc::new(SshConfigGetHandler),
        Arc::new(SshConfigSetHandler),
        // File Operations
        Arc::new(SshFileReadHandler::new()),
        Arc::new(SshFileWriteHandler::new()),
        Arc::new(SshFileChmodHandler::new()),
        Arc::new(SshFileChownHandler::new()),
        Arc::new(SshFileStatHandler::new()),
        // User Management
        Arc::new(SshUserListHandler::new()),
        Arc::new(SshUserInfoHandler::new()),
        Arc::new(SshUserAddHandler::new()),
        Arc::new(SshUserModifyHandler::new()),
        Arc::new(SshUserDeleteHandler::new()),
        Arc::new(SshGroupListHandler::new()),
        Arc::new(SshGroupAddHandler::new()),
        Arc::new(SshGroupDeleteHandler::new()),
        // Storage
        Arc::new(SshStorageLsblkHandler::new()),
        Arc::new(SshStorageDfHandler::new()),
        Arc::new(SshStorageMountHandler::new()),
        Arc::new(SshStorageUmountHandler::new()),
        Arc::new(SshStorageLvmHandler::new()),
        Arc::new(SshStorageFdiskHandler::new()),
        Arc::new(SshStorageFstabHandler::new()),
        // Journald
        Arc::new(SshJournalQueryHandler::new()),
        Arc::new(SshJournalFollowHandler::new()),
        Arc::new(SshJournalBootsHandler::new()),
        Arc::new(SshJournalDiskUsageHandler::new()),
        // Systemd Timers
        Arc::new(SshTimerListHandler::new()),
        Arc::new(SshTimerInfoHandler::new()),
        Arc::new(SshTimerEnableHandler::new()),
        Arc::new(SshTimerDisableHandler::new()),
        Arc::new(SshTimerTriggerHandler::new()),
        // Security Modules
        Arc::new(SshSelinuxStatusHandler::new()),
        Arc::new(SshSelinuxBooleansHandler::new()),
        Arc::new(SshApparmorStatusHandler::new()),
        Arc::new(SshApparmorProfilesHandler::new()),
        Arc::new(SshSecurityAuditHandler::new()),
        // Network Equipment
        Arc::new(SshNetEquipShowRunHandler::new()),
        Arc::new(SshNetEquipShowInterfacesHandler::new()),
        Arc::new(SshNetEquipShowRoutesHandler::new()),
        Arc::new(SshNetEquipShowArpHandler::new()),
        Arc::new(SshNetEquipShowVersionHandler::new()),
        Arc::new(SshNetEquipShowVlansHandler::new()),
        Arc::new(SshNetEquipConfigHandler::new()),
        Arc::new(SshNetEquipSaveHandler::new()),
        // Podman
        Arc::new(SshPodmanPsHandler::new()),
        Arc::new(SshPodmanLogsHandler::new()),
        Arc::new(SshPodmanInspectHandler::new()),
        Arc::new(SshPodmanExecHandler::new()),
        Arc::new(SshPodmanImagesHandler::new()),
        Arc::new(SshPodmanComposeHandler::new()),
        // LDAP
        Arc::new(SshLdapSearchHandler::new()),
        Arc::new(SshLdapUserInfoHandler::new()),
        Arc::new(SshLdapGroupMembersHandler::new()),
        Arc::new(SshLdapAddHandler::new()),
        Arc::new(SshLdapModifyHandler::new()),
        // Windows Services
        Arc::new(SshWinServiceStatusHandler::new()),
        Arc::new(SshWinServiceStartHandler::new()),
        Arc::new(SshWinServiceStopHandler::new()),
        Arc::new(SshWinServiceRestartHandler::new()),
        Arc::new(SshWinServiceListHandler::new()),
        Arc::new(SshWinServiceEnableHandler::new()),
        Arc::new(SshWinServiceDisableHandler::new()),
        Arc::new(SshWinServiceConfigHandler::new()),
        Arc::new(SshWinEventLogsHandler::new()),
        // Windows Events
        Arc::new(SshWinEventQueryHandler::new()),
        Arc::new(SshWinEventSourcesHandler::new()),
        Arc::new(SshWinEventTailHandler::new()),
        Arc::new(SshWinEventExportHandler::new()),
        // Active Directory
        Arc::new(SshAdUserListHandler::new()),
        Arc::new(SshAdUserInfoHandler::new()),
        Arc::new(SshAdGroupListHandler::new()),
        Arc::new(SshAdGroupMembersHandler::new()),
        Arc::new(SshAdComputerListHandler::new()),
        Arc::new(SshAdDomainInfoHandler::new()),
        // Scheduled Tasks
        Arc::new(SshSchtaskListHandler::new()),
        Arc::new(SshSchtaskInfoHandler::new()),
        Arc::new(SshSchtaskRunHandler::new()),
        Arc::new(SshSchtaskEnableHandler::new()),
        Arc::new(SshSchtaskDisableHandler::new()),
        // Windows Firewall
        Arc::new(SshWinFirewallStatusHandler::new()),
        Arc::new(SshWinFirewallListHandler::new()),
        Arc::new(SshWinFirewallAllowHandler::new()),
        Arc::new(SshWinFirewallDenyHandler::new()),
        Arc::new(SshWinFirewallRemoveHandler::new()),
        // IIS
        Arc::new(SshIisStatusHandler::new()),
        Arc::new(SshIisListSitesHandler::new()),
        Arc::new(SshIisListPoolsHandler::new()),
        Arc::new(SshIisStartHandler::new()),
        Arc::new(SshIisStopHandler::new()),
        Arc::new(SshIisRestartHandler::new()),
        // Windows Updates
        Arc::new(SshWinUpdateListHandler::new()),
        Arc::new(SshWinUpdateHistoryHandler::new()),
        Arc::new(SshWinUpdateInstallHandler::new()),
        Arc::new(SshWinUpdateSearchHandler::new()),
        Arc::new(SshWinUpdateRebootHandler::new()),
        // Windows Performance
        Arc::new(SshWinPerfCpuHandler::new()),
        Arc::new(SshWinPerfMemoryHandler::new()),
        Arc::new(SshWinPerfDiskHandler::new()),
        Arc::new(SshWinPerfNetworkHandler::new()),
        Arc::new(SshWinPerfOverviewHandler::new()),
        // Hyper-V
        Arc::new(SshHypervVmListHandler::new()),
        Arc::new(SshHypervVmInfoHandler::new()),
        Arc::new(SshHypervVmStartHandler::new()),
        Arc::new(SshHypervVmStopHandler::new()),
        Arc::new(SshHypervSnapshotListHandler::new()),
        Arc::new(SshHypervSnapshotCreateHandler::new()),
        Arc::new(SshHypervHostInfoHandler::new()),
        Arc::new(SshHypervSwitchListHandler::new()),
        // Windows Registry
        Arc::new(SshRegQueryHandler::new()),
        Arc::new(SshRegSetHandler::new()),
        Arc::new(SshRegListHandler::new()),
        Arc::new(SshRegExportHandler::new()),
        Arc::new(SshRegDeleteHandler::new()),
        // Windows Features
        Arc::new(SshWinFeatureListHandler::new()),
        Arc::new(SshWinFeatureInfoHandler::new()),
        Arc::new(SshWinFeatureInstallHandler::new()),
        Arc::new(SshWinFeatureRemoveHandler::new()),
        // Windows Network
        Arc::new(SshWinNetAdaptersHandler::new()),
        Arc::new(SshWinNetIpHandler::new()),
        Arc::new(SshWinNetRoutesHandler::new()),
        Arc::new(SshWinNetConnectionsHandler::new()),
        Arc::new(SshWinNetPingHandler::new()),
        Arc::new(SshWinNetDnsHandler::new()),
        // Windows Process
        Arc::new(SshWinProcessListHandler::new()),
        Arc::new(SshWinProcessInfoHandler::new()),
        Arc::new(SshWinProcessKillHandler::new()),
        Arc::new(SshWinProcessTopHandler::new()),
        Arc::new(SshWinProcessByNameHandler::new()),
        Arc::new(SshWinDiskUsageHandler::new()),
    ];

    for handler in all_handlers {
        let group = tool_group(handler.name());
        if tool_groups.is_group_enabled(group) {
            registry.register(handler);
        }
    }

    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BridgeError;
    use crate::mcp::protocol::ToolCallResult;
    use crate::ports::ToolContext;
    use crate::ports::mock::create_test_context;
    use async_trait::async_trait;

    struct TestHandler;

    #[async_trait]
    impl ToolHandler for TestHandler {
        fn name(&self) -> &'static str {
            "test_tool"
        }

        fn description(&self) -> &'static str {
            "A test tool"
        }

        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: "test_tool",
                description: "A test tool",
                input_schema: r#"{"type": "object", "properties": {}}"#,
            }
        }

        async fn execute(
            &self,
            _args: Option<serde_json::Value>,
            _ctx: &ToolContext,
        ) -> Result<ToolCallResult> {
            Ok(ToolCallResult::text("test result"))
        }
    }

    #[test]
    fn test_register_and_get() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(TestHandler));

        assert!(registry.get("test_tool").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_list_tools() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(TestHandler));

        let tools = registry.list_tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "test_tool");
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut registry = ToolRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry.register(Arc::new(TestHandler));
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_default_registry_has_all_tools() {
        let registry = create_default_registry();
        assert_eq!(registry.len(), 329);
        // Core
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_exec_multi").is_some());
        assert!(registry.get("ssh_status").is_some());
        assert!(registry.get("ssh_history").is_some());
        assert!(registry.get("ssh_health").is_some());
        assert!(registry.get("ssh_output_fetch").is_some());
        // Monitoring
        assert!(registry.get("ssh_metrics").is_some());
        assert!(registry.get("ssh_metrics_multi").is_some());
        assert!(registry.get("ssh_tail").is_some());
        // File transfer
        assert!(registry.get("ssh_upload").is_some());
        assert!(registry.get("ssh_download").is_some());
        assert!(registry.get("ssh_sync").is_some());
        // Sessions
        assert!(registry.get("ssh_session_create").is_some());
        assert!(registry.get("ssh_session_exec").is_some());
        assert!(registry.get("ssh_session_list").is_some());
        assert!(registry.get("ssh_session_close").is_some());
        // Tunnels
        assert!(registry.get("ssh_tunnel_create").is_some());
        assert!(registry.get("ssh_tunnel_list").is_some());
        assert!(registry.get("ssh_tunnel_close").is_some());
        // Directory
        assert!(registry.get("ssh_ls").is_some());
        assert!(registry.get("ssh_find").is_some());
        // Monitoring extra
        assert!(registry.get("ssh_disk_usage").is_some());
        // Database
        assert!(registry.get("ssh_db_query").is_some());
        assert!(registry.get("ssh_db_dump").is_some());
        assert!(registry.get("ssh_db_restore").is_some());
        // Backup
        assert!(registry.get("ssh_backup_create").is_some());
        assert!(registry.get("ssh_backup_list").is_some());
        assert!(registry.get("ssh_backup_restore").is_some());
        // Docker
        assert!(registry.get("ssh_docker_ps").is_some());
        assert!(registry.get("ssh_docker_logs").is_some());
        assert!(registry.get("ssh_docker_inspect").is_some());
        assert!(registry.get("ssh_docker_exec").is_some());
        assert!(registry.get("ssh_docker_compose").is_some());
        assert!(registry.get("ssh_docker_images").is_some());
        assert!(registry.get("ssh_docker_stats").is_some());
        assert!(registry.get("ssh_docker_volume_ls").is_some());
        assert!(registry.get("ssh_docker_network_ls").is_some());
        assert!(registry.get("ssh_docker_volume_inspect").is_some());
        assert!(registry.get("ssh_docker_network_inspect").is_some());
        // ESXi
        assert!(registry.get("ssh_esxi_vm_list").is_some());
        assert!(registry.get("ssh_esxi_vm_info").is_some());
        assert!(registry.get("ssh_esxi_vm_power").is_some());
        assert!(registry.get("ssh_esxi_snapshot").is_some());
        assert!(registry.get("ssh_esxi_host_info").is_some());
        assert!(registry.get("ssh_esxi_datastore_list").is_some());
        assert!(registry.get("ssh_esxi_network_list").is_some());
        // Git
        assert!(registry.get("ssh_git_status").is_some());
        assert!(registry.get("ssh_git_log").is_some());
        assert!(registry.get("ssh_git_diff").is_some());
        assert!(registry.get("ssh_git_pull").is_some());
        assert!(registry.get("ssh_git_clone").is_some());
        assert!(registry.get("ssh_git_branch").is_some());
        assert!(registry.get("ssh_git_checkout").is_some());
        // Kubernetes (kubectl)
        assert!(registry.get("ssh_k8s_get").is_some());
        assert!(registry.get("ssh_k8s_logs").is_some());
        assert!(registry.get("ssh_k8s_describe").is_some());
        assert!(registry.get("ssh_k8s_apply").is_some());
        assert!(registry.get("ssh_k8s_delete").is_some());
        assert!(registry.get("ssh_k8s_rollout").is_some());
        assert!(registry.get("ssh_k8s_scale").is_some());
        assert!(registry.get("ssh_k8s_exec").is_some());
        assert!(registry.get("ssh_k8s_top").is_some());
        // Kubernetes (helm)
        assert!(registry.get("ssh_helm_list").is_some());
        assert!(registry.get("ssh_helm_status").is_some());
        assert!(registry.get("ssh_helm_upgrade").is_some());
        assert!(registry.get("ssh_helm_install").is_some());
        assert!(registry.get("ssh_helm_rollback").is_some());
        assert!(registry.get("ssh_helm_history").is_some());
        assert!(registry.get("ssh_helm_uninstall").is_some());
        // Ansible
        assert!(registry.get("ssh_ansible_playbook").is_some());
        assert!(registry.get("ssh_ansible_inventory").is_some());
        assert!(registry.get("ssh_ansible_adhoc").is_some());
        // Systemd
        assert!(registry.get("ssh_service_status").is_some());
        assert!(registry.get("ssh_service_start").is_some());
        assert!(registry.get("ssh_service_stop").is_some());
        assert!(registry.get("ssh_service_restart").is_some());
        assert!(registry.get("ssh_service_list").is_some());
        assert!(registry.get("ssh_service_logs").is_some());
        assert!(registry.get("ssh_service_enable").is_some());
        assert!(registry.get("ssh_service_disable").is_some());
        assert!(registry.get("ssh_service_daemon_reload").is_some());
        // Network
        assert!(registry.get("ssh_net_connections").is_some());
        assert!(registry.get("ssh_net_interfaces").is_some());
        assert!(registry.get("ssh_net_routes").is_some());
        assert!(registry.get("ssh_net_ping").is_some());
        assert!(registry.get("ssh_net_traceroute").is_some());
        assert!(registry.get("ssh_net_dns").is_some());
        // Process
        assert!(registry.get("ssh_process_list").is_some());
        assert!(registry.get("ssh_process_kill").is_some());
        assert!(registry.get("ssh_process_top").is_some());
        // Package
        assert!(registry.get("ssh_pkg_list").is_some());
        assert!(registry.get("ssh_pkg_search").is_some());
        assert!(registry.get("ssh_pkg_install").is_some());
        assert!(registry.get("ssh_pkg_update").is_some());
        assert!(registry.get("ssh_pkg_remove").is_some());
        // Firewall
        assert!(registry.get("ssh_firewall_status").is_some());
        assert!(registry.get("ssh_firewall_list").is_some());
        assert!(registry.get("ssh_firewall_allow").is_some());
        assert!(registry.get("ssh_firewall_deny").is_some());
        // Cron
        assert!(registry.get("ssh_cron_list").is_some());
        assert!(registry.get("ssh_cron_add").is_some());
        assert!(registry.get("ssh_cron_remove").is_some());
        // Certificates
        assert!(registry.get("ssh_cert_check").is_some());
        assert!(registry.get("ssh_cert_info").is_some());
        assert!(registry.get("ssh_cert_expiry").is_some());
        // Nginx
        assert!(registry.get("ssh_nginx_status").is_some());
        assert!(registry.get("ssh_nginx_test").is_some());
        assert!(registry.get("ssh_nginx_reload").is_some());
        assert!(registry.get("ssh_nginx_list_sites").is_some());
        // Diagnostics
        assert!(registry.get("ssh_diagnose").is_some());
        assert!(registry.get("ssh_incident_triage").is_some());
        assert!(registry.get("ssh_compare_state").is_some());
        // Orchestration
        assert!(registry.get("ssh_canary_exec").is_some());
        assert!(registry.get("ssh_rolling_exec").is_some());
        assert!(registry.get("ssh_fleet_diff").is_some());
        // Runbooks
        assert!(registry.get("ssh_runbook_list").is_some());
        assert!(registry.get("ssh_runbook_execute").is_some());
        assert!(registry.get("ssh_runbook_validate").is_some());
        // Recording
        assert!(registry.get("ssh_recording_start").is_some());
        assert!(registry.get("ssh_recording_stop").is_some());
        assert!(registry.get("ssh_recording_list").is_some());
        assert!(registry.get("ssh_recording_replay").is_some());
        assert!(registry.get("ssh_recording_verify").is_some());
        // Redis
        assert!(registry.get("ssh_redis_info").is_some());
        assert!(registry.get("ssh_redis_cli").is_some());
        assert!(registry.get("ssh_redis_keys").is_some());
        // PostgreSQL
        assert!(registry.get("ssh_postgresql_query").is_some());
        assert!(registry.get("ssh_postgresql_status").is_some());
        // MySQL
        assert!(registry.get("ssh_mysql_query").is_some());
        assert!(registry.get("ssh_mysql_status").is_some());
        // Apache
        assert!(registry.get("ssh_apache_status").is_some());
        assert!(registry.get("ssh_apache_vhosts").is_some());
        // Let's Encrypt
        assert!(registry.get("ssh_letsencrypt_status").is_some());
        // MongoDB
        assert!(registry.get("ssh_mongodb_status").is_some());
        // Terraform
        assert!(registry.get("ssh_terraform_init").is_some());
        assert!(registry.get("ssh_terraform_plan").is_some());
        assert!(registry.get("ssh_terraform_apply").is_some());
        assert!(registry.get("ssh_terraform_state").is_some());
        assert!(registry.get("ssh_terraform_output").is_some());
        // Vault
        assert!(registry.get("ssh_vault_status").is_some());
        assert!(registry.get("ssh_vault_read").is_some());
        assert!(registry.get("ssh_vault_list").is_some());
        assert!(registry.get("ssh_vault_write").is_some());
        // Config
        assert!(registry.get("ssh_config_get").is_some());
        assert!(registry.get("ssh_config_set").is_some());
        // Windows Services
        assert!(registry.get("ssh_win_service_status").is_some());
        assert!(registry.get("ssh_win_service_start").is_some());
        assert!(registry.get("ssh_win_service_stop").is_some());
        assert!(registry.get("ssh_win_service_restart").is_some());
        assert!(registry.get("ssh_win_service_list").is_some());
        assert!(registry.get("ssh_win_service_enable").is_some());
        assert!(registry.get("ssh_win_service_disable").is_some());
        assert!(registry.get("ssh_win_service_config").is_some());
        assert!(registry.get("ssh_win_event_logs").is_some());
        // Windows Events
        assert!(registry.get("ssh_win_event_query").is_some());
        assert!(registry.get("ssh_win_event_sources").is_some());
        assert!(registry.get("ssh_win_event_tail").is_some());
        assert!(registry.get("ssh_win_event_export").is_some());
        // Active Directory
        assert!(registry.get("ssh_ad_user_list").is_some());
        assert!(registry.get("ssh_ad_user_info").is_some());
        assert!(registry.get("ssh_ad_group_list").is_some());
        assert!(registry.get("ssh_ad_group_members").is_some());
        assert!(registry.get("ssh_ad_computer_list").is_some());
        assert!(registry.get("ssh_ad_domain_info").is_some());
        // Scheduled Tasks
        assert!(registry.get("ssh_schtask_list").is_some());
        assert!(registry.get("ssh_schtask_info").is_some());
        assert!(registry.get("ssh_schtask_run").is_some());
        assert!(registry.get("ssh_schtask_enable").is_some());
        assert!(registry.get("ssh_schtask_disable").is_some());
        // Windows Firewall
        assert!(registry.get("ssh_win_firewall_status").is_some());
        assert!(registry.get("ssh_win_firewall_list").is_some());
        assert!(registry.get("ssh_win_firewall_allow").is_some());
        assert!(registry.get("ssh_win_firewall_deny").is_some());
        assert!(registry.get("ssh_win_firewall_remove").is_some());
        // IIS
        assert!(registry.get("ssh_iis_status").is_some());
        assert!(registry.get("ssh_iis_list_sites").is_some());
        assert!(registry.get("ssh_iis_list_pools").is_some());
        assert!(registry.get("ssh_iis_start").is_some());
        assert!(registry.get("ssh_iis_stop").is_some());
        assert!(registry.get("ssh_iis_restart").is_some());
        // Windows Updates
        assert!(registry.get("ssh_win_update_list").is_some());
        assert!(registry.get("ssh_win_update_history").is_some());
        assert!(registry.get("ssh_win_update_install").is_some());
        assert!(registry.get("ssh_win_update_search").is_some());
        assert!(registry.get("ssh_win_update_reboot").is_some());
        // Windows Performance
        assert!(registry.get("ssh_win_perf_cpu").is_some());
        assert!(registry.get("ssh_win_perf_memory").is_some());
        assert!(registry.get("ssh_win_perf_disk").is_some());
        assert!(registry.get("ssh_win_perf_network").is_some());
        assert!(registry.get("ssh_win_perf_overview").is_some());
        // Hyper-V
        assert!(registry.get("ssh_hyperv_vm_list").is_some());
        assert!(registry.get("ssh_hyperv_vm_info").is_some());
        assert!(registry.get("ssh_hyperv_vm_start").is_some());
        assert!(registry.get("ssh_hyperv_vm_stop").is_some());
        assert!(registry.get("ssh_hyperv_snapshot_list").is_some());
        assert!(registry.get("ssh_hyperv_snapshot_create").is_some());
        assert!(registry.get("ssh_hyperv_host_info").is_some());
        assert!(registry.get("ssh_hyperv_switch_list").is_some());
        // Windows Registry
        assert!(registry.get("ssh_reg_query").is_some());
        assert!(registry.get("ssh_reg_set").is_some());
        assert!(registry.get("ssh_reg_list").is_some());
        assert!(registry.get("ssh_reg_export").is_some());
        assert!(registry.get("ssh_reg_delete").is_some());
        // Windows Features
        assert!(registry.get("ssh_win_feature_list").is_some());
        assert!(registry.get("ssh_win_feature_info").is_some());
        assert!(registry.get("ssh_win_feature_install").is_some());
        assert!(registry.get("ssh_win_feature_remove").is_some());
        // Windows Network
        assert!(registry.get("ssh_win_net_adapters").is_some());
        assert!(registry.get("ssh_win_net_ip").is_some());
        assert!(registry.get("ssh_win_net_routes").is_some());
        assert!(registry.get("ssh_win_net_connections").is_some());
        assert!(registry.get("ssh_win_net_ping").is_some());
        assert!(registry.get("ssh_win_net_dns").is_some());
        // Windows Process
        assert!(registry.get("ssh_win_process_list").is_some());
        assert!(registry.get("ssh_win_process_info").is_some());
        assert!(registry.get("ssh_win_process_kill").is_some());
        assert!(registry.get("ssh_win_process_top").is_some());
        assert!(registry.get("ssh_win_process_by_name").is_some());
        assert!(registry.get("ssh_win_disk_usage").is_some());
    }

    #[tokio::test]
    async fn test_execute_unknown_tool() {
        let registry = ToolRegistry::new();
        let ctx = create_test_context();
        let result = registry.execute("unknown", None, &ctx).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BridgeError::McpUnknownTool { tool } => {
                assert_eq!(tool, "unknown");
            }
            e => panic!("Expected McpUnknownTool error, got: {e:?}"),
        }
    }

    #[tokio::test]
    async fn test_execute_registered_tool() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(TestHandler));
        let ctx = create_test_context();

        let result = registry.execute("test_tool", None, &ctx).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(!call_result.content.is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_tool_group_mapping() {
        assert_eq!(tool_group("ssh_exec"), "core");
        assert_eq!(tool_group("ssh_exec_multi"), "core");
        assert_eq!(tool_group("ssh_status"), "core");
        assert_eq!(tool_group("ssh_health"), "core");
        assert_eq!(tool_group("ssh_history"), "core");
        assert_eq!(tool_group("ssh_output_fetch"), "core");
        assert_eq!(tool_group("ssh_upload"), "file_transfer");
        assert_eq!(tool_group("ssh_download"), "file_transfer");
        assert_eq!(tool_group("ssh_sync"), "file_transfer");
        assert_eq!(tool_group("ssh_session_create"), "sessions");
        assert_eq!(tool_group("ssh_session_exec"), "sessions");
        assert_eq!(tool_group("ssh_session_list"), "sessions");
        assert_eq!(tool_group("ssh_session_close"), "sessions");
        assert_eq!(tool_group("ssh_metrics"), "monitoring");
        assert_eq!(tool_group("ssh_metrics_multi"), "monitoring");
        assert_eq!(tool_group("ssh_tail"), "monitoring");
        assert_eq!(tool_group("ssh_tunnel_create"), "tunnels");
        assert_eq!(tool_group("ssh_tunnel_list"), "tunnels");
        assert_eq!(tool_group("ssh_tunnel_close"), "tunnels");
        assert_eq!(tool_group("ssh_ls"), "directory");
        assert_eq!(tool_group("ssh_find"), "directory");
        assert_eq!(tool_group("ssh_disk_usage"), "monitoring");
        assert_eq!(tool_group("ssh_db_query"), "database");
        assert_eq!(tool_group("ssh_db_dump"), "database");
        assert_eq!(tool_group("ssh_db_restore"), "database");
        assert_eq!(tool_group("ssh_backup_create"), "backup");
        assert_eq!(tool_group("ssh_backup_list"), "backup");
        assert_eq!(tool_group("ssh_backup_restore"), "backup");
        // Docker
        assert_eq!(tool_group("ssh_docker_ps"), "docker");
        assert_eq!(tool_group("ssh_docker_logs"), "docker");
        assert_eq!(tool_group("ssh_docker_inspect"), "docker");
        assert_eq!(tool_group("ssh_docker_exec"), "docker");
        assert_eq!(tool_group("ssh_docker_compose"), "docker");
        assert_eq!(tool_group("ssh_docker_images"), "docker");
        assert_eq!(tool_group("ssh_docker_stats"), "docker");
        assert_eq!(tool_group("ssh_docker_volume_ls"), "docker");
        assert_eq!(tool_group("ssh_docker_network_ls"), "docker");
        assert_eq!(tool_group("ssh_docker_volume_inspect"), "docker");
        assert_eq!(tool_group("ssh_docker_network_inspect"), "docker");
        // ESXi
        assert_eq!(tool_group("ssh_esxi_vm_list"), "esxi");
        assert_eq!(tool_group("ssh_esxi_vm_info"), "esxi");
        assert_eq!(tool_group("ssh_esxi_vm_power"), "esxi");
        assert_eq!(tool_group("ssh_esxi_snapshot"), "esxi");
        assert_eq!(tool_group("ssh_esxi_host_info"), "esxi");
        assert_eq!(tool_group("ssh_esxi_datastore_list"), "esxi");
        assert_eq!(tool_group("ssh_esxi_network_list"), "esxi");
        // Git
        assert_eq!(tool_group("ssh_git_status"), "git");
        assert_eq!(tool_group("ssh_git_log"), "git");
        assert_eq!(tool_group("ssh_git_diff"), "git");
        assert_eq!(tool_group("ssh_git_pull"), "git");
        assert_eq!(tool_group("ssh_git_clone"), "git");
        assert_eq!(tool_group("ssh_git_branch"), "git");
        assert_eq!(tool_group("ssh_git_checkout"), "git");
        // Kubernetes (kubectl)
        assert_eq!(tool_group("ssh_k8s_get"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_logs"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_describe"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_apply"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_delete"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_rollout"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_scale"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_exec"), "kubernetes");
        assert_eq!(tool_group("ssh_k8s_top"), "kubernetes");
        // Kubernetes (helm)
        assert_eq!(tool_group("ssh_helm_list"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_status"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_upgrade"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_install"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_rollback"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_history"), "kubernetes");
        assert_eq!(tool_group("ssh_helm_uninstall"), "kubernetes");
        // Ansible
        assert_eq!(tool_group("ssh_ansible_playbook"), "ansible");
        assert_eq!(tool_group("ssh_ansible_inventory"), "ansible");
        assert_eq!(tool_group("ssh_ansible_adhoc"), "ansible");
        // Systemd
        assert_eq!(tool_group("ssh_service_status"), "systemd");
        assert_eq!(tool_group("ssh_service_start"), "systemd");
        assert_eq!(tool_group("ssh_service_stop"), "systemd");
        assert_eq!(tool_group("ssh_service_restart"), "systemd");
        assert_eq!(tool_group("ssh_service_list"), "systemd");
        assert_eq!(tool_group("ssh_service_logs"), "systemd");
        assert_eq!(tool_group("ssh_service_enable"), "systemd");
        assert_eq!(tool_group("ssh_service_disable"), "systemd");
        assert_eq!(tool_group("ssh_service_daemon_reload"), "systemd");
        // Network
        assert_eq!(tool_group("ssh_net_connections"), "network");
        assert_eq!(tool_group("ssh_net_interfaces"), "network");
        assert_eq!(tool_group("ssh_net_routes"), "network");
        assert_eq!(tool_group("ssh_net_ping"), "network");
        assert_eq!(tool_group("ssh_net_traceroute"), "network");
        assert_eq!(tool_group("ssh_net_dns"), "network");
        // Process
        assert_eq!(tool_group("ssh_process_list"), "process");
        assert_eq!(tool_group("ssh_process_kill"), "process");
        assert_eq!(tool_group("ssh_process_top"), "process");
        // Package
        assert_eq!(tool_group("ssh_pkg_list"), "package");
        assert_eq!(tool_group("ssh_pkg_search"), "package");
        assert_eq!(tool_group("ssh_pkg_install"), "package");
        assert_eq!(tool_group("ssh_pkg_update"), "package");
        assert_eq!(tool_group("ssh_pkg_remove"), "package");
        // Firewall
        assert_eq!(tool_group("ssh_firewall_status"), "firewall");
        assert_eq!(tool_group("ssh_firewall_list"), "firewall");
        assert_eq!(tool_group("ssh_firewall_allow"), "firewall");
        assert_eq!(tool_group("ssh_firewall_deny"), "firewall");
        // Cron
        assert_eq!(tool_group("ssh_cron_list"), "cron");
        assert_eq!(tool_group("ssh_cron_add"), "cron");
        assert_eq!(tool_group("ssh_cron_remove"), "cron");
        // Certificates
        assert_eq!(tool_group("ssh_cert_check"), "certificates");
        assert_eq!(tool_group("ssh_cert_info"), "certificates");
        assert_eq!(tool_group("ssh_cert_expiry"), "certificates");
        // Nginx
        assert_eq!(tool_group("ssh_nginx_status"), "nginx");
        assert_eq!(tool_group("ssh_nginx_test"), "nginx");
        assert_eq!(tool_group("ssh_nginx_reload"), "nginx");
        assert_eq!(tool_group("ssh_nginx_list_sites"), "nginx");
        // Diagnostics
        assert_eq!(tool_group("ssh_diagnose"), "diagnostics");
        assert_eq!(tool_group("ssh_incident_triage"), "diagnostics");
        assert_eq!(tool_group("ssh_compare_state"), "diagnostics");
        // Orchestration
        assert_eq!(tool_group("ssh_canary_exec"), "orchestration");
        assert_eq!(tool_group("ssh_rolling_exec"), "orchestration");
        assert_eq!(tool_group("ssh_fleet_diff"), "orchestration");
        // Drift
        assert_eq!(tool_group("ssh_env_snapshot"), "drift");
        assert_eq!(tool_group("ssh_env_diff"), "drift");
        assert_eq!(tool_group("ssh_env_drift"), "drift");
        // File Advanced (in file_ops group)
        assert_eq!(tool_group("ssh_file_diff"), "file_ops");
        assert_eq!(tool_group("ssh_file_patch"), "file_ops");
        assert_eq!(tool_group("ssh_file_template"), "file_ops");
        // Security Scanning
        assert_eq!(tool_group("ssh_sbom_generate"), "security_scan");
        assert_eq!(tool_group("ssh_vuln_scan"), "security_scan");
        assert_eq!(tool_group("ssh_compliance_check"), "security_scan");
        // Runbooks
        assert_eq!(tool_group("ssh_runbook_list"), "runbooks");
        assert_eq!(tool_group("ssh_runbook_execute"), "runbooks");
        assert_eq!(tool_group("ssh_runbook_validate"), "runbooks");
        // Recording
        assert_eq!(tool_group("ssh_recording_start"), "recording");
        assert_eq!(tool_group("ssh_recording_stop"), "recording");
        assert_eq!(tool_group("ssh_recording_list"), "recording");
        assert_eq!(tool_group("ssh_recording_replay"), "recording");
        assert_eq!(tool_group("ssh_recording_verify"), "recording");
        // Redis
        assert_eq!(tool_group("ssh_redis_info"), "redis");
        assert_eq!(tool_group("ssh_redis_cli"), "redis");
        assert_eq!(tool_group("ssh_redis_keys"), "redis");
        // Terraform
        assert_eq!(tool_group("ssh_terraform_init"), "terraform");
        assert_eq!(tool_group("ssh_terraform_plan"), "terraform");
        assert_eq!(tool_group("ssh_terraform_apply"), "terraform");
        assert_eq!(tool_group("ssh_terraform_state"), "terraform");
        assert_eq!(tool_group("ssh_terraform_output"), "terraform");
        // Vault
        assert_eq!(tool_group("ssh_vault_status"), "vault");
        assert_eq!(tool_group("ssh_vault_read"), "vault");
        assert_eq!(tool_group("ssh_vault_list"), "vault");
        assert_eq!(tool_group("ssh_vault_write"), "vault");
        // Config
        assert_eq!(tool_group("ssh_config_get"), "config");
        assert_eq!(tool_group("ssh_config_set"), "config");
        // Windows Services
        assert_eq!(tool_group("ssh_win_service_status"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_start"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_stop"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_restart"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_list"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_enable"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_disable"), "windows_services");
        assert_eq!(tool_group("ssh_win_service_config"), "windows_services");
        // Windows Events
        assert_eq!(tool_group("ssh_win_event_logs"), "windows_events");
        assert_eq!(tool_group("ssh_win_event_query"), "windows_events");
        assert_eq!(tool_group("ssh_win_event_sources"), "windows_events");
        assert_eq!(tool_group("ssh_win_event_tail"), "windows_events");
        assert_eq!(tool_group("ssh_win_event_export"), "windows_events");
        // Active Directory
        assert_eq!(tool_group("ssh_ad_user_list"), "active_directory");
        assert_eq!(tool_group("ssh_ad_user_info"), "active_directory");
        assert_eq!(tool_group("ssh_ad_group_list"), "active_directory");
        assert_eq!(tool_group("ssh_ad_group_members"), "active_directory");
        assert_eq!(tool_group("ssh_ad_computer_list"), "active_directory");
        assert_eq!(tool_group("ssh_ad_domain_info"), "active_directory");
        // Scheduled Tasks
        assert_eq!(tool_group("ssh_schtask_list"), "scheduled_tasks");
        assert_eq!(tool_group("ssh_schtask_info"), "scheduled_tasks");
        assert_eq!(tool_group("ssh_schtask_run"), "scheduled_tasks");
        assert_eq!(tool_group("ssh_schtask_enable"), "scheduled_tasks");
        assert_eq!(tool_group("ssh_schtask_disable"), "scheduled_tasks");
        // Windows Firewall
        assert_eq!(tool_group("ssh_win_firewall_status"), "windows_firewall");
        assert_eq!(tool_group("ssh_win_firewall_list"), "windows_firewall");
        assert_eq!(tool_group("ssh_win_firewall_allow"), "windows_firewall");
        assert_eq!(tool_group("ssh_win_firewall_deny"), "windows_firewall");
        assert_eq!(tool_group("ssh_win_firewall_remove"), "windows_firewall");
        // IIS
        assert_eq!(tool_group("ssh_iis_status"), "iis");
        assert_eq!(tool_group("ssh_iis_list_sites"), "iis");
        assert_eq!(tool_group("ssh_iis_list_pools"), "iis");
        assert_eq!(tool_group("ssh_iis_start"), "iis");
        assert_eq!(tool_group("ssh_iis_stop"), "iis");
        assert_eq!(tool_group("ssh_iis_restart"), "iis");
        // Windows Updates
        assert_eq!(tool_group("ssh_win_update_list"), "windows_updates");
        assert_eq!(tool_group("ssh_win_update_history"), "windows_updates");
        assert_eq!(tool_group("ssh_win_update_install"), "windows_updates");
        assert_eq!(tool_group("ssh_win_update_search"), "windows_updates");
        assert_eq!(tool_group("ssh_win_update_reboot"), "windows_updates");
        // Windows Performance
        assert_eq!(tool_group("ssh_win_perf_cpu"), "windows_perf");
        assert_eq!(tool_group("ssh_win_perf_memory"), "windows_perf");
        assert_eq!(tool_group("ssh_win_perf_disk"), "windows_perf");
        assert_eq!(tool_group("ssh_win_perf_network"), "windows_perf");
        assert_eq!(tool_group("ssh_win_perf_overview"), "windows_perf");
        assert_eq!(tool_group("ssh_win_disk_usage"), "windows_perf");
        // Hyper-V
        assert_eq!(tool_group("ssh_hyperv_vm_list"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_vm_info"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_vm_start"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_vm_stop"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_snapshot_list"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_snapshot_create"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_host_info"), "hyperv");
        assert_eq!(tool_group("ssh_hyperv_switch_list"), "hyperv");
        // Windows Registry
        assert_eq!(tool_group("ssh_reg_query"), "windows_registry");
        assert_eq!(tool_group("ssh_reg_set"), "windows_registry");
        assert_eq!(tool_group("ssh_reg_list"), "windows_registry");
        assert_eq!(tool_group("ssh_reg_export"), "windows_registry");
        assert_eq!(tool_group("ssh_reg_delete"), "windows_registry");
        // Windows Features
        assert_eq!(tool_group("ssh_win_feature_list"), "windows_features");
        assert_eq!(tool_group("ssh_win_feature_info"), "windows_features");
        assert_eq!(tool_group("ssh_win_feature_install"), "windows_features");
        assert_eq!(tool_group("ssh_win_feature_remove"), "windows_features");
        // Windows Network
        assert_eq!(tool_group("ssh_win_net_adapters"), "windows_network");
        assert_eq!(tool_group("ssh_win_net_ip"), "windows_network");
        assert_eq!(tool_group("ssh_win_net_routes"), "windows_network");
        assert_eq!(tool_group("ssh_win_net_connections"), "windows_network");
        assert_eq!(tool_group("ssh_win_net_ping"), "windows_network");
        assert_eq!(tool_group("ssh_win_net_dns"), "windows_network");
        // Windows Process
        assert_eq!(tool_group("ssh_win_process_list"), "windows_process");
        assert_eq!(tool_group("ssh_win_process_info"), "windows_process");
        assert_eq!(tool_group("ssh_win_process_kill"), "windows_process");
        assert_eq!(tool_group("ssh_win_process_top"), "windows_process");
        assert_eq!(tool_group("ssh_win_process_by_name"), "windows_process");
        // Unknown defaults to core
        assert_eq!(tool_group("unknown_tool"), "core");
    }

    #[test]
    fn test_filtered_registry_all_enabled() {
        let config = ToolGroupsConfig::default();
        let registry = create_filtered_registry(&config);
        assert_eq!(registry.len(), 329);
    }

    #[test]
    fn test_filtered_registry_disable_sessions() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("sessions".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 4 session tools = 246
        assert_eq!(registry.len(), 325);
        assert!(registry.get("ssh_session_create").is_none());
        assert!(registry.get("ssh_session_exec").is_none());
        assert!(registry.get("ssh_session_list").is_none());
        assert!(registry.get("ssh_session_close").is_none());
        // Core tools still present
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_monitoring() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("monitoring".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 4 monitoring tools  = 246
        assert_eq!(registry.len(), 325);
        assert!(registry.get("ssh_metrics").is_none());
        assert!(registry.get("ssh_metrics_multi").is_none());
        assert!(registry.get("ssh_tail").is_none());
    }

    #[test]
    fn test_filtered_registry_disable_file_transfer() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("file_transfer".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 3 file transfer tools  = 247
        assert_eq!(registry.len(), 326);
        assert!(registry.get("ssh_upload").is_none());
        assert!(registry.get("ssh_download").is_none());
        assert!(registry.get("ssh_sync").is_none());
    }

    #[test]
    fn test_filtered_registry_disable_multiple_groups() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("sessions".to_string(), false);
        groups.insert("monitoring".to_string(), false);
        groups.insert("file_transfer".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus sessions(4) + monitoring(4) + file_transfer(3) = 270
        assert_eq!(registry.len(), 318);
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_exec_multi").is_some());
        assert!(registry.get("ssh_status").is_some());
        assert!(registry.get("ssh_health").is_some());
        assert!(registry.get("ssh_history").is_some());
    }

    #[test]
    fn test_filtered_registry_explicit_enable() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("core".to_string(), true);
        groups.insert("sessions".to_string(), true);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // All groups enabled (unlisted default to true)
        assert_eq!(registry.len(), 329);
    }

    #[test]
    fn test_filtered_registry_disable_tunnels() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("tunnels".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 3 tunnel tools  = 247
        assert_eq!(registry.len(), 326);
        assert!(registry.get("ssh_tunnel_create").is_none());
        assert!(registry.get("ssh_tunnel_list").is_none());
        assert!(registry.get("ssh_tunnel_close").is_none());
        // Core tools still present
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_kubernetes() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("kubernetes".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 16 kubernetes tools (9 k8s + 7 helm)  = 234
        assert_eq!(registry.len(), 313);
        // kubectl tools removed
        assert!(registry.get("ssh_k8s_get").is_none());
        assert!(registry.get("ssh_k8s_logs").is_none());
        assert!(registry.get("ssh_k8s_describe").is_none());
        assert!(registry.get("ssh_k8s_apply").is_none());
        assert!(registry.get("ssh_k8s_delete").is_none());
        assert!(registry.get("ssh_k8s_rollout").is_none());
        assert!(registry.get("ssh_k8s_scale").is_none());
        assert!(registry.get("ssh_k8s_exec").is_none());
        assert!(registry.get("ssh_k8s_top").is_none());
        // helm tools removed
        assert!(registry.get("ssh_helm_list").is_none());
        assert!(registry.get("ssh_helm_status").is_none());
        assert!(registry.get("ssh_helm_upgrade").is_none());
        assert!(registry.get("ssh_helm_install").is_none());
        assert!(registry.get("ssh_helm_rollback").is_none());
        assert!(registry.get("ssh_helm_history").is_none());
        assert!(registry.get("ssh_helm_uninstall").is_none());
        // Other groups still present
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_ansible_playbook").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_ansible() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("ansible".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 3 ansible tools  = 247
        assert_eq!(registry.len(), 326);
        assert!(registry.get("ssh_ansible_playbook").is_none());
        assert!(registry.get("ssh_ansible_inventory").is_none());
        assert!(registry.get("ssh_ansible_adhoc").is_none());
        // Kubernetes tools still present
        assert!(registry.get("ssh_k8s_get").is_some());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_docker() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("docker".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 11 docker tools  = 270
        assert_eq!(registry.len(), 318);
        assert!(registry.get("ssh_docker_ps").is_none());
        assert!(registry.get("ssh_docker_logs").is_none());
        assert!(registry.get("ssh_docker_inspect").is_none());
        assert!(registry.get("ssh_docker_exec").is_none());
        assert!(registry.get("ssh_docker_compose").is_none());
        assert!(registry.get("ssh_docker_images").is_none());
        assert!(registry.get("ssh_docker_stats").is_none());
        assert!(registry.get("ssh_docker_volume_ls").is_none());
        assert!(registry.get("ssh_docker_network_ls").is_none());
        assert!(registry.get("ssh_docker_volume_inspect").is_none());
        assert!(registry.get("ssh_docker_network_inspect").is_none());
        // Other groups still present
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_k8s_get").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_esxi() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("esxi".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 7 esxi tools  = 243
        assert_eq!(registry.len(), 322);
        assert!(registry.get("ssh_esxi_vm_list").is_none());
        assert!(registry.get("ssh_esxi_vm_info").is_none());
        assert!(registry.get("ssh_esxi_vm_power").is_none());
        assert!(registry.get("ssh_esxi_snapshot").is_none());
        assert!(registry.get("ssh_esxi_host_info").is_none());
        assert!(registry.get("ssh_esxi_datastore_list").is_none());
        assert!(registry.get("ssh_esxi_network_list").is_none());
        // Other groups still present
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_docker_ps").is_some());
        assert!(registry.get("ssh_k8s_get").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_git() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("git".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 7 git tools  = 243
        assert_eq!(registry.len(), 322);
        assert!(registry.get("ssh_git_status").is_none());
        assert!(registry.get("ssh_git_log").is_none());
        assert!(registry.get("ssh_git_diff").is_none());
        assert!(registry.get("ssh_git_pull").is_none());
        assert!(registry.get("ssh_git_clone").is_none());
        assert!(registry.get("ssh_git_branch").is_none());
        assert!(registry.get("ssh_git_checkout").is_none());
        // Other groups still present
        assert!(registry.get("ssh_exec").is_some());
        assert!(registry.get("ssh_docker_ps").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_systemd() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("systemd".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 9 systemd tools  = 272
        assert_eq!(registry.len(), 320);
        assert!(registry.get("ssh_service_status").is_none());
        assert!(registry.get("ssh_service_start").is_none());
        assert!(registry.get("ssh_service_stop").is_none());
        assert!(registry.get("ssh_service_restart").is_none());
        assert!(registry.get("ssh_service_list").is_none());
        assert!(registry.get("ssh_service_logs").is_none());
        assert!(registry.get("ssh_service_enable").is_none());
        assert!(registry.get("ssh_service_disable").is_none());
        assert!(registry.get("ssh_service_daemon_reload").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_network() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("network".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 6 network tools  = 244
        assert_eq!(registry.len(), 323);
        assert!(registry.get("ssh_net_connections").is_none());
        assert!(registry.get("ssh_net_interfaces").is_none());
        assert!(registry.get("ssh_net_routes").is_none());
        assert!(registry.get("ssh_net_ping").is_none());
        assert!(registry.get("ssh_net_traceroute").is_none());
        assert!(registry.get("ssh_net_dns").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_process() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("process".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 3 process tools  = 247
        assert_eq!(registry.len(), 326);
        assert!(registry.get("ssh_process_list").is_none());
        assert!(registry.get("ssh_process_kill").is_none());
        assert!(registry.get("ssh_process_top").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_package() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("package".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 5 package tools  = 276
        assert_eq!(registry.len(), 324);
        assert!(registry.get("ssh_pkg_list").is_none());
        assert!(registry.get("ssh_pkg_search").is_none());
        assert!(registry.get("ssh_pkg_install").is_none());
        assert!(registry.get("ssh_pkg_update").is_none());
        assert!(registry.get("ssh_pkg_remove").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_firewall() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("firewall".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 4 firewall tools  = 246
        assert_eq!(registry.len(), 325);
        assert!(registry.get("ssh_firewall_status").is_none());
        assert!(registry.get("ssh_firewall_list").is_none());
        assert!(registry.get("ssh_firewall_allow").is_none());
        assert!(registry.get("ssh_firewall_deny").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_cron() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("cron".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 3 cron tools  = 247
        assert_eq!(registry.len(), 326);
        assert!(registry.get("ssh_cron_list").is_none());
        assert!(registry.get("ssh_cron_add").is_none());
        assert!(registry.get("ssh_cron_remove").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_certificates() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("certificates".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 3 certificate tools  = 247
        assert_eq!(registry.len(), 326);
        assert!(registry.get("ssh_cert_check").is_none());
        assert!(registry.get("ssh_cert_info").is_none());
        assert!(registry.get("ssh_cert_expiry").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_nginx() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("nginx".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 4 nginx tools  = 246
        assert_eq!(registry.len(), 325);
        assert!(registry.get("ssh_nginx_status").is_none());
        assert!(registry.get("ssh_nginx_test").is_none());
        assert!(registry.get("ssh_nginx_reload").is_none());
        assert!(registry.get("ssh_nginx_list_sites").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_redis() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("redis".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 3 redis tools  = 247
        assert_eq!(registry.len(), 326);
        assert!(registry.get("ssh_redis_info").is_none());
        assert!(registry.get("ssh_redis_cli").is_none());
        assert!(registry.get("ssh_redis_keys").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_terraform() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("terraform".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 5 terraform tools  = 276
        assert_eq!(registry.len(), 324);
        assert!(registry.get("ssh_terraform_init").is_none());
        assert!(registry.get("ssh_terraform_plan").is_none());
        assert!(registry.get("ssh_terraform_apply").is_none());
        assert!(registry.get("ssh_terraform_state").is_none());
        assert!(registry.get("ssh_terraform_output").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_vault() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("vault".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 4 vault tools  = 246
        assert_eq!(registry.len(), 325);
        assert!(registry.get("ssh_vault_status").is_none());
        assert!(registry.get("ssh_vault_read").is_none());
        assert!(registry.get("ssh_vault_list").is_none());
        assert!(registry.get("ssh_vault_write").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_config() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("config".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 2 config tools  = 248
        assert_eq!(registry.len(), 327);
        assert!(registry.get("ssh_config_get").is_none());
        assert!(registry.get("ssh_config_set").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    // ============== Tool Annotations Tests ==============

    #[test]
    fn test_filtered_registry_disable_windows_services() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("windows_services".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 8 windows_services tools  = 242
        assert_eq!(registry.len(), 321);
        assert!(registry.get("ssh_win_service_status").is_none());
        assert!(registry.get("ssh_win_service_start").is_none());
        assert!(registry.get("ssh_win_service_stop").is_none());
        assert!(registry.get("ssh_win_service_restart").is_none());
        assert!(registry.get("ssh_win_service_list").is_none());
        assert!(registry.get("ssh_win_service_enable").is_none());
        assert!(registry.get("ssh_win_service_disable").is_none());
        assert!(registry.get("ssh_win_service_config").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_events() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("windows_events".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 5 windows_events tools  = 276
        assert_eq!(registry.len(), 324);
        assert!(registry.get("ssh_win_event_logs").is_none());
        assert!(registry.get("ssh_win_event_query").is_none());
        assert!(registry.get("ssh_win_event_sources").is_none());
        assert!(registry.get("ssh_win_event_tail").is_none());
        assert!(registry.get("ssh_win_event_export").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_active_directory() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("active_directory".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 6 active_directory tools  = 244
        assert_eq!(registry.len(), 323);
        assert!(registry.get("ssh_ad_user_list").is_none());
        assert!(registry.get("ssh_ad_user_info").is_none());
        assert!(registry.get("ssh_ad_group_list").is_none());
        assert!(registry.get("ssh_ad_group_members").is_none());
        assert!(registry.get("ssh_ad_computer_list").is_none());
        assert!(registry.get("ssh_ad_domain_info").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_scheduled_tasks() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("scheduled_tasks".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 5 scheduled_tasks tools  = 276
        assert_eq!(registry.len(), 324);
        assert!(registry.get("ssh_schtask_list").is_none());
        assert!(registry.get("ssh_schtask_info").is_none());
        assert!(registry.get("ssh_schtask_run").is_none());
        assert!(registry.get("ssh_schtask_enable").is_none());
        assert!(registry.get("ssh_schtask_disable").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_firewall() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("windows_firewall".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 5 windows_firewall tools  = 276
        assert_eq!(registry.len(), 324);
        assert!(registry.get("ssh_win_firewall_status").is_none());
        assert!(registry.get("ssh_win_firewall_list").is_none());
        assert!(registry.get("ssh_win_firewall_allow").is_none());
        assert!(registry.get("ssh_win_firewall_deny").is_none());
        assert!(registry.get("ssh_win_firewall_remove").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_iis() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("iis".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 6 iis tools  = 244
        assert_eq!(registry.len(), 323);
        assert!(registry.get("ssh_iis_status").is_none());
        assert!(registry.get("ssh_iis_list_sites").is_none());
        assert!(registry.get("ssh_iis_list_pools").is_none());
        assert!(registry.get("ssh_iis_start").is_none());
        assert!(registry.get("ssh_iis_stop").is_none());
        assert!(registry.get("ssh_iis_restart").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_updates() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("windows_updates".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 5 windows_updates tools  = 276
        assert_eq!(registry.len(), 324);
        assert!(registry.get("ssh_win_update_list").is_none());
        assert!(registry.get("ssh_win_update_history").is_none());
        assert!(registry.get("ssh_win_update_install").is_none());
        assert!(registry.get("ssh_win_update_search").is_none());
        assert!(registry.get("ssh_win_update_reboot").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_perf() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("windows_perf".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 6 windows_perf tools  = 244
        assert_eq!(registry.len(), 323);
        assert!(registry.get("ssh_win_perf_cpu").is_none());
        assert!(registry.get("ssh_win_perf_memory").is_none());
        assert!(registry.get("ssh_win_perf_disk").is_none());
        assert!(registry.get("ssh_win_perf_network").is_none());
        assert!(registry.get("ssh_win_perf_overview").is_none());
        assert!(registry.get("ssh_win_disk_usage").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_hyperv() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("hyperv".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 8 hyperv tools  = 242
        assert_eq!(registry.len(), 321);
        assert!(registry.get("ssh_hyperv_vm_list").is_none());
        assert!(registry.get("ssh_hyperv_vm_info").is_none());
        assert!(registry.get("ssh_hyperv_vm_start").is_none());
        assert!(registry.get("ssh_hyperv_vm_stop").is_none());
        assert!(registry.get("ssh_hyperv_snapshot_list").is_none());
        assert!(registry.get("ssh_hyperv_snapshot_create").is_none());
        assert!(registry.get("ssh_hyperv_host_info").is_none());
        assert!(registry.get("ssh_hyperv_switch_list").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_registry() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("windows_registry".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 5 windows_registry tools  = 276
        assert_eq!(registry.len(), 324);
        assert!(registry.get("ssh_reg_query").is_none());
        assert!(registry.get("ssh_reg_set").is_none());
        assert!(registry.get("ssh_reg_list").is_none());
        assert!(registry.get("ssh_reg_export").is_none());
        assert!(registry.get("ssh_reg_delete").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_features() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("windows_features".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 4 windows_features tools  = 246
        assert_eq!(registry.len(), 325);
        assert!(registry.get("ssh_win_feature_list").is_none());
        assert!(registry.get("ssh_win_feature_info").is_none());
        assert!(registry.get("ssh_win_feature_install").is_none());
        assert!(registry.get("ssh_win_feature_remove").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_network() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("windows_network".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 6 windows_network tools  = 244
        assert_eq!(registry.len(), 323);
        assert!(registry.get("ssh_win_net_adapters").is_none());
        assert!(registry.get("ssh_win_net_ip").is_none());
        assert!(registry.get("ssh_win_net_routes").is_none());
        assert!(registry.get("ssh_win_net_connections").is_none());
        assert!(registry.get("ssh_win_net_ping").is_none());
        assert!(registry.get("ssh_win_net_dns").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_filtered_registry_disable_windows_process() {
        let mut groups = std::collections::HashMap::new();
        groups.insert("windows_process".to_string(), false);
        let config = ToolGroupsConfig { groups };

        let registry = create_filtered_registry(&config);
        // 281 total minus 5 windows_process tools  = 276
        assert_eq!(registry.len(), 324);
        assert!(registry.get("ssh_win_process_list").is_none());
        assert!(registry.get("ssh_win_process_info").is_none());
        assert!(registry.get("ssh_win_process_kill").is_none());
        assert!(registry.get("ssh_win_process_top").is_none());
        assert!(registry.get("ssh_win_process_by_name").is_none());
        assert!(registry.get("ssh_exec").is_some());
    }

    #[test]
    fn test_all_tools_have_annotations_with_title() {
        let registry = create_default_registry();
        for tool in registry.list_tools() {
            let ann = tool_annotations(&tool.name);
            assert!(
                ann.title.is_some(),
                "Tool '{}' missing annotation title",
                tool.name
            );
        }
    }

    #[test]
    fn test_list_tools_includes_annotations() {
        let registry = create_default_registry();
        let tools = registry.list_tools();
        // All tools should have annotations since all have titles
        for tool in &tools {
            assert!(
                tool.annotations.is_some(),
                "Tool '{}' missing annotations in list_tools()",
                tool.name
            );
        }
    }

    #[test]
    fn test_read_only_tools_annotations() {
        let read_only = [
            "ssh_status",
            "ssh_health",
            "ssh_history",
            "ssh_output_fetch",
            "ssh_metrics",
            "ssh_tail",
            "ssh_ls",
            "ssh_docker_ps",
            "ssh_docker_logs",
            "ssh_docker_inspect",
            "ssh_docker_images",
            "ssh_docker_stats",
            "ssh_k8s_get",
            "ssh_k8s_logs",
            "ssh_k8s_describe",
            "ssh_k8s_top",
            "ssh_helm_list",
            "ssh_helm_status",
            "ssh_helm_history",
            "ssh_service_status",
            "ssh_service_list",
            "ssh_service_logs",
            "ssh_net_connections",
            "ssh_net_ping",
            "ssh_process_list",
            "ssh_process_top",
            "ssh_pkg_list",
            "ssh_firewall_status",
            "ssh_cron_list",
            "ssh_cert_check",
            "ssh_nginx_status",
            "ssh_redis_info",
            "ssh_terraform_state",
            "ssh_vault_status",
            "ssh_config_get",
            "ssh_session_list",
            "ssh_tunnel_list",
            "ssh_backup_list",
        ];
        for name in &read_only {
            let ann = tool_annotations(name);
            assert_eq!(ann.read_only_hint, Some(true), "{name} should be read-only");
            assert_eq!(
                ann.destructive_hint,
                Some(false),
                "{name} should not be destructive"
            );
        }
    }

    #[test]
    fn test_destructive_tools_annotations() {
        let destructive = [
            "ssh_k8s_delete",
            "ssh_helm_uninstall",
            "ssh_process_kill",
            "ssh_cron_remove",
            "ssh_session_close",
            "ssh_tunnel_close",
            "ssh_firewall_deny",
            "ssh_service_stop",
        ];
        for name in &destructive {
            let ann = tool_annotations(name);
            assert_eq!(
                ann.destructive_hint,
                Some(true),
                "{name} should be destructive"
            );
            assert_eq!(
                ann.read_only_hint,
                Some(false),
                "{name} should not be read-only"
            );
        }
    }

    #[test]
    fn test_idempotent_tools_annotations() {
        let idempotent = [
            "ssh_k8s_apply",
            "ssh_service_restart",
            "ssh_terraform_init",
            "ssh_nginx_reload",
        ];
        for name in &idempotent {
            let ann = tool_annotations(name);
            assert_eq!(
                ann.idempotent_hint,
                Some(true),
                "{name} should be idempotent"
            );
        }
    }

    #[test]
    fn test_mutating_tools_annotations() {
        let mutating = [
            "ssh_exec",
            "ssh_exec_multi",
            "ssh_docker_exec",
            "ssh_git_pull",
            "ssh_helm_install",
            "ssh_terraform_apply",
            "ssh_upload",
            "ssh_db_query",
        ];
        for name in &mutating {
            let ann = tool_annotations(name);
            assert_eq!(
                ann.read_only_hint,
                Some(false),
                "{name} should not be read-only"
            );
            assert_eq!(
                ann.destructive_hint,
                Some(false),
                "{name} should not be destructive"
            );
        }
    }

    #[test]
    fn test_unknown_tool_returns_empty_annotations() {
        let ann = tool_annotations("nonexistent_tool");
        assert!(ann.is_empty());
    }

    #[test]
    fn test_no_duplicate_tool_names() {
        let registry = create_default_registry();
        let tools = registry.list_tools();
        let mut seen = std::collections::HashSet::new();
        for tool in &tools {
            assert!(
                seen.insert(&tool.name),
                "Duplicate tool name: {}",
                tool.name
            );
        }
    }

    #[test]
    fn test_all_tools_have_valid_schema_json() {
        let registry = create_default_registry();
        for tool in registry.list_tools() {
            assert!(
                tool.input_schema.is_object(),
                "Tool '{}' has invalid input_schema (not a JSON object)",
                tool.name
            );
            assert_eq!(
                tool.input_schema["type"], "object",
                "Tool '{}' schema type must be 'object'",
                tool.name
            );
            assert!(
                tool.input_schema.get("properties").is_some(),
                "Tool '{}' schema missing 'properties'",
                tool.name
            );
        }
    }

    #[test]
    fn test_tool_groups_cover_all_tools() {
        let valid_groups = [
            "core",
            "file_transfer",
            "sessions",
            "monitoring",
            "tunnels",
            "directory",
            "database",
            "backup",
            "docker",
            "esxi",
            "git",
            "kubernetes",
            "ansible",
            "systemd",
            "network",
            "process",
            "package",
            "firewall",
            "cron",
            "certificates",
            "nginx",
            "redis",
            "terraform",
            "vault",
            "config",
            "windows_services",
            "windows_events",
            "active_directory",
            "scheduled_tasks",
            "windows_firewall",
            "iis",
            "windows_updates",
            "windows_perf",
            "hyperv",
            "windows_registry",
            "windows_features",
            "windows_network",
            "windows_process",
            "file_ops",
            "user_management",
            "storage",
            "journald",
            "systemd_timers",
            "security_modules",
            "network_equipment",
            "podman",
            "ldap",
            "postgresql",
            "mysql",
            "apache",
            "letsencrypt",
            "mongodb",
            "recording",
            "diagnostics",
            "runbooks",
            "orchestration",
            "drift",
            "security_scan",
            "cron_analysis",
            "performance",
            "container_logs",
            "network_security",
            "compliance",
            "cloud",
            "inventory",
            "multicloud",
            "alerting",
            "capacity",
            "incident",
            "log_aggregation",
            "key_management",
            "chatops",
        ];
        let registry = create_default_registry();
        for tool in registry.list_tools() {
            let group = tool_group(&tool.name);
            assert!(
                valid_groups.contains(&group),
                "Tool '{}' has unknown group '{group}'",
                tool.name
            );
        }
    }

    #[test]
    fn test_annotation_consistency_read_only_not_destructive() {
        let registry = create_default_registry();
        for tool in registry.list_tools() {
            let ann = tool_annotations(&tool.name);
            if ann.read_only_hint == Some(true) {
                assert_ne!(
                    ann.destructive_hint,
                    Some(true),
                    "Tool '{}' is read-only but marked destructive",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn test_annotation_consistency_destructive_not_read_only() {
        let registry = create_default_registry();
        for tool in registry.list_tools() {
            let ann = tool_annotations(&tool.name);
            if ann.destructive_hint == Some(true) {
                assert_ne!(
                    ann.read_only_hint,
                    Some(true),
                    "Tool '{}' is destructive but marked read-only",
                    tool.name
                );
            }
        }
    }
}
