# MCP Tool Entry-Point Map (2026-05-09)

**Project:** mcp-ssh-bridge — MCP JSON-RPC server
**Scope:** `src/mcp/tool_handlers/` (358 handlers, excluding `mod.rs`)
**Method:** programmatic classification (skill `entry-point-analyzer:entry-point-analyzer` is smart-contract-only and does not apply; manual heuristic per file-name pattern + body grep)
**Risk score** = writes_files*4 + executes_shell_raw*4 + handles_creds*3 + destructive*3 + executes_shell_builtin*2 + reads_files*1

## Summary

| Bucket | Count |
|---|---|
| P0 (>=10) | 97 |
| P1 (7-9) | 21 |
| P2 (4-6) | 222 |
| P3 (1-3) | 18 |
| P4 (0) | 0 |
| **Total** | **358** |

## P0 (>=10) — 97 handlers

| Tool | Score | Writes | RawExec | BuiltinExec | Creds | Destructive | Reads | Permissive-only | Handler path |
|---|---|---|---|---|---|---|---|---|---|
| `ssh_canary_exec` | 14 | ✓ | ✓ |  | ✓ | ✓ |  | ✓ | `src/mcp/tool_handlers/ssh_canary_exec.rs` |
| `ssh_pty_exec` | 14 | ✓ | ✓ |  | ✓ | ✓ |  | ✓ | `src/mcp/tool_handlers/ssh_pty_exec.rs` |
| `ssh_pty_interact` | 14 | ✓ | ✓ |  | ✓ | ✓ |  | ✓ | `src/mcp/tool_handlers/ssh_pty_interact.rs` |
| `ssh_at_jobs` | 13 | ✓ |  | ✓ | ✓ | ✓ | ✓ |  | `src/mcp/tool_handlers/ssh_at_jobs.rs` |
| `ssh_letsencrypt_status` | 13 | ✓ |  | ✓ | ✓ | ✓ | ✓ |  | `src/mcp/tool_handlers/ssh_letsencrypt_status.rs` |
| `ssh_alert_set` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_alert_set.rs` |
| `ssh_ansible_adhoc` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_ansible_adhoc.rs` |
| `ssh_ansible_playbook` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_ansible_playbook.rs` |
| `ssh_apparmor_profiles` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_apparmor_profiles.rs` |
| `ssh_awx_job_cancel` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_awx_job_cancel.rs` |
| `ssh_awx_job_launch` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_awx_job_launch.rs` |
| `ssh_awx_project_sync` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_awx_project_sync.rs` |
| `ssh_backup_snapshot` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_backup_snapshot.rs` |
| `ssh_compliance_check` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_compliance_check.rs` |
| `ssh_cron_add` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_cron_add.rs` |
| `ssh_cron_remove` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_cron_remove.rs` |
| `ssh_docker_compose` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_docker_compose.rs` |
| `ssh_esxi_snapshot` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_esxi_snapshot.rs` |
| `ssh_file_chmod` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_file_chmod.rs` |
| `ssh_file_chown` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_file_chown.rs` |
| `ssh_file_patch` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_file_patch.rs` |
| `ssh_file_template` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_file_template.rs` |
| `ssh_firewall_allow` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_firewall_allow.rs` |
| `ssh_firewall_deny` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_firewall_deny.rs` |
| `ssh_group_add` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_group_add.rs` |
| `ssh_group_delete` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_group_delete.rs` |
| `ssh_helm_install` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_helm_install.rs` |
| `ssh_helm_rollback` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_helm_rollback.rs` |
| `ssh_helm_uninstall` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_helm_uninstall.rs` |
| `ssh_helm_upgrade` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_helm_upgrade.rs` |
| `ssh_hyperv_snapshot_create` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_hyperv_snapshot_create.rs` |
| `ssh_hyperv_vm_start` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_hyperv_vm_start.rs` |
| `ssh_hyperv_vm_stop` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_hyperv_vm_stop.rs` |
| `ssh_iis_restart` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_iis_restart.rs` |
| `ssh_iis_start` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_iis_start.rs` |
| `ssh_iis_stop` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_iis_stop.rs` |
| `ssh_inventory_sync` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_inventory_sync.rs` |
| `ssh_k8s_apply` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_k8s_apply.rs` |
| `ssh_k8s_delete` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_k8s_delete.rs` |
| `ssh_k8s_rollout` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_k8s_rollout.rs` |
| `ssh_k8s_scale` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_k8s_scale.rs` |
| `ssh_key_distribute` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_key_distribute.rs` |
| `ssh_key_generate` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_key_generate.rs` |
| `ssh_ldap_add` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_ldap_add.rs` |
| `ssh_ldap_modify` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_ldap_modify.rs` |
| `ssh_net_equip_config` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_net_equip_config.rs` |
| `ssh_net_equip_save` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_net_equip_save.rs` |
| `ssh_pkg_install` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_pkg_install.rs` |
| `ssh_pkg_remove` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_pkg_remove.rs` |
| `ssh_pkg_update` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_pkg_update.rs` |
| `ssh_podman_compose` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_podman_compose.rs` |
| `ssh_process_kill` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_process_kill.rs` |
| `ssh_pty_resize` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_pty_resize.rs` |
| `ssh_reg_delete` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_reg_delete.rs` |
| `ssh_reg_export` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_reg_export.rs` |
| `ssh_reg_set` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_reg_set.rs` |
| `ssh_schtask_disable` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_schtask_disable.rs` |
| `ssh_schtask_enable` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_schtask_enable.rs` |
| `ssh_schtask_run` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_schtask_run.rs` |
| `ssh_selinux_booleans` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_selinux_booleans.rs` |
| `ssh_service_daemon_reload` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_service_daemon_reload.rs` |
| `ssh_service_disable` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_service_disable.rs` |
| `ssh_service_enable` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_service_enable.rs` |
| `ssh_service_restart` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_service_restart.rs` |
| `ssh_service_start` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_service_start.rs` |
| `ssh_service_stop` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_service_stop.rs` |
| `ssh_storage_fdisk` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_storage_fdisk.rs` |
| `ssh_storage_fstab` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_storage_fstab.rs` |
| `ssh_storage_lvm` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_storage_lvm.rs` |
| `ssh_storage_mount` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_storage_mount.rs` |
| `ssh_storage_umount` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_storage_umount.rs` |
| `ssh_template_apply` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_template_apply.rs` |
| `ssh_terraform_apply` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_terraform_apply.rs` |
| `ssh_timer_disable` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_timer_disable.rs` |
| `ssh_timer_enable` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_timer_enable.rs` |
| `ssh_timer_trigger` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_timer_trigger.rs` |
| `ssh_user_add` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_user_add.rs` |
| `ssh_user_delete` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_user_delete.rs` |
| `ssh_user_modify` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_user_modify.rs` |
| `ssh_vault_write` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_vault_write.rs` |
| `ssh_win_feature_install` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_feature_install.rs` |
| `ssh_win_feature_remove` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_feature_remove.rs` |
| `ssh_win_firewall_allow` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_firewall_allow.rs` |
| `ssh_win_firewall_deny` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_firewall_deny.rs` |
| `ssh_win_firewall_remove` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_firewall_remove.rs` |
| `ssh_win_process_kill` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_process_kill.rs` |
| `ssh_win_service_disable` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_service_disable.rs` |
| `ssh_win_service_enable` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_service_enable.rs` |
| `ssh_win_service_restart` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_service_restart.rs` |
| `ssh_win_service_start` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_service_start.rs` |
| `ssh_win_service_stop` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_service_stop.rs` |
| `ssh_win_update_install` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_update_install.rs` |
| `ssh_win_update_reboot` | 12 | ✓ |  | ✓ | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_win_update_reboot.rs` |
| `ssh_backup_create` | 10 | ✓ |  |  | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_backup_create.rs` |
| `ssh_backup_restore` | 10 | ✓ |  |  | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_backup_restore.rs` |
| `ssh_db_dump` | 10 | ✓ |  |  | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_db_dump.rs` |
| `ssh_db_restore` | 10 | ✓ |  |  | ✓ | ✓ |  |  | `src/mcp/tool_handlers/ssh_db_restore.rs` |

## P1 (7-9) — 21 handlers

| Tool | Score | Writes | RawExec | BuiltinExec | Creds | Destructive | Reads | Permissive-only | Handler path |
|---|---|---|---|---|---|---|---|---|---|
| `ssh_esxi_vm_power` | 9 | ✓ |  | ✓ |  | ✓ |  |  | `src/mcp/tool_handlers/ssh_esxi_vm_power.rs` |
| `ssh_file_write` | 9 | ✓ |  | ✓ |  | ✓ |  |  | `src/mcp/tool_handlers/ssh_file_write.rs` |
| `ssh_config_set` | 8 | ✓ |  |  |  | ✓ | ✓ |  | `src/mcp/tool_handlers/ssh_config_set.rs` |
| `ssh_session_close` | 8 | ✓ |  |  |  | ✓ | ✓ |  | `src/mcp/tool_handlers/ssh_session_close.rs` |
| `ssh_session_create` | 8 | ✓ |  |  |  | ✓ | ✓ |  | `src/mcp/tool_handlers/ssh_session_create.rs` |
| `ssh_session_exec` | 8 |  | ✓ |  | ✓ |  | ✓ | ✓ | `src/mcp/tool_handlers/ssh_session_exec.rs` |
| `ssh_docker_exec` | 7 |  | ✓ |  | ✓ |  |  | ✓ | `src/mcp/tool_handlers/ssh_docker_exec.rs` |
| `ssh_download` | 7 | ✓ |  |  |  | ✓ |  |  | `src/mcp/tool_handlers/ssh_download.rs` |
| `ssh_exec` | 7 |  | ✓ |  | ✓ |  |  | ✓ | `src/mcp/tool_handlers/ssh_exec.rs` |
| `ssh_exec_multi` | 7 |  | ✓ |  | ✓ |  |  | ✓ | `src/mcp/tool_handlers/ssh_exec_multi.rs` |
| `ssh_files_write` | 7 | ✓ |  |  |  | ✓ |  |  | `src/mcp/tool_handlers/ssh_files_write.rs` |
| `ssh_k8s_exec` | 7 |  | ✓ |  | ✓ |  |  | ✓ | `src/mcp/tool_handlers/ssh_k8s_exec.rs` |
| `ssh_podman_exec` | 7 |  | ✓ |  | ✓ |  |  | ✓ | `src/mcp/tool_handlers/ssh_podman_exec.rs` |
| `ssh_recording_start` | 7 | ✓ |  |  |  | ✓ |  |  | `src/mcp/tool_handlers/ssh_recording_start.rs` |
| `ssh_recording_stop` | 7 | ✓ |  |  |  | ✓ |  |  | `src/mcp/tool_handlers/ssh_recording_stop.rs` |
| `ssh_rolling_exec` | 7 |  | ✓ |  | ✓ |  |  | ✓ | `src/mcp/tool_handlers/ssh_rolling_exec.rs` |
| `ssh_runbook_execute` | 7 | ✓ |  |  |  | ✓ |  |  | `src/mcp/tool_handlers/ssh_runbook_execute.rs` |
| `ssh_sync` | 7 | ✓ |  |  |  | ✓ |  |  | `src/mcp/tool_handlers/ssh_sync.rs` |
| `ssh_tunnel_close` | 7 | ✓ |  |  |  | ✓ |  |  | `src/mcp/tool_handlers/ssh_tunnel_close.rs` |
| `ssh_tunnel_create` | 7 | ✓ |  |  |  | ✓ |  |  | `src/mcp/tool_handlers/ssh_tunnel_create.rs` |
| `ssh_upload` | 7 | ✓ |  |  |  | ✓ |  |  | `src/mcp/tool_handlers/ssh_upload.rs` |

## P2 (4-6) — 222 handlers

| Tool | Score | Writes | RawExec | BuiltinExec | Creds | Destructive | Reads | Permissive-only | Handler path |
|---|---|---|---|---|---|---|---|---|---|
| `ssh_ad_computer_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ad_computer_list.rs` |
| `ssh_ad_domain_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ad_domain_info.rs` |
| `ssh_ad_group_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ad_group_list.rs` |
| `ssh_ad_group_members` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ad_group_members.rs` |
| `ssh_ad_user_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ad_user_info.rs` |
| `ssh_ad_user_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ad_user_list.rs` |
| `ssh_alert_check` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_alert_check.rs` |
| `ssh_alert_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_alert_list.rs` |
| `ssh_ansible_config` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ansible_config.rs` |
| `ssh_ansible_facts` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ansible_facts.rs` |
| `ssh_ansible_inventory` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ansible_inventory.rs` |
| `ssh_ansible_lint` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ansible_lint.rs` |
| `ssh_ansible_recap` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ansible_recap.rs` |
| `ssh_ansible_run_background` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ansible_run_background.rs` |
| `ssh_apache_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_apache_status.rs` |
| `ssh_apache_vhosts` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_apache_vhosts.rs` |
| `ssh_apparmor_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_apparmor_status.rs` |
| `ssh_aws_cli` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_aws_cli.rs` |
| `ssh_awx_inventories` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_awx_inventories.rs` |
| `ssh_awx_inventory_hosts` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_awx_inventory_hosts.rs` |
| `ssh_awx_job_events` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_awx_job_events.rs` |
| `ssh_awx_job_follow` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_awx_job_follow.rs` |
| `ssh_awx_job_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_awx_job_status.rs` |
| `ssh_awx_job_stdout` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_awx_job_stdout.rs` |
| `ssh_awx_job_summary` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_awx_job_summary.rs` |
| `ssh_awx_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_awx_status.rs` |
| `ssh_awx_template_detail` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_awx_template_detail.rs` |
| `ssh_awx_templates` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_awx_templates.rs` |
| `ssh_backup_schedule` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_backup_schedule.rs` |
| `ssh_backup_verify` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_backup_verify.rs` |
| `ssh_benchmark` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_benchmark.rs` |
| `ssh_capacity_collect` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_capacity_collect.rs` |
| `ssh_capacity_predict` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_capacity_predict.rs` |
| `ssh_capacity_trend` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_capacity_trend.rs` |
| `ssh_cert_check` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_cert_check.rs` |
| `ssh_cert_expiry` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_cert_expiry.rs` |
| `ssh_cert_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_cert_info.rs` |
| `ssh_cis_benchmark` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_cis_benchmark.rs` |
| `ssh_cloud_cost` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_cloud_cost.rs` |
| `ssh_cloud_metadata` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_cloud_metadata.rs` |
| `ssh_cloud_tags` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_cloud_tags.rs` |
| `ssh_compare_state` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_compare_state.rs` |
| `ssh_compliance_report` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_compliance_report.rs` |
| `ssh_compliance_score` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_compliance_score.rs` |
| `ssh_container_events` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_container_events.rs` |
| `ssh_container_health_history` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_container_health_history.rs` |
| `ssh_container_log_search` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_container_log_search.rs` |
| `ssh_container_log_stats` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_container_log_stats.rs` |
| `ssh_cron_analyze` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_cron_analyze.rs` |
| `ssh_cron_history` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_cron_history.rs` |
| `ssh_cron_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_cron_list.rs` |
| `ssh_diagnose` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_diagnose.rs` |
| `ssh_discover_hosts` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_discover_hosts.rs` |
| `ssh_disk_usage` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_disk_usage.rs` |
| `ssh_docker_images` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_docker_images.rs` |
| `ssh_docker_logs` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_docker_logs.rs` |
| `ssh_docker_network_inspect` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_docker_network_inspect.rs` |
| `ssh_docker_network_ls` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_docker_network_ls.rs` |
| `ssh_docker_ps` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_docker_ps.rs` |
| `ssh_docker_stats` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_docker_stats.rs` |
| `ssh_docker_volume_inspect` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_docker_volume_inspect.rs` |
| `ssh_docker_volume_ls` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_docker_volume_ls.rs` |
| `ssh_env_diff` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_env_diff.rs` |
| `ssh_env_drift` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_env_drift.rs` |
| `ssh_env_snapshot` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_env_snapshot.rs` |
| `ssh_fail2ban_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_fail2ban_status.rs` |
| `ssh_file_diff` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_file_diff.rs` |
| `ssh_file_read` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_file_read.rs` |
| `ssh_file_stat` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_file_stat.rs` |
| `ssh_find` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_find.rs` |
| `ssh_firewall_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_firewall_list.rs` |
| `ssh_firewall_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_firewall_status.rs` |
| `ssh_fleet_diff` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_fleet_diff.rs` |
| `ssh_git_checkout` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_git_checkout.rs` |
| `ssh_git_clone` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_git_clone.rs` |
| `ssh_git_diff` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_git_diff.rs` |
| `ssh_git_log` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_git_log.rs` |
| `ssh_git_pull` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_git_pull.rs` |
| `ssh_git_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_git_status.rs` |
| `ssh_group_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_group_list.rs` |
| `ssh_helm_history` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_helm_history.rs` |
| `ssh_helm_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_helm_list.rs` |
| `ssh_helm_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_helm_status.rs` |
| `ssh_host_tags` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_host_tags.rs` |
| `ssh_hyperv_host_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_hyperv_host_info.rs` |
| `ssh_hyperv_snapshot_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_hyperv_snapshot_list.rs` |
| `ssh_hyperv_switch_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_hyperv_switch_list.rs` |
| `ssh_hyperv_vm_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_hyperv_vm_info.rs` |
| `ssh_hyperv_vm_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_hyperv_vm_list.rs` |
| `ssh_iis_list_pools` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_iis_list_pools.rs` |
| `ssh_iis_list_sites` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_iis_list_sites.rs` |
| `ssh_iis_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_iis_status.rs` |
| `ssh_incident_correlate` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_incident_correlate.rs` |
| `ssh_incident_timeline` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_incident_timeline.rs` |
| `ssh_incident_triage` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_incident_triage.rs` |
| `ssh_io_trace` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_io_trace.rs` |
| `ssh_journal_boots` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_journal_boots.rs` |
| `ssh_journal_disk_usage` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_journal_disk_usage.rs` |
| `ssh_journal_follow` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_journal_follow.rs` |
| `ssh_journal_query` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_journal_query.rs` |
| `ssh_k8s_describe` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_k8s_describe.rs` |
| `ssh_k8s_get` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_k8s_get.rs` |
| `ssh_k8s_logs` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_k8s_logs.rs` |
| `ssh_k8s_top` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_k8s_top.rs` |
| `ssh_key_audit` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_key_audit.rs` |
| `ssh_latency_test` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_latency_test.rs` |
| `ssh_ldap_group_members` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ldap_group_members.rs` |
| `ssh_ldap_search` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ldap_search.rs` |
| `ssh_ldap_user_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ldap_user_info.rs` |
| `ssh_log_aggregate` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_log_aggregate.rs` |
| `ssh_log_search_multi` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_log_search_multi.rs` |
| `ssh_log_tail_multi` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_log_tail_multi.rs` |
| `ssh_metrics` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_metrics.rs` |
| `ssh_metrics_multi` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_metrics_multi.rs` |
| `ssh_mongodb_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_mongodb_status.rs` |
| `ssh_multicloud_compare` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_multicloud_compare.rs` |
| `ssh_multicloud_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_multicloud_list.rs` |
| `ssh_multicloud_sync` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_multicloud_sync.rs` |
| `ssh_mysql_query` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_mysql_query.rs` |
| `ssh_mysql_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_mysql_status.rs` |
| `ssh_net_connections` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_connections.rs` |
| `ssh_net_dns` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_dns.rs` |
| `ssh_net_equip_show_arp` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_equip_show_arp.rs` |
| `ssh_net_equip_show_interfaces` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_equip_show_interfaces.rs` |
| `ssh_net_equip_show_routes` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_equip_show_routes.rs` |
| `ssh_net_equip_show_run` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_equip_show_run.rs` |
| `ssh_net_equip_show_version` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_equip_show_version.rs` |
| `ssh_net_equip_show_vlans` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_equip_show_vlans.rs` |
| `ssh_net_interfaces` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_interfaces.rs` |
| `ssh_net_ping` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_ping.rs` |
| `ssh_net_routes` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_routes.rs` |
| `ssh_net_traceroute` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_net_traceroute.rs` |
| `ssh_network_capture` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_network_capture.rs` |
| `ssh_nginx_list_sites` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_nginx_list_sites.rs` |
| `ssh_nginx_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_nginx_status.rs` |
| `ssh_nginx_test` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_nginx_test.rs` |
| `ssh_notify` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_notify.rs` |
| `ssh_perf_trace` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_perf_trace.rs` |
| `ssh_pkg_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_pkg_list.rs` |
| `ssh_pkg_search` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_pkg_search.rs` |
| `ssh_podman_images` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_podman_images.rs` |
| `ssh_podman_inspect` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_podman_inspect.rs` |
| `ssh_podman_logs` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_podman_logs.rs` |
| `ssh_podman_ps` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_podman_ps.rs` |
| `ssh_port_scan` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_port_scan.rs` |
| `ssh_postgresql_query` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_postgresql_query.rs` |
| `ssh_postgresql_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_postgresql_status.rs` |
| `ssh_process_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_process_list.rs` |
| `ssh_process_top` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_process_top.rs` |
| `ssh_redis_cli` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_redis_cli.rs` |
| `ssh_redis_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_redis_info.rs` |
| `ssh_redis_keys` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_redis_keys.rs` |
| `ssh_reg_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_reg_list.rs` |
| `ssh_reg_query` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_reg_query.rs` |
| `ssh_sbom_generate` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_sbom_generate.rs` |
| `ssh_schtask_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_schtask_info.rs` |
| `ssh_schtask_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_schtask_list.rs` |
| `ssh_security_audit` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_security_audit.rs` |
| `ssh_selinux_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_selinux_status.rs` |
| `ssh_service_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_service_list.rs` |
| `ssh_service_logs` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_service_logs.rs` |
| `ssh_service_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_service_status.rs` |
| `ssh_ssl_audit` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ssl_audit.rs` |
| `ssh_stig_check` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_stig_check.rs` |
| `ssh_storage_df` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_storage_df.rs` |
| `ssh_storage_lsblk` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_storage_lsblk.rs` |
| `ssh_template_diff` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_template_diff.rs` |
| `ssh_template_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_template_list.rs` |
| `ssh_template_show` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_template_show.rs` |
| `ssh_template_validate` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_template_validate.rs` |
| `ssh_terraform_init` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_terraform_init.rs` |
| `ssh_terraform_output` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_terraform_output.rs` |
| `ssh_terraform_plan` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_terraform_plan.rs` |
| `ssh_terraform_state` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_terraform_state.rs` |
| `ssh_timer_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_timer_info.rs` |
| `ssh_timer_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_timer_list.rs` |
| `ssh_user_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_user_info.rs` |
| `ssh_user_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_user_list.rs` |
| `ssh_vault_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_vault_list.rs` |
| `ssh_vault_read` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_vault_read.rs` |
| `ssh_vault_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_vault_status.rs` |
| `ssh_vuln_scan` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_vuln_scan.rs` |
| `ssh_webhook_send` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_webhook_send.rs` |
| `ssh_win_disk_usage` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_disk_usage.rs` |
| `ssh_win_event_export` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_event_export.rs` |
| `ssh_win_event_logs` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_event_logs.rs` |
| `ssh_win_event_query` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_event_query.rs` |
| `ssh_win_event_sources` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_event_sources.rs` |
| `ssh_win_event_tail` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_event_tail.rs` |
| `ssh_win_feature_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_feature_info.rs` |
| `ssh_win_feature_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_feature_list.rs` |
| `ssh_win_firewall_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_firewall_list.rs` |
| `ssh_win_firewall_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_firewall_status.rs` |
| `ssh_win_net_adapters` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_net_adapters.rs` |
| `ssh_win_net_connections` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_net_connections.rs` |
| `ssh_win_net_dns` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_net_dns.rs` |
| `ssh_win_net_ip` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_net_ip.rs` |
| `ssh_win_net_ping` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_net_ping.rs` |
| `ssh_win_net_routes` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_net_routes.rs` |
| `ssh_win_perf_cpu` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_perf_cpu.rs` |
| `ssh_win_perf_disk` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_perf_disk.rs` |
| `ssh_win_perf_memory` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_perf_memory.rs` |
| `ssh_win_perf_network` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_perf_network.rs` |
| `ssh_win_perf_overview` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_perf_overview.rs` |
| `ssh_win_process_by_name` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_process_by_name.rs` |
| `ssh_win_process_info` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_process_info.rs` |
| `ssh_win_process_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_process_list.rs` |
| `ssh_win_process_top` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_process_top.rs` |
| `ssh_win_service_config` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_service_config.rs` |
| `ssh_win_service_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_service_list.rs` |
| `ssh_win_service_status` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_service_status.rs` |
| `ssh_win_update_history` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_update_history.rs` |
| `ssh_win_update_list` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_update_list.rs` |
| `ssh_win_update_search` | 6 |  |  | ✓ | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_win_update_search.rs` |
| `ssh_nginx_reload` | 5 |  |  | ✓ | ✓ |  |  |  | `src/mcp/tool_handlers/ssh_nginx_reload.rs` |
| `utils` | 5 |  |  | ✓ | ✓ |  |  |  | `src/mcp/tool_handlers/utils.rs` |
| `ssh_ansible_events` | 4 |  |  |  | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_ansible_events.rs` |
| `ssh_backup_list` | 4 |  |  |  | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_backup_list.rs` |
| `ssh_db_query` | 4 |  |  |  | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_db_query.rs` |
| `ssh_health` | 4 |  |  |  | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_health.rs` |
| `ssh_runbook_list` | 4 |  |  |  | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_runbook_list.rs` |
| `ssh_status` | 4 |  |  |  | ✓ |  | ✓ |  | `src/mcp/tool_handlers/ssh_status.rs` |

## P3 (1-3) — 18 handlers

| Tool | Score | Writes | RawExec | BuiltinExec | Creds | Destructive | Reads | Permissive-only | Handler path |
|---|---|---|---|---|---|---|---|---|---|
| `ssh_docker_inspect` | 3 |  |  | ✓ |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_docker_inspect.rs` |
| `ssh_esxi_datastore_list` | 3 |  |  | ✓ |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_esxi_datastore_list.rs` |
| `ssh_esxi_host_info` | 3 |  |  | ✓ |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_esxi_host_info.rs` |
| `ssh_esxi_network_list` | 3 |  |  | ✓ |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_esxi_network_list.rs` |
| `ssh_esxi_vm_info` | 3 |  |  | ✓ |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_esxi_vm_info.rs` |
| `ssh_esxi_vm_list` | 3 |  |  | ✓ |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_esxi_vm_list.rs` |
| `ssh_git_branch` | 3 |  |  | ✓ |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_git_branch.rs` |
| `ssh_runbook_validate` | 3 |  |  | ✓ |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_runbook_validate.rs` |
| `ssh_tail` | 3 |  |  | ✓ |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_tail.rs` |
| `ssh_config_get` | 1 |  |  |  |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_config_get.rs` |
| `ssh_history` | 1 |  |  |  |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_history.rs` |
| `ssh_ls` | 1 |  |  |  |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_ls.rs` |
| `ssh_output_fetch` | 1 |  |  |  |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_output_fetch.rs` |
| `ssh_recording_list` | 1 |  |  |  |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_recording_list.rs` |
| `ssh_recording_replay` | 1 |  |  |  |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_recording_replay.rs` |
| `ssh_recording_verify` | 1 |  |  |  |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_recording_verify.rs` |
| `ssh_session_list` | 1 |  |  |  |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_session_list.rs` |
| `ssh_tunnel_list` | 1 |  |  |  |  |  | ✓ |  | `src/mcp/tool_handlers/ssh_tunnel_list.rs` |

