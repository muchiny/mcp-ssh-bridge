# MCP SSH Bridge

<div align="center">

[![CI](https://github.com/muchiny/mcp-ssh-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/muchiny/mcp-ssh-bridge/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/mcp-ssh-bridge?style=flat-square&logo=rust)](https://crates.io/crates/mcp-ssh-bridge)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2025--11--25-blueviolet?style=flat-square)](https://modelcontextprotocol.io)

**A Rust MCP server that lets Claude Code securely execute commands on remote servers via SSH.**
**250 tools across 47 groups — Linux, Windows, Docker, Kubernetes, Podman, LDAP, network equipment, and more.**

</div>

---

## What is this?

MCP SSH Bridge is a local server that sits between Claude Code and your remote servers. Claude Code talks to it via JSON-RPC over stdio, and it executes commands on your servers over SSH.

```
Claude Code  <--JSON-RPC-->  MCP SSH Bridge  <--SSH-->  Your Servers
```

Without it, Claude cannot reach your servers. With it, Claude can run commands, transfer files, read logs, check metrics, manage Docker containers, Kubernetes clusters, Podman, LDAP directories, network equipment, systemd services, and much more — all through 250 purpose-built tools with built-in security controls.

---

## Install

Pick one method:

**From crates.io** (recommended):

```bash
cargo install mcp-ssh-bridge
```

**From source:**

```bash
git clone https://github.com/muchiny/mcp-ssh-bridge
cd mcp-ssh-bridge
make release
```

**Prebuilt binaries:** Download from [GitHub Releases](https://github.com/muchiny/mcp-ssh-bridge/releases/latest) (Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64).

**Docker:**

```bash
docker pull ghcr.io/muchiny/mcp-ssh-bridge:latest
```

---

## Configure

### 1. Create the config file

```bash
mkdir -p ~/.config/mcp-ssh-bridge
cp config/config.example.yaml ~/.config/mcp-ssh-bridge/config.yaml
```

### 2. Add your SSH hosts

Edit `~/.config/mcp-ssh-bridge/config.yaml`:

```yaml
hosts:
  # Each key is a host alias — this is what you pass to tools as the "host" parameter
  prod-server:
    hostname: 192.168.1.100
    port: 22
    user: admin
    auth:
      type: key
      path: ~/.ssh/id_ed25519
    description: "Production server"

  dev-server:
    hostname: 10.0.0.5
    port: 22
    user: deploy
    auth:
      type: agent  # Uses SSH_AUTH_SOCK
    description: "Development server"
```

**Authentication methods:**

| Method | Config | Notes |
|--------|--------|-------|
| SSH Key | `type: key` + `path: ~/.ssh/id_ed25519` | Recommended. Supports optional `passphrase`. |
| SSH Agent | `type: agent` | Uses `SSH_AUTH_SOCK`. Recommended. |
| Password | `type: password` + `password: "..."` | Avoid if possible. |

> **Tip:** Verify your SSH access first: `ssh user@hostname "echo OK"`

### 3. Configure security

The `security` section controls which commands Claude can run:

```yaml
security:
  # strict:     only whitelisted commands allowed (safest)
  # standard:   whitelist for ssh_exec, built-in tools only check blacklist (default)
  # permissive: only blacklist checked (most open)
  mode: standard

  whitelist:
    - "^docker\\s+(ps|logs|inspect).*"
    - "^kubectl\\s+(get|describe|logs).*"
    - "^(ls|cat|head|tail|grep|df|free)\\s*.*"
    - "^systemctl\\s+(status|list-units).*"
    - "^git\\s+(status|log|diff|branch).*"

  blacklist:
    - "rm\\s+(-[a-zA-Z]*r|--(recursive|force))"
    - "mkfs\\."
    - "dd\\s+if="
    - "chmod\\s+777"
    - "curl.*\\|.*sh"
    - "docker\\s+rm\\s+-f"
    - "kubectl\\s+delete"
```

**How it works:**

- **Blacklist** is always checked first — matched commands are always denied.
- In **strict** mode, the command must also match a whitelist pattern.
- In **standard** mode, the whitelist applies to `ssh_exec`/`ssh_session_exec` only; built-in tools (docker, k8s, etc.) only check the blacklist.
- In **permissive** mode, only the blacklist is checked.

### 4. Add to Claude Code

Add to your `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "ssh-bridge": {
      "command": "mcp-ssh-bridge"
    }
  }
}
```

If you installed from source, use the full path:

```json
{
  "mcpServers": {
    "ssh-bridge": {
      "command": "/path/to/mcp-ssh-bridge/target/release/mcp-ssh-bridge"
    }
  }
}
```

That's it. Restart Claude Code and it will discover all available tools automatically.

---

## SSH hosts from ~/.ssh/config

Hosts from your `~/.ssh/config` are auto-discovered by default — no extra configuration needed. They are merged with YAML-defined hosts (YAML takes precedence on conflicts).

To disable or exclude specific hosts:

```yaml
ssh_config:
  enabled: true          # Set to false to disable auto-discovery
  exclude:
    - personal-server    # Skip this host alias
```

---

## Advanced host configuration

### Jump hosts (bastion)

Route SSH connections through a bastion server:

```yaml
hosts:
  bastion:
    hostname: bastion.example.com
    user: admin
    auth:
      type: agent

  internal-db:
    hostname: 10.0.0.5       # Private IP, not reachable directly
    user: deploy
    proxy_jump: bastion       # Route through bastion
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

### SOCKS proxy

Route through a SOCKS4/5 proxy:

```yaml
hosts:
  behind-proxy:
    hostname: 10.0.0.50
    user: deploy
    socks_proxy:
      hostname: proxy.corp.com
      port: 1080
      version: socks5          # socks5 (default) or socks4
      # username: user         # Optional SOCKS5 auth
      # password: pass
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

> `proxy_jump` and `socks_proxy` are mutually exclusive on the same host.

### Windows servers

Add `os_type: windows` to enable 74 Windows-specific tools (PowerShell-based):

```yaml
hosts:
  windows-dc:
    hostname: 192.168.1.200
    user: Administrator
    os_type: windows
    shell: powershell     # Optional, default: cmd
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

### Sudo support

Configure per-host sudo password for commands that need elevation:

```yaml
hosts:
  prod-server:
    hostname: 192.168.1.100
    user: deploy
    sudo_password: "your-sudo-password"
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

Then use `"sudo": true` in tool calls like `ssh_exec`.

---

## Limits and timeouts

```yaml
limits:
  command_timeout_seconds: 60       # Max command duration
  connection_timeout_seconds: 10    # SSH connect timeout
  max_concurrent_commands: 5        # Parallel tool calls
  max_output_chars: 20000           # Output truncation threshold (0 = unlimited)
  rate_limit_per_second: 0          # Per-host rate limit (0 = disabled)
  retry_attempts: 3                 # Auto-retry on transient SSH errors
```

Truncated outputs include an `output_id` — use `ssh_output_fetch` to retrieve the full content page by page.

### Per-client output limits

Automatically adjust output size based on the MCP client:

```yaml
limits:
  client_overrides:
    - name_contains: claude
      max_output_chars: 80000
    - name_contains: cursor
      max_output_chars: 50000
```

---

## Output sanitization

Outputs are automatically scanned for secrets using 56 built-in patterns covering: passwords, API keys (AWS, OpenAI, GitHub, GitLab, Slack, etc.), certificates, database connection strings, Kubernetes tokens, and more. Detected secrets are replaced with `[REDACTED]`.

```yaml
security:
  sanitize:
    enabled: true                    # Default: true
    disable_builtin:
      # - "gitlab"                   # Disable a specific category
    custom_patterns:
      - pattern: "INTERNAL_[A-Z0-9]{32}"
        replacement: "[INTERNAL_REDACTED]"
```

---

## Audit logging

All commands are logged to a JSON-lines audit file:

```yaml
audit:
  enabled: true
  path: ~/.local/share/mcp-ssh-bridge/audit.log
  max_size_mb: 100
  retain_days: 30
```

Each entry records: timestamp, host, command, result (success/error), exit code, duration.

---

## Tool groups

The 250 tools are organized in 47 groups. All groups are enabled by default. Disable groups you don't need to reduce the MCP context sent to the LLM:

```yaml
tool_groups:
  groups:
    sessions: false          # Disable persistent shell sessions
    tunnels: false           # Disable SSH tunnels
    database: false          # Disable db query/dump/restore
    esxi: false              # Disable VMware ESXi tools
    windows_services: false  # Disable Windows service management
    # ... see config.example.yaml for all 47 groups
```

### Linux groups (34 groups, 176 tools)

| Group | Tools |
|-------|-------|
| `core` | ssh_exec, ssh_exec_multi, ssh_status, ssh_health, ssh_history, ssh_output_fetch |
| `config` | ssh_config_get, ssh_config_set |
| `file_transfer` | ssh_upload, ssh_download, ssh_sync |
| `sessions` | ssh_session_create, ssh_session_exec, ssh_session_list, ssh_session_close |
| `monitoring` | ssh_metrics, ssh_metrics_multi, ssh_tail, ssh_disk_usage |
| `tunnels` | ssh_tunnel_create, ssh_tunnel_list, ssh_tunnel_close |
| `directory` | ssh_ls, ssh_find |
| `database` | ssh_db_query, ssh_db_dump, ssh_db_restore |
| `backup` | ssh_backup_create, ssh_backup_list, ssh_backup_restore |
| `docker` | ssh_docker_ps, ssh_docker_logs, ssh_docker_inspect, ssh_docker_exec, ssh_docker_compose, ssh_docker_images, ssh_docker_stats, ssh_docker_volume_ls, ssh_docker_network_ls, ssh_docker_volume_inspect, ssh_docker_network_inspect |
| `esxi` | ssh_esxi_vm_list, ssh_esxi_vm_info, ssh_esxi_vm_power, ssh_esxi_snapshot, ssh_esxi_host_info, ssh_esxi_datastore_list, ssh_esxi_network_list |
| `git` | ssh_git_status, ssh_git_log, ssh_git_diff, ssh_git_pull, ssh_git_clone, ssh_git_branch, ssh_git_checkout |
| `kubernetes` | ssh_k8s_get, ssh_k8s_logs, ssh_k8s_describe, ssh_k8s_apply, ssh_k8s_delete, ssh_k8s_rollout, ssh_k8s_scale, ssh_k8s_exec, ssh_k8s_top, ssh_helm_list, ssh_helm_status, ssh_helm_upgrade, ssh_helm_install, ssh_helm_rollback, ssh_helm_history, ssh_helm_uninstall |
| `ansible` | ssh_ansible_playbook, ssh_ansible_inventory, ssh_ansible_adhoc |
| `systemd` | ssh_service_status, ssh_service_start, ssh_service_stop, ssh_service_restart, ssh_service_list, ssh_service_logs, ssh_service_enable, ssh_service_disable, ssh_service_daemon_reload |
| `network` | ssh_net_connections, ssh_net_interfaces, ssh_net_routes, ssh_net_ping, ssh_net_traceroute, ssh_net_dns |
| `process` | ssh_process_list, ssh_process_kill, ssh_process_top |
| `package` | ssh_pkg_list, ssh_pkg_search, ssh_pkg_install, ssh_pkg_update, ssh_pkg_remove |
| `firewall` | ssh_firewall_status, ssh_firewall_list, ssh_firewall_allow, ssh_firewall_deny |
| `cron` | ssh_cron_list, ssh_cron_add, ssh_cron_remove |
| `certificates` | ssh_cert_check, ssh_cert_info, ssh_cert_expiry |
| `nginx` | ssh_nginx_status, ssh_nginx_test, ssh_nginx_reload, ssh_nginx_list_sites |
| `redis` | ssh_redis_info, ssh_redis_cli, ssh_redis_keys |
| `terraform` | ssh_terraform_init, ssh_terraform_plan, ssh_terraform_apply, ssh_terraform_state, ssh_terraform_output |
| `vault` | ssh_vault_status, ssh_vault_read, ssh_vault_list, ssh_vault_write |
| `file_ops` | ssh_file_read, ssh_file_write, ssh_file_chmod, ssh_file_chown, ssh_file_stat |
| `user_management` | ssh_user_list, ssh_user_info, ssh_user_add, ssh_user_modify, ssh_user_delete, ssh_group_list, ssh_group_add, ssh_group_delete |
| `storage` | ssh_storage_lsblk, ssh_storage_df, ssh_storage_mount, ssh_storage_umount, ssh_storage_lvm, ssh_storage_fdisk, ssh_storage_fstab |
| `journald` | ssh_journal_query, ssh_journal_follow, ssh_journal_boots, ssh_journal_disk_usage |
| `systemd_timers` | ssh_timer_list, ssh_timer_info, ssh_timer_enable, ssh_timer_disable, ssh_timer_trigger |
| `security_modules` | ssh_selinux_status, ssh_selinux_booleans, ssh_apparmor_status, ssh_apparmor_profiles, ssh_security_audit |
| `network_equipment` | ssh_net_equip_show_run, ssh_net_equip_show_interfaces, ssh_net_equip_show_routes, ssh_net_equip_show_arp, ssh_net_equip_show_version, ssh_net_equip_show_vlans, ssh_net_equip_config, ssh_net_equip_save |
| `podman` | ssh_podman_ps, ssh_podman_logs, ssh_podman_inspect, ssh_podman_exec, ssh_podman_images, ssh_podman_compose |
| `ldap` | ssh_ldap_search, ssh_ldap_user_info, ssh_ldap_group_members, ssh_ldap_add, ssh_ldap_modify |

### Windows groups (13 groups, 74 tools)

| Group | Tools |
|-------|-------|
| `windows_services` | ssh_win_service_list, ssh_win_service_status, ssh_win_service_start, ssh_win_service_stop, ssh_win_service_restart, ssh_win_service_enable, ssh_win_service_disable, ssh_win_service_config |
| `windows_events` | ssh_win_event_query, ssh_win_event_logs, ssh_win_event_sources, ssh_win_event_tail, ssh_win_event_export |
| `active_directory` | ssh_ad_user_list, ssh_ad_user_info, ssh_ad_group_list, ssh_ad_group_members, ssh_ad_computer_list, ssh_ad_domain_info |
| `scheduled_tasks` | ssh_schtask_list, ssh_schtask_info, ssh_schtask_run, ssh_schtask_enable, ssh_schtask_disable |
| `windows_firewall` | ssh_win_firewall_status, ssh_win_firewall_list, ssh_win_firewall_allow, ssh_win_firewall_deny, ssh_win_firewall_remove |
| `iis` | ssh_iis_list_sites, ssh_iis_list_pools, ssh_iis_status, ssh_iis_start, ssh_iis_stop, ssh_iis_restart |
| `windows_updates` | ssh_win_update_list, ssh_win_update_search, ssh_win_update_install, ssh_win_update_history, ssh_win_update_reboot |
| `windows_perf` | ssh_win_perf_overview, ssh_win_perf_cpu, ssh_win_perf_memory, ssh_win_perf_disk, ssh_win_perf_network, ssh_win_disk_usage |
| `hyperv` | ssh_hyperv_vm_list, ssh_hyperv_vm_info, ssh_hyperv_vm_start, ssh_hyperv_vm_stop, ssh_hyperv_host_info, ssh_hyperv_switch_list, ssh_hyperv_snapshot_list, ssh_hyperv_snapshot_create |
| `windows_registry` | ssh_reg_query, ssh_reg_list, ssh_reg_set, ssh_reg_delete, ssh_reg_export |
| `windows_features` | ssh_win_feature_list, ssh_win_feature_info, ssh_win_feature_install, ssh_win_feature_remove |
| `windows_network` | ssh_win_net_ip, ssh_win_net_adapters, ssh_win_net_connections, ssh_win_net_routes, ssh_win_net_ping, ssh_win_net_dns |
| `windows_process` | ssh_win_process_list, ssh_win_process_top, ssh_win_process_info, ssh_win_process_by_name, ssh_win_process_kill |

---

## MCP prompts and resources

### Prompts

Pre-built conversation templates that guide Claude through common workflows:

| Prompt | Description | Required args |
|--------|-------------|---------------|
| `system-health` | Full system health check (CPU, memory, disk, services) | `host` |
| `deploy` | Step-by-step deployment workflow | `host`, `service` |
| `security-audit` | Security posture assessment | `host` |
| `troubleshoot` | Systematic troubleshooting guide | `host`, `symptom` |
| `docker-health` | Docker/container health assessment | `host` |
| `k8s-overview` | Kubernetes cluster state overview | `host` |
| `backup-verify` | Backup integrity verification | `host` |

### Resources

Direct data access via URI:

| URI pattern | Description |
|-------------|-------------|
| `metrics://{host}` | System metrics (CPU, memory, disk, network, load) as JSON |
| `file://{host}/{path}` | Remote file content |
| `log://{host}/{path}` | Last lines of a log file |

---

## CLI usage

The binary can also be used standalone (outside MCP mode):

```bash
mcp-ssh-bridge                              # MCP server mode (default)
mcp-ssh-bridge --config /path/config.yaml   # Custom config path
mcp-ssh-bridge status                       # Show configured hosts
mcp-ssh-bridge exec <host> "<command>"      # Execute a command directly
mcp-ssh-bridge history [--limit 20]         # Show command history
mcp-ssh-bridge upload <host> <local> <remote>
mcp-ssh-bridge download <host> <remote> <local>
```

---

## Troubleshooting

**"Unknown host: xxx"** — The host alias is not in your `config.yaml`. Run `ssh_status` to see configured hosts.

**"Command denied"** — The command doesn't match any whitelist pattern (strict/standard mode) or matches a blacklist pattern. Check your `security` config.

**"SSH connection failed"** — Verify: (1) the host is reachable (`ping hostname`), (2) SSH works manually (`ssh user@host`), (3) key permissions are correct (`chmod 600 ~/.ssh/id_*`).

**"Unknown host key"** — The host key is not in `~/.ssh/known_hosts`. Add it: `ssh-keyscan hostname >> ~/.ssh/known_hosts`

**Host key verification modes:**

| Mode | Behavior |
|------|----------|
| `Strict` (default) | Rejects unknown and changed host keys |
| `AcceptNew` | Accepts new keys, rejects changed keys |
| `Off` | Accepts all keys (testing only) |

Set per-host in config: `host_key_verification: AcceptNew`

---

## Development

```bash
make build              # Debug build
make release            # Optimized release with LTO
make test               # Run tests (uses nextest if available)
make lint               # Clippy with strict warnings
make ci                 # Quick CI (fmt-check, lint, test, audit, typos)
make ci-full            # Full CI (ci + hack + geiger)
```

Rust edition 2024, MSRV 1.93+. `#![forbid(unsafe_code)]`.

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## License

[MIT](LICENSE)
