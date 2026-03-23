# CLAUDE.md

## Project Overview

MCP SSH Bridge is a Rust MCP server that enables Claude Code to securely execute commands on air-gapped environments via SSH. JSON-RPC over stdio, strict security controls. **337 tools** across **74 groups** (59 Linux, 13 Windows, 2 cross-platform).

## Build Commands

```bash
make build              # Debug build
make release            # Optimized release build with LTO
make test               # Run tests (uses nextest if available)
make lint               # Run clippy with strict warnings
make ci                 # Quick CI (fmt-check, lint, test, audit, typos)
make ci-full            # Full CI (ci + hack + geiger)
make release-pipeline   # Full release (ci-full + release-all + docker-scan)
make dxt                # Build DXT package (Claude Desktop extension)
make deps-check         # Check outdated/unused deps
make help               # Show all available targets
```

## Architecture Hexagonale (Ports & Adapters)

```
┌─────────────────────────────────────────────────────────────┐
│                    ADAPTERS (Externe)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ MCP Adapter │  │ SSH Adapter │  │ Config YAML Adapter │  │
│  │ (JSON-RPC)  │  │  (russh)    │  │  (serde-saphyr)    │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
└─────────┼────────────────┼────────────────────┼─────────────┘
          │                │                    │
          ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                      PORTS (Traits)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ToolHandler  │  │ SshExecutor │  │  ConfigProvider     │  │
│  │   trait     │  │   trait     │  │      trait          │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
└─────────┼────────────────┼────────────────────┼─────────────┘
          │                │                    │
          ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                    DOMAIN (Core Logic)                       │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    Use Cases                         │    │
│  │  ExecuteCommand │ ValidateCommand │ SanitizeOutput  │    │
│  │  Diagnostics │ Runbooks │ Orchestration │ Drift     │    │
│  └─────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    Entities                          │    │
│  │   Command │ CommandResult │ SecurityPolicy │ Host    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
src/
├── main.rs, lib.rs, error.rs    # Entry point, exports, errors
├── cli/                          # CLI (feature-gated: clap)
├── config/                       # YAML config loading
├── domain/                       # Pure business logic (use cases, builders)
│   ├── runbook.rs                # 🆕 Runbook engine (YAML workflows)
│   └── use_cases/                # Command builders (65 modules)
│       ├── diagnostics.rs        # Intelligent diagnostics
│       ├── orchestration.rs      # Multi-host orchestration
│       ├── drift.rs              # Environment drift detection
│       ├── file_advanced.rs      # File diff/patch/template
│       ├── sbom.rs               # SBOM & vulnerability scanning
│       ├── performance.rs        # Perf profiling/flamegraph
│       ├── container_logs.rs     # Container log analysis
│       ├── cron_analysis.rs      # Cron conflict/timeline
│       ├── network_security.rs   # Port scan, firewall audit, SSL
│       ├── compliance.rs         # CIS/STIG/PCI/HIPAA/SOC2/GDPR/NIST/ISO
│       ├── cloud.rs              # AWS CLI, cloud metadata/tags/cost
│       ├── inventory.rs          # Host discovery, CMDB sync
│       ├── multicloud.rs         # Multi-cloud resources
│       ├── alerting.rs           # Alert status/silence/history
│       ├── capacity.rs           # Capacity forecast/report
│       ├── incident.rs           # Incident timeline/collect
│       ├── log_aggregation.rs    # Cross-host log correlation
│       ├── key_management.rs     # SSH key rotation/distribution
│       ├── chatops.rs            # Webhook/Slack notifications
│       ├── templates.rs          # Config template management
│       └── pty.rs                # Interactive PTY sessions
├── ports/                        # Traits (SshExecutor, ToolHandler, ConfigProvider)
├── mcp/                          # MCP protocol adapter + tool_handlers/
├── ssh/                          # SSH client adapter (russh)
└── security/                     # Validation, sanitization, rate limiting
    ├── entropy.rs                # 🆕 Shannon entropy-based secret detection
    └── recording.rs              # 🆕 Session recording with hash-chain audit
config/
├── config.example.yaml           # Configuration reference
└── runbooks/                     # 🆕 Built-in runbook YAML definitions
.well-known/mcp/server-card.json  # 🆕 MCP ecosystem discovery
dxt/                              # 🆕 DXT packaging (Claude Desktop extension)
```

## Tool Groups Reference (74 groups, 337 tools)

Use this table to find the right tool for a task. Each tool is prefixed `ssh_`.

### Core Infrastructure (Linux)

| Group | Tools | Use when… |
|-------|-------|-----------|
| `core` | `exec`, `exec_multi`, `status`, `health`, `history`, `output_fetch` | Running arbitrary commands, system info |
| `file_transfer` | `upload`, `download`, `sync` | Moving files between hosts |
| `file_ops` | `file_read`, `file_write`, `file_chmod`, `file_chown`, `file_stat`, `file_diff`, `file_patch`, `file_template` | File reading/writing/manipulation |
| `sessions` | `session_create`, `session_exec`, `session_close`, `session_list` | Persistent tmux sessions |
| `directory` | `ls`, `find` | Directory listing & file search |
| `process` | `process_list`, `process_kill`, `process_top` | Process management |
| `monitoring` | `metrics`, `metrics_multi`, `tail`, `disk_usage` | System monitoring & metrics |
| `network` | `net_connections`, `net_interfaces`, `net_routes`, `net_ping`, `net_traceroute`, `net_dns` | Network diagnostics |
| `systemd` | `service_status`, `service_start`, `service_stop`, `service_restart`, `service_enable`, `service_disable`, `service_logs`, `service_list`, `service_daemon_reload` | Systemd service management |
| `systemd_timers` | `timer_list`, `timer_info`, `timer_enable`, `timer_disable`, `timer_trigger` | Systemd timer management |
| `firewall` | `firewall_status`, `firewall_list`, `firewall_allow`, `firewall_deny` | iptables/ufw firewall rules |
| `package` | `pkg_list`, `pkg_install`, `pkg_remove`, `pkg_update`, `pkg_search` | Package management (apt/yum/dnf) |
| `cron` | `cron_list`, `cron_add`, `cron_remove` | Crontab management |
| `user_management` | `user_list`, `user_info`, `user_add`, `user_modify`, `user_delete`, `group_list`, `group_add`, `group_delete` | User & group management |
| `storage` | `storage_lsblk`, `storage_df`, `storage_mount`, `storage_umount`, `storage_lvm`, `storage_fdisk`, `storage_fstab` | Storage/LVM/mounts |
| `journald` | `journal_query`, `journal_follow`, `journal_boots`, `journal_disk_usage` | Journald log queries |
| `security_modules` | `selinux_status`, `selinux_booleans`, `apparmor_status`, `apparmor_profiles`, `security_audit` | SELinux, AppArmor, auditd |
| `backup` | `backup_create`, `backup_list`, `backup_restore`, `backup_snapshot`, `backup_verify`, `backup_schedule` | Backup management |
| `network_equipment` | `net_equip_show_run`, `net_equip_show_interfaces`, `net_equip_show_routes`, `net_equip_show_arp`, `net_equip_show_version`, `net_equip_show_vlans`, `net_equip_config`, `net_equip_save` | Network switch/router management |
| `ldap` | `ldap_search`, `ldap_user_info`, `ldap_group_members`, `ldap_add`, `ldap_modify` | LDAP directory operations |
| `tunnels` | `tunnel_create`, `tunnel_list`, `tunnel_close` | SSH tunnel management |

### Containers & Orchestration

| Group | Tools | Use when… |
|-------|-------|-----------|
| `docker` | `docker_ps`, `docker_logs`, `docker_inspect`, `docker_exec`, `docker_compose`, `docker_images`, `docker_stats`, `docker_volume_ls`, `docker_network_ls`, `docker_volume_inspect`, `docker_network_inspect` | Docker container management |
| `podman` | `podman_ps`, `podman_logs`, `podman_inspect`, `podman_exec`, `podman_images`, `podman_compose` | Podman container management |
| `kubernetes` | `k8s_get`, `k8s_logs`, `k8s_describe`, `k8s_apply`, `k8s_delete`, `k8s_rollout`, `k8s_scale`, `k8s_exec`, `k8s_top`, `helm_list`, `helm_status`, `helm_upgrade`, `helm_install`, `helm_rollback`, `helm_history`, `helm_uninstall` | Kubernetes & Helm management |
| `esxi` | `esxi_vm_list`, `esxi_vm_info`, `esxi_vm_power`, `esxi_snapshot`, `esxi_host_info`, `esxi_datastore_list`, `esxi_network_list` | VMware ESXi management |

### Databases

| Group | Tools | Use when… |
|-------|-------|-----------|
| `database` | `db_query`, `db_dump`, `db_restore` | Generic DB operations |
| `redis` | `redis_info`, `redis_cli`, `redis_keys` | Redis key-value store |
| `postgresql` | `postgresql_query`, `postgresql_status` | PostgreSQL databases |
| `mysql` | `mysql_query`, `mysql_status` | MySQL/MariaDB databases |
| `mongodb` | `mongodb_status` | MongoDB status |

### Web Servers & Reverse Proxies

| Group | Tools | Use when… |
|-------|-------|-----------|
| `nginx` | `nginx_status`, `nginx_test`, `nginx_reload`, `nginx_list_sites` | Nginx management |
| `apache` | `apache_status`, `apache_vhosts` | Apache HTTPD |

### Infrastructure as Code

| Group | Tools | Use when… |
|-------|-------|-----------|
| `ansible` | `ansible_playbook`, `ansible_inventory`, `ansible_adhoc` | Ansible automation |
| `terraform` | `terraform_init`, `terraform_plan`, `terraform_apply`, `terraform_state`, `terraform_output` | Terraform IaC |
| `vault` | `vault_read`, `vault_list`, `vault_status`, `vault_write` | HashiCorp Vault secrets |
| `git` | `git_status`, `git_log`, `git_diff`, `git_pull`, `git_clone`, `git_branch`, `git_checkout` | Git repositories |

### Security & Compliance

| Group | Tools | Use when… |
|-------|-------|-----------|
| `certificates` | `cert_check`, `cert_info`, `cert_expiry` | TLS/SSL certificate inspection |
| `letsencrypt` | `letsencrypt_status` | Let's Encrypt certificate status |
| `security_scan` | `sbom_generate`, `vuln_scan`, `compliance_check` | SBOM generation, vulnerability & compliance scanning |
| `network_security` | `port_scan`, `ssl_audit`, `network_capture`, `fail2ban_status` | Port scanning, SSL audit, traffic capture, fail2ban |
| `compliance` | `cis_benchmark`, `stig_check`, `compliance_score`, `compliance_report` | CIS/STIG benchmarks & compliance reporting |

### Observability & Analysis

| Group | Tools | Use when… |
|-------|-------|-----------|
| `diagnostics` | `diagnose`, `incident_triage`, `compare_state` | Intelligent root-cause diagnostics & state comparison |
| `performance` | `perf_trace`, `io_trace`, `latency_test`, `benchmark` | Performance profiling, I/O tracing, benchmarks |
| `container_logs` | `container_log_search`, `container_log_stats`, `container_events`, `container_health_history` | Container log analysis & health tracking |
| `cron_analysis` | `cron_analyze`, `cron_history`, `at_jobs` | Cron conflict analysis, execution history |
| `drift` | `env_snapshot`, `env_diff`, `env_drift` | Environment drift detection & snapshot comparison |

### Cloud & Inventory

| Group | Tools | Use when… |
|-------|-------|-----------|
| `cloud` | `aws_cli`, `cloud_metadata`, `cloud_tags`, `cloud_cost` | Cloud provider interaction |
| `inventory` | `discover_hosts`, `inventory_sync`, `host_tags` | Host discovery & CMDB sync |
| `multicloud` | `multicloud_list`, `multicloud_sync`, `multicloud_compare` | Multi-cloud resource management |

### Alerting & Incident Response

| Group | Tools | Use when… |
|-------|-------|-----------|
| `alerting` | `alert_check`, `alert_list`, `alert_set` | Metric monitoring, threshold checking, alert rules |
| `capacity` | `capacity_collect`, `capacity_trend`, `capacity_predict` | Capacity data collection, trending, prediction |
| `incident` | `incident_timeline`, `incident_correlate` | Incident response timeline & log correlation |

### Multi-host Operations & ChatOps

| Group | Tools | Use when… |
|-------|-------|-----------|
| `orchestration` | `canary_exec`, `rolling_exec`, `fleet_diff` | Multi-host canary/rolling deployments, fleet comparison |
| `runbooks` | `runbook_list`, `runbook_execute`, `runbook_validate` | YAML-defined runbook execution & validation |
| `log_aggregation` | `log_aggregate`, `log_search_multi`, `log_tail_multi` | Cross-host log aggregation, search, tail |
| `key_management` | `key_generate`, `key_distribute`, `key_audit` | SSH key generation, distribution, audit |
| `chatops` | `webhook_send`, `notify` | Slack/Teams/webhook notifications |

### Config Templates & Interactive

| Group | Tools | Use when… |
|-------|-------|-----------|
| `templates` | `template_list`, `template_show`, `template_apply`, `template_validate`, `template_diff` | Config template management |
| `pty` | `pty_exec`, `pty_interact`, `pty_resize` | Interactive PTY sessions |

### Windows (13 groups)

| Group | Tools | Use when… |
|-------|-------|-----------|
| `windows_services` | `win_service_status`, `win_service_start`, `win_service_stop`, `win_service_restart`, `win_service_list`, `win_service_enable`, `win_service_disable`, `win_service_config` | Windows service management |
| `windows_events` | `win_event_logs`, `win_event_query`, `win_event_sources`, `win_event_tail`, `win_event_export` | Windows Event Log queries |
| `active_directory` | `ad_user_list`, `ad_user_info`, `ad_group_list`, `ad_group_members`, `ad_computer_list`, `ad_domain_info` | Active Directory management |
| `scheduled_tasks` | `schtask_list`, `schtask_info`, `schtask_run`, `schtask_enable`, `schtask_disable` | Windows Task Scheduler |
| `windows_firewall` | `win_firewall_status`, `win_firewall_list`, `win_firewall_allow`, `win_firewall_deny`, `win_firewall_remove` | Windows Firewall rules |
| `iis` | `iis_status`, `iis_list_sites`, `iis_list_pools`, `iis_start`, `iis_stop`, `iis_restart` | IIS web server management |
| `windows_updates` | `win_update_list`, `win_update_history`, `win_update_install`, `win_update_search`, `win_update_reboot` | Windows Update management |
| `windows_perf` | `win_perf_cpu`, `win_perf_memory`, `win_perf_disk`, `win_perf_network`, `win_perf_overview`, `win_disk_usage` | Performance counters |
| `hyperv` | `hyperv_vm_list`, `hyperv_vm_info`, `hyperv_vm_start`, `hyperv_vm_stop`, `hyperv_switch_list`, `hyperv_snapshot_list`, `hyperv_snapshot_create`, `hyperv_host_info` | Hyper-V VM management |
| `windows_registry` | `reg_query`, `reg_set`, `reg_delete`, `reg_list`, `reg_export` | Registry operations |
| `windows_features` | `win_feature_list`, `win_feature_info`, `win_feature_install`, `win_feature_remove` | Windows Features/Roles |
| `windows_network` | `win_net_adapters`, `win_net_connections`, `win_net_dns`, `win_net_ip`, `win_net_ping`, `win_net_routes` | Windows networking |
| `windows_process` | `win_process_list`, `win_process_info`, `win_process_kill`, `win_process_top`, `win_process_by_name` | Windows process management |

### Cross-Platform

| Group | Tools | Use when… |
|-------|-------|-----------|
| `config` | `config_get`, `config_set` | Show/modify bridge configuration |
| `recording` | `recording_start`, `recording_stop`, `recording_list`, `recording_replay`, `recording_verify` | Session recording & audit |

## Feature Flags

```toml
default = ["cli"]
cli = ["dep:clap", "dep:clap_complete"]  # CLI binary (disable for lib-only)
http = [...]                              # HTTP/SSE transport (axum)
mimalloc = ["dep:mimalloc"]               # Memory allocator

# Protocol adapters (Tier 1 — air-gapped)
winrm = [...]   telnet = [...]   netconf = [...]   grpc = [...]

# Protocol adapters (Tier 2 — infrastructure)
k8s-exec = [...]   serial = [...]   snmp = [...]

# Protocol adapters (Tier 3 — cloud, non air-gapped)
ssm = [...]   azure = [...]   gcp = []
cloud = ["ssm", "azure", "gcp"]

# Protocol adapters (Tier 4 — messaging)
zeromq = [...]   nats = [...]   mqtt = [...]
messaging = ["zeromq", "nats", "mqtt"]

# Bundles
full = ["cli", "mimalloc", "http"]
air-gapped = ["winrm", "telnet", "netconf"]
all-protocols = [...]  # All protocol adapters
```

## Key Principles

1. **Ports (Traits)**: Define interfaces (`SshExecutor`, `ToolHandler`)
2. **Adapters**: Implement ports (russh, JSON-RPC, YAML)
3. **Domain**: Pure business logic, no external dependencies
4. **Use Cases**: Orchestrate: validation → execution → sanitization → audit
5. **Tool Registry**: Open/Closed pattern for adding tools

## Code Quality

- `#![forbid(unsafe_code)]`
- Clippy with `-D warnings` (all lint groups enabled)
- rustfmt 100 char line width
- cargo-deny for security/license checks
- 5800+ tests (unit, integration, fuzz, mutation)

## Configuration

YAML config at `~/.config/mcp-ssh-bridge/config.yaml`. See `config/config.example.yaml`.
Key sections: `hosts`, `security`, `limits`, `audit`, `tool_groups`, `recording`.

## Known Advisories

6 advisories ignored in `deny.toml` — all transitive, no upstream fix available:

- RUSTSEC-2023-0071 — Marvin Attack on RSA (russh)
- RUSTSEC-2026-0044 — aws-lc-sys X.509 bypass (aws-sdk)
- RUSTSEC-2026-0048 — aws-lc-sys CRL logic error (aws-sdk)
- RUSTSEC-2026-0049 — rustls-webpki CRL matching (russh/aws-sdk/rumqttc)
- RUSTSEC-2021-0153 — encoding crate unmaintained (mini-telnet)
- RUSTSEC-2025-0134 — rustls-pemfile unmaintained (kube/rumqttc/async-nats)

## Path-Scoped Rules

Detailed guidance is loaded automatically via `.claude/rules/`:

- `tool-handlers.md` — Adding tools, handler pattern, clippy pitfalls
- `domain-builders.md` — Domain layer purity, builder conventions
- `security.md` — Security model, blacklist, sanitization
- `registry.md` — Test count assertions, clippy attributes
- `ssh-adapter.md` — Host keys, auth, connection pool, retry
- `testing.md` — Standard tests, fuzz, coverage, mutation
