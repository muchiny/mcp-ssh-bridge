# CLAUDE.md

## Project Overview

MCP SSH Bridge is a Rust MCP server that enables Claude Code to securely execute commands on air-gapped environments via SSH. JSON-RPC over stdio, strict security controls. **337 tools** across **57 groups** (42 Linux, 13 Windows, 2 cross-platform).

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

## Tool Groups Reference (57 groups, 337 tools)

Use this table to find the right tool for a task. Each tool is prefixed `ssh_`.

### Core Infrastructure (Linux)
| Group | Tools | Use when… |
|-------|-------|-----------|
| `core` | `exec`, `script`, `env`, `uptime`, `hostname`, `reboot`, `shutdown`, `shell_config` | Running arbitrary commands, system info, reboots |
| `file_transfer` | `upload`, `download`, `read_file`, `write_file`, `stat`, `find` | Moving/reading/writing files |
| `file_ops` | `mkdir`, `copy`, `move`, `remove`, `chmod`, `chown`, `link`, `archive`, `extract`, `checksum`, `du`, `tree`, `watch`, `file_diff`, `file_patch`, `file_template`, `file_search_replace`, `file_head`, `file_tail`, `file_wc`, `file_sort`, `file_uniq`, `file_truncate` | File manipulation & analysis |
| `sessions` | `session_start`, `session_send`, `session_read`, `session_end`, `session_list` | Persistent tmux sessions |
| `directory` | `ls`, `pwd`, `cd` | Directory navigation |
| `process` | `ps`, `kill`, `top` | Process management |
| `monitoring` | `df`, `free`, `vmstat`, `iostat`, `netstat`, `lsof` | System monitoring |
| `network` | `ping`, `traceroute`, `dig`, `curl`, `ss`, `ip_addr`, `ip_route` | Network diagnostics |
| `systemd` | `service_status`, `service_start`, `service_stop`, `service_restart`, `service_enable`, `service_disable`, `service_logs`, `service_list` | Systemd service management |
| `systemd_timers` | `timer_list`, `timer_info`, `timer_enable`, `timer_disable`, `timer_trigger` | Systemd timer management |
| `firewall` | `firewall_status`, `firewall_list`, `firewall_allow`, `firewall_deny`, `firewall_delete` | iptables/ufw firewall rules |
| `package` | `pkg_list`, `pkg_install`, `pkg_remove`, `pkg_update`, `pkg_search`, `pkg_info` | Package management (apt/yum/dnf) |
| `cron` | `cron_list`, `cron_add`, `cron_remove` | Crontab management |
| `user_management` | `user_list`, `user_info`, `user_add`, `user_remove`, `group_list`, `group_add` | User & group management |
| `storage` | `lvm_info`, `mount_list`, `swap_info` | Storage/LVM/mounts |
| `journald` | `journal_query`, `journal_follow`, `journal_units` | Journald log queries |
| `security_modules` | `selinux_status`, `apparmor_status`, `audit_log` | SELinux, AppArmor, auditd |

### Containers & Orchestration
| Group | Tools | Use when… |
|-------|-------|-----------|
| `docker` | `docker_ps`, `docker_logs`, `docker_inspect`, `docker_stats`, `docker_exec`, `docker_images`, `docker_compose` | Docker container management |
| `podman` | `podman_ps`, `podman_logs`, `podman_inspect`, `podman_stats`, `podman_exec`, `podman_images` | Podman container management |
| `kubernetes` | `kubectl_get`, `kubectl_describe`, `kubectl_logs`, `kubectl_apply`, `kubectl_delete`, `kubectl_exec` | Kubernetes cluster management |

### Databases
| Group | Tools | Use when… |
|-------|-------|-----------|
| `database` | `db_query`, `db_tables`, `db_schema` | Generic DB operations |
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
| `ansible` | `ansible_playbook`, `ansible_inventory`, `ansible_facts` | Ansible automation |
| `terraform` | `terraform_init`, `terraform_plan`, `terraform_apply`, `terraform_state` | Terraform IaC |
| `vault` | `vault_read`, `vault_list`, `vault_status` | HashiCorp Vault secrets |
| `git` | `git_status`, `git_log`, `git_diff`, `git_pull`, `git_clone` | Git repositories |

### Security & Compliance (v1.7+)
| Group | Tools | Use when… |
|-------|-------|-----------|
| `certificates` | `cert_check`, `cert_info`, `cert_expiry` | TLS/SSL certificate inspection |
| `letsencrypt` | `letsencrypt_status` | Let's Encrypt certificate status |
| `security_scan` | `lynis_audit`, `rkhunter_check`, `clamav_scan` | Host security scanning |
| `network_security` | `port_scan`, `firewall_audit`, `open_ports`, `connection_analysis`, `fail2ban_status`, `dns_audit`, `ssl_audit`, `network_segmentation` | Network security auditing |
| `compliance` | `cis_benchmark`, `stig_check`, `pci_check`, `hipaa_check`, `soc2_check`, `gdpr_check`, `nist_check`, `iso27001_check` | Regulatory compliance checks |

### Observability & Analysis (v1.6+)
| Group | Tools | Use when… |
|-------|-------|-----------|
| `diagnostics` | `diagnose` | Intelligent root-cause diagnostics |
| `performance` | `perf_profile`, `perf_flame`, `perf_benchmark` | Performance profiling |
| `container_logs` | `container_log_search`, `container_log_stats`, `container_log_export` | Container log analysis |
| `cron_analysis` | `cron_conflict_check`, `cron_timeline` | Cron scheduling analysis |
| `drift` | `drift_detect` | Environment drift detection |

### Cloud & Inventory (v1.8+)
| Group | Tools | Use when… |
|-------|-------|-----------|
| `cloud` | `aws_cli`, `cloud_metadata`, `cloud_tags`, `cloud_cost` | Cloud provider interaction |
| `inventory` | `discover_hosts`, `inventory_sync`, `host_tags` | Host discovery & CMDB sync |
| `multicloud` | `multicloud_list`, `multicloud_sync`, `multicloud_compare` | Multi-cloud resource management |

### Alerting & Incident Response (v1.9+)
| Group | Tools | Use when… |
|-------|-------|-----------|
| `alerting` | `alert_status`, `alert_silence`, `alert_history` | Monitoring alert management |
| `capacity` | `capacity_forecast`, `capacity_report`, `capacity_recommend` | Capacity planning |
| `incident` | `incident_timeline`, `incident_collect` | Incident response & forensics |

### Multi-host Operations & ChatOps (v2.0+)
| Group | Tools | Use when… |
|-------|-------|-----------|
| `orchestration` | `orchestrate` | Multi-host command orchestration |
| `runbooks` | `runbook_exec`, `runbook_list` | YAML-defined runbook execution |
| `log_aggregation` | `log_aggregate`, `log_correlate`, `log_pattern`, `log_anomaly` | Cross-host log analysis |
| `key_management` | `key_rotate`, `key_distribute`, `key_audit` | SSH key lifecycle management |
| `chatops` | `webhook_send`, `notify` | Slack/Teams/webhook notifications |

### Config Templates & Interactive (v2.1+)
| Group | Tools | Use when… |
|-------|-------|-----------|
| `templates` | `template_list`, `template_show`, `template_apply`, `template_validate`, `template_diff` | Config template management |
| `pty` | `pty_exec`, `pty_interact`, `pty_resize` | Interactive PTY sessions |

### Windows (13 groups)
| Group | Tools | Use when… |
|-------|-------|-----------|
| `windows_services` | `win_service_*` | Windows service management |
| `windows_events` | `win_event_*` | Windows Event Log queries |
| `active_directory` | `win_ad_*` | Active Directory management |
| `scheduled_tasks` | `win_task_*` | Windows Task Scheduler |
| `windows_firewall` | `win_fw_*` | Windows Firewall rules |
| `iis` | `win_iis_*` | IIS web server management |
| `windows_updates` | `win_update_*` | Windows Update management |
| `windows_perf` | `win_perf_*` | Performance counters |
| `hyperv` | `win_hyperv_*` | Hyper-V VM management |
| `windows_registry` | `win_reg_*` | Registry operations |
| `windows_features` | `win_feature_*` | Windows Features/Roles |
| `windows_network` | `win_net_*` | Windows networking |
| `windows_process` | `win_proc_*` | Windows process management |

### Cross-Platform
| Group | Tools | Use when… |
|-------|-------|-----------|
| `config` | `config_show` | Show bridge configuration |
| `recording` | `recording_start`, `recording_stop`, `recording_status`, `recording_list` | Session recording & audit |

## Feature Flags

```toml
default = ["cli"]
cli = ["dep:clap"]       # CLI binary (disable for lib-only)
mimalloc = ["dep:mimalloc"]
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

RUSTSEC-2023-0071 (Marvin Attack on RSA) ignored — transitive dep from russh, no upstream fix, safe for local CLI.

## Path-Scoped Rules

Detailed guidance is loaded automatically via `.claude/rules/`:

- `tool-handlers.md` — Adding tools, handler pattern, clippy pitfalls
- `domain-builders.md` — Domain layer purity, builder conventions
- `security.md` — Security model, blacklist, sanitization
- `registry.md` — Test count assertions, clippy attributes
- `ssh-adapter.md` — Host keys, auth, connection pool, retry
- `testing.md` — Standard tests, fuzz, coverage, mutation
