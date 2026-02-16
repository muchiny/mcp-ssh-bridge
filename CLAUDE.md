# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP SSH Bridge is a Rust MCP (Model Context Protocol) server that enables Claude Code to securely execute commands on air-gapped environments via SSH. It communicates with Claude Code via JSON-RPC over stdio while maintaining SSH connections to remote hosts with strict security controls.

## Build and Development Commands

All commands are available via the Makefile:

```bash
make build              # Debug build
make release            # Optimized release build with LTO
make test               # Run tests (uses nextest if available)
make lint               # Run clippy with strict warnings
make fmt                # Format code
make fmt-check          # Check formatting
make ci                 # Quick CI (fmt-check, lint, test, audit, typos)
make ci-full            # Full CI (ci + hack + geiger)
make release-all        # Cross-compile all 5 platforms
make release-pipeline   # Full release (ci-full + release-all + docker-scan)
make deps-check         # Check outdated/unused deps (replaces Dependabot)
make docker-scan        # Build + Trivy scan Docker image
make dev                # Watch mode with auto-check
make setup              # Install all dev dependencies
make help               # Show all available targets
```

## Architecture Hexagonale (Ports & Adapters)

Ce projet suit l'**Architecture Hexagonale** pour améliorer la testabilité et l'extensibilité.

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
│  └─────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    Entities                          │    │
│  │   Command │ CommandResult │ SecurityPolicy │ Host    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
mcp-ssh-bridge/
├── src/                      # Source code
│   ├── main.rs               # CLI entry point
│   ├── lib.rs                # Library exports
│   ├── error.rs              # Centralized error types
│   ├── cli/                  # CLI module (feature-gated)
│   │   ├── mod.rs            # CLI definition (clap)
│   │   └── runner.rs         # Command execution
│   ├── config/               # Configuration loading
│   ├── domain/               # Business logic (use cases)
│   ├── ports/                # Traits (interfaces)
│   ├── mcp/                  # MCP protocol (adapter)
│   │   └── tool_handlers/    # Individual tool handlers
│   ├── ssh/                  # SSH client (adapter)
│   └── security/             # Security components
├── tests/                    # Integration tests
├── examples/                 # Usage examples
├── benches/                  # Criterion benchmarks
├── config/                   # Example configuration
└── .github/workflows/        # CI/CD
```

## Feature Flags

```toml
[features]
default = ["cli"]
cli = ["dep:clap"]    # CLI binary (can be disabled for lib-only)
mimalloc = ["dep:mimalloc"]
full = ["cli"]
```

## Key Principles

1. **Ports (Traits)**: Define interfaces (`SshExecutor`, `ToolHandler`)
2. **Adapters**: Implement ports (russh, JSON-RPC, YAML)
3. **Domain**: Pure business logic, no external dependencies
4. **Use Cases**: Orchestrate operations (validation → execution → sanitization → audit)
5. **Tool Registry**: Open/Closed pattern for adding tools without modifying existing code

## Adding a New Tool

1. Create a file in `src/mcp/tool_handlers/`
2. Implement the `ToolHandler` trait
3. Register in `create_default_registry()` (`src/mcp/registry.rs`)
4. Assign it to a tool group for `ToolGroupsConfig` filtering
5. Assign annotations in `tool_annotations()` (`src/mcp/registry.rs`) - use `read_only()`, `mutating()`, or `destructive()`

### Tool Groups (38 groups, 197 tools)

#### Linux Groups (25 groups, 123 tools)

| Group | Tools |
|-------|-------|
| **core** | `ssh_exec`, `ssh_exec_multi`, `ssh_status`, `ssh_health`, `ssh_history`, `ssh_output_fetch` |
| **file_transfer** | `ssh_upload`, `ssh_download`, `ssh_sync` |
| **sessions** | `ssh_session_create`, `ssh_session_exec`, `ssh_session_list`, `ssh_session_close` |
| **monitoring** | `ssh_metrics`, `ssh_metrics_multi`, `ssh_tail`, `ssh_disk_usage` |
| **tunnels** | `ssh_tunnel_create`, `ssh_tunnel_list`, `ssh_tunnel_close` |
| **directory** | `ssh_ls`, `ssh_find` |
| **database** | `ssh_db_query`, `ssh_db_dump`, `ssh_db_restore` |
| **backup** | `ssh_backup_create`, `ssh_backup_list`, `ssh_backup_restore` |
| **docker** | `ssh_docker_ps`, `ssh_docker_logs`, `ssh_docker_inspect`, `ssh_docker_exec`, `ssh_docker_compose`, `ssh_docker_images`, `ssh_docker_stats`, `ssh_docker_volume_ls`, `ssh_docker_network_ls`, `ssh_docker_volume_inspect`, `ssh_docker_network_inspect` |
| **esxi** | `ssh_esxi_vm_list`, `ssh_esxi_vm_info`, `ssh_esxi_vm_power`, `ssh_esxi_snapshot`, `ssh_esxi_host_info`, `ssh_esxi_datastore_list`, `ssh_esxi_network_list` |
| **git** | `ssh_git_status`, `ssh_git_log`, `ssh_git_diff`, `ssh_git_pull`, `ssh_git_clone`, `ssh_git_branch`, `ssh_git_checkout` |
| **kubernetes** | `ssh_k8s_get`, `ssh_k8s_logs`, `ssh_k8s_describe`, `ssh_k8s_apply`, `ssh_k8s_delete`, `ssh_k8s_rollout`, `ssh_k8s_scale`, `ssh_k8s_exec`, `ssh_k8s_top`, `ssh_helm_list`, `ssh_helm_status`, `ssh_helm_upgrade`, `ssh_helm_install`, `ssh_helm_rollback`, `ssh_helm_history`, `ssh_helm_uninstall` |
| **ansible** | `ssh_ansible_playbook`, `ssh_ansible_inventory`, `ssh_ansible_adhoc` |
| **systemd** | `ssh_service_status`, `ssh_service_start`, `ssh_service_stop`, `ssh_service_restart`, `ssh_service_list`, `ssh_service_logs`, `ssh_service_enable`, `ssh_service_disable`, `ssh_service_daemon_reload` |
| **network** | `ssh_net_connections`, `ssh_net_interfaces`, `ssh_net_routes`, `ssh_net_ping`, `ssh_net_traceroute`, `ssh_net_dns` |
| **process** | `ssh_process_list`, `ssh_process_kill`, `ssh_process_top` |
| **package** | `ssh_pkg_list`, `ssh_pkg_search`, `ssh_pkg_install`, `ssh_pkg_update`, `ssh_pkg_remove` |
| **firewall** | `ssh_firewall_status`, `ssh_firewall_list`, `ssh_firewall_allow`, `ssh_firewall_deny` |
| **cron** | `ssh_cron_list`, `ssh_cron_add`, `ssh_cron_remove` |
| **certificates** | `ssh_cert_check`, `ssh_cert_info`, `ssh_cert_expiry` |
| **nginx** | `ssh_nginx_status`, `ssh_nginx_test`, `ssh_nginx_reload`, `ssh_nginx_list_sites` |
| **redis** | `ssh_redis_info`, `ssh_redis_cli`, `ssh_redis_keys` |
| **terraform** | `ssh_terraform_init`, `ssh_terraform_plan`, `ssh_terraform_apply`, `ssh_terraform_state`, `ssh_terraform_output` |
| **vault** | `ssh_vault_status`, `ssh_vault_read`, `ssh_vault_list`, `ssh_vault_write` |
| **config** | `ssh_config_get`, `ssh_config_set` |

#### Windows Groups (13 groups, 74 tools)

| Group | Tools |
|-------|-------|
| **windows_services** | `ssh_win_service_status`, `ssh_win_service_start`, `ssh_win_service_stop`, `ssh_win_service_restart`, `ssh_win_service_list`, `ssh_win_service_enable`, `ssh_win_service_disable`, `ssh_win_service_config` |
| **windows_events** | `ssh_win_event_logs`, `ssh_win_event_query`, `ssh_win_event_sources`, `ssh_win_event_tail`, `ssh_win_event_export` |
| **active_directory** | `ssh_ad_user_list`, `ssh_ad_user_info`, `ssh_ad_group_list`, `ssh_ad_group_members`, `ssh_ad_computer_list`, `ssh_ad_domain_info` |
| **scheduled_tasks** | `ssh_schtask_list`, `ssh_schtask_info`, `ssh_schtask_run`, `ssh_schtask_enable`, `ssh_schtask_disable` |
| **windows_firewall** | `ssh_win_firewall_status`, `ssh_win_firewall_list`, `ssh_win_firewall_allow`, `ssh_win_firewall_deny`, `ssh_win_firewall_remove` |
| **iis** | `ssh_iis_status`, `ssh_iis_list_sites`, `ssh_iis_list_pools`, `ssh_iis_start`, `ssh_iis_stop`, `ssh_iis_restart` |
| **windows_updates** | `ssh_win_update_list`, `ssh_win_update_history`, `ssh_win_update_install`, `ssh_win_update_search`, `ssh_win_update_reboot` |
| **windows_perf** | `ssh_win_perf_cpu`, `ssh_win_perf_memory`, `ssh_win_perf_disk`, `ssh_win_perf_network`, `ssh_win_perf_overview`, `ssh_win_disk_usage` |
| **hyperv** | `ssh_hyperv_vm_list`, `ssh_hyperv_vm_info`, `ssh_hyperv_vm_start`, `ssh_hyperv_vm_stop`, `ssh_hyperv_snapshot_list`, `ssh_hyperv_snapshot_create`, `ssh_hyperv_host_info`, `ssh_hyperv_switch_list` |
| **windows_registry** | `ssh_reg_query`, `ssh_reg_set`, `ssh_reg_list`, `ssh_reg_export`, `ssh_reg_delete` |
| **windows_features** | `ssh_win_feature_list`, `ssh_win_feature_info`, `ssh_win_feature_install`, `ssh_win_feature_remove` |
| **windows_network** | `ssh_win_net_adapters`, `ssh_win_net_ip`, `ssh_win_net_routes`, `ssh_win_net_connections`, `ssh_win_net_ping`, `ssh_win_net_dns` |
| **windows_process** | `ssh_win_process_list`, `ssh_win_process_info`, `ssh_win_process_kill`, `ssh_win_process_top`, `ssh_win_process_by_name` |

## Configuration

YAML config at `~/.config/mcp-ssh-bridge/config.yaml`. See `config/config.example.yaml` for format.

Key sections: `hosts` (SSH targets), `security` (whitelist/blacklist/sanitization), `limits` (timeouts), `audit` (logging).

## Code Quality

- Unsafe code is forbidden (`#![forbid(unsafe_code)]`)
- Clippy runs with `-D warnings` (warnings are errors)
- All lints (correctness, suspicious, style, complexity, performance, pedantic) are enabled
- rustfmt uses 100 char line width
- cargo-deny for security/license checks
- markdownlint for documentation

## Security Model

- **Strict mode** (default): Only whitelisted commands allowed
- **Permissive mode**: All commands except blacklisted ones
- Default blacklist protects against: rm -rf, mkfs, dd, chmod 777, curl|sh, etc.
- Output sanitization masks passwords, API keys, private keys

## SSH Features

### Host Key Verification

Three modes via `host_key_verification` in host config:

- **Strict** (default): Rejects unknown hosts and key changes (MITM protection)
- **AcceptNew**: Accepts new hosts, rejects key changes
- **Off**: Accepts all keys (testing only)

### Authentication Methods

- **Key**: SSH key file with optional passphrase
- **Agent**: SSH agent (Unix only, via SSH_AUTH_SOCK)
- **Password**: Plain password (not recommended)

### Connection Pool

Automatic connection reuse with configurable:

- `max_connections_per_host`: 5 (default)
- `max_idle_seconds`: 300 (5 min)
- `max_age_seconds`: 3600 (1 hour)

### Retry Logic

Exponential backoff for transient errors:

- `retry_attempts`: 3 (default)
- `retry_initial_delay_ms`: 100ms (default)

## Module Documentation

Each module has its own README:

| Module | README |
|--------|--------|
| Source overview | `src/README.md` |
| CLI | `src/cli/README.md` |
| Configuration | `src/config/README.md` |
| Domain/Use Cases | `src/domain/README.md` |
| Ports (traits) | `src/ports/README.md` |
| MCP protocol | `src/mcp/README.md` |
| Tool handlers | `src/mcp/tool_handlers/README.md` |
| SSH client | `src/ssh/README.md` |
| Security | `src/security/README.md` |
| Tests | `tests/README.md` |
| Examples | `examples/README.md` |
| Benchmarks | `benches/README.md` |
| Config examples | `config/README.md` |

## CI/CD

### Quick Commands

```bash
make ci                           # Quick CI (fmt+lint+test+audit+typos)
make ci-full                      # Full CI (ci+hack+geiger)
make release-pipeline             # Full release (ci-full+release-all+docker-scan)
make deps-check                   # Check outdated/unused deps
```

### Git Hooks

- **pre-commit**: `cargo fmt`, `cargo clippy`, `typos`, `commitlint`
- **pre-push**: `make ci` (fmt-check + lint + test + audit + typos)

## Testing Tools

### Mutation Testing (cargo-mutants)

Configuration in `.cargo/mutants.toml`:

```bash
make mutants       # Security module only (faster)
make mutants-full  # Full codebase
```

Current mutation score: ~88% on security module.

### Code Coverage (cargo-tarpaulin)

```bash
cargo tarpaulin --engine llvm --out Html
```

Note: Uses LLVM engine due to ptrace compatibility issues. Current coverage: ~54%.

### Fuzz Testing (cargo-fuzz)

26 fuzz targets available in `fuzz/fuzz_targets/`:

```bash
cargo +nightly fuzz list
cargo +nightly fuzz run <target> -- -max_total_time=30
```

## Known Advisories

RUSTSEC-2023-0071 (Marvin Attack on RSA) is ignored in `.cargo/audit.toml` and `deny.toml`:
- Transitive dependency from russh → rsa crate
- No upstream fix available
- Medium severity (5.9), timing attack requires network observation
- Safe for local CLI usage
