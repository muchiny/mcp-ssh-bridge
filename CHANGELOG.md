# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.1] - 2026-02-16

### Changed

- Deduplicate 17 local `shell_escape` functions into centralized `shell::escape(s, ShellType::Posix)`
- Integrate `validate_terraform_dir` into all `TerraformCommandBuilder` methods
- Integrate `validate_vault_path` into `VaultCommandBuilder` read/list/write methods
- Integrate `validate_network_target` into `NetworkCommandBuilder` and `WindowsNetworkCommandBuilder`
- Add 8 missing Windows groups to `config.example.yaml` documentation
- Fix `ssh_win_disk_usage` group placement in `config.example.yaml`
- Update handler count comment in `lib.rs` (111 → 197)

## [2.0.0] - 2026-02-15

### Added

- **Windows Support**: 74 new tools across 13 groups for Windows Server management via PowerShell:
  - **Windows Services** (`windows_services`, 8 tools): `ssh_win_service_status`, `ssh_win_service_start`, `ssh_win_service_stop`, `ssh_win_service_restart`, `ssh_win_service_list`, `ssh_win_service_enable`, `ssh_win_service_disable`, `ssh_win_service_config`
  - **Windows Events** (`windows_events`, 5 tools): `ssh_win_event_logs`, `ssh_win_event_query`, `ssh_win_event_sources`, `ssh_win_event_tail`, `ssh_win_event_export`
  - **Active Directory** (`active_directory`, 6 tools): `ssh_ad_user_list`, `ssh_ad_user_info`, `ssh_ad_group_list`, `ssh_ad_group_members`, `ssh_ad_computer_list`, `ssh_ad_domain_info`
  - **Scheduled Tasks** (`scheduled_tasks`, 5 tools): `ssh_schtask_list`, `ssh_schtask_info`, `ssh_schtask_run`, `ssh_schtask_enable`, `ssh_schtask_disable`
  - **Windows Firewall** (`windows_firewall`, 5 tools): `ssh_win_firewall_status`, `ssh_win_firewall_list`, `ssh_win_firewall_allow`, `ssh_win_firewall_deny`, `ssh_win_firewall_remove`
  - **IIS** (`iis`, 6 tools): `ssh_iis_status`, `ssh_iis_list_sites`, `ssh_iis_list_pools`, `ssh_iis_start`, `ssh_iis_stop`, `ssh_iis_restart`
  - **Windows Updates** (`windows_updates`, 5 tools): `ssh_win_update_list`, `ssh_win_update_history`, `ssh_win_update_install`, `ssh_win_update_search`, `ssh_win_update_reboot`
  - **Windows Performance** (`windows_perf`, 6 tools): `ssh_win_perf_cpu`, `ssh_win_perf_memory`, `ssh_win_perf_disk`, `ssh_win_perf_network`, `ssh_win_perf_overview`, `ssh_win_disk_usage`
  - **Hyper-V** (`hyperv`, 8 tools): `ssh_hyperv_vm_list`, `ssh_hyperv_vm_info`, `ssh_hyperv_vm_start`, `ssh_hyperv_vm_stop`, `ssh_hyperv_snapshot_list`, `ssh_hyperv_snapshot_create`, `ssh_hyperv_host_info`, `ssh_hyperv_switch_list`
  - **Windows Registry** (`windows_registry`, 5 tools): `ssh_reg_query`, `ssh_reg_set`, `ssh_reg_list`, `ssh_reg_export`, `ssh_reg_delete`
  - **Windows Features** (`windows_features`, 4 tools): `ssh_win_feature_list`, `ssh_win_feature_info`, `ssh_win_feature_install`, `ssh_win_feature_remove`
  - **Windows Network** (`windows_network`, 6 tools): `ssh_win_net_adapters`, `ssh_win_net_ip`, `ssh_win_net_routes`, `ssh_win_net_connections`, `ssh_win_net_ping`, `ssh_win_net_dns`
  - **Windows Process** (`windows_process`, 5 tools): `ssh_win_process_list`, `ssh_win_process_info`, `ssh_win_process_kill`, `ssh_win_process_top`, `ssh_win_process_by_name`
- **OS Detection**: `OsType` (Linux/Windows) and `ShellType` (Posix/Cmd/PowerShell) for per-host OS routing
- **Shell Utilities**: `shell::escape()` with PowerShell-aware quoting (`shell.rs`)
- **13 Windows Domain Command Builders**: `WindowsServiceCommandBuilder`, `WindowsEventCommandBuilder`, `ActiveDirectoryCommandBuilder`, `ScheduledTaskCommandBuilder`, `WindowsFirewallCommandBuilder`, `IisCommandBuilder`, `WindowsUpdateCommandBuilder`, `WindowsPerfCommandBuilder`, `HyperVCommandBuilder`, `WindowsRegistryCommandBuilder`, `WindowsFeatureCommandBuilder`, `WindowsNetworkCommandBuilder`, `WindowsProcessCommandBuilder`
- **New Linux Tools**:
  - `ssh_disk_usage` (monitoring group): Disk usage analysis
  - `ssh_find` (directory group): File search with filters
  - `ssh_pkg_remove` (package group): Package removal
  - `ssh_service_enable`, `ssh_service_disable`, `ssh_service_daemon_reload` (systemd group): Service management
  - `ssh_docker_volume_ls`, `ssh_docker_volume_inspect`, `ssh_docker_network_ls`, `ssh_docker_network_inspect` (docker group): Docker volume and network management
- **SOCKS Proxy Support**: Connect through SOCKS5 proxies
- **SSH Config Auto-Discovery**: Enabled by default

### Changed

- **MCP Protocol**: Upgraded to `2025-11-25` (from `2025-06-18`)
- **Tool Count**: 113 → 197 tools across 38 groups (was 25 groups)
- **Tool Groups**: 25 → 38 groups (25 Linux + 13 Windows)
- **Test Count**: ~3788 tests

## [1.9.0] - 2026-02-14

### Added

- **Tool Annotations (MCP 2025-06-18)**: All 113 tools now have behavioral hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`, `title`) enabling Claude Code to optimize tool selection and confirm dangerous operations
- **New Config Tools** (`config` group, 2 tools):
  - `ssh_config_get`: Query runtime configuration (max_output_chars, timeouts)
  - `ssh_config_set`: Modify max_output_chars dynamically per session
- **Prompts** (4 new MCP prompts):
  - `backup-verify`: Backup verification workflow
  - `docker-health`: Docker health diagnostics
  - `k8s-overview`: Kubernetes cluster overview
  - `troubleshoot`: Troubleshooting assistant
- **Resources** (2 new MCP resources):
  - `history://recent`: Command execution history
  - `services://list`: System services listing
- **Security Documentation**:
  - `SECURITY.md`: Vulnerability reporting policy
  - `docs/THREAT_MODEL.md`: Comprehensive threat analysis
- **Security Audit**: CI workflow + test suite for security validation
- **Per-client output limits**: `ClientOverride` config, `runtime_max_output_chars` in server
- **Output management**: `OutputCache` for pagination, `save_output` parameter, configurable `max_output_chars`

### Changed

- **MCP Protocol**: Upgraded to `2025-06-18` (from `2024-11-05`)
- **Content types**: `ToolContent` now supports Text, Image, Audio, Resource variants
- **Structured content**: `ToolCallResult.structured_content` field for machine-readable data
- **Instructions**: `InitializeResult` includes server guidance for LLM tool selection
- **Tool Groups**: 24 → 25 groups (added `config`)
- **Tool Count**: 111 → 113 tools

## [1.8.3] - 2026-02-12

### Added

- **11 new tool groups** (45 tools) for system administration:
  - **Systemd** (`systemd` group, 6 tools): `ssh_service_status`, `ssh_service_start`, `ssh_service_stop`, `ssh_service_restart`, `ssh_service_list`, `ssh_service_logs`
  - **Network** (`network` group, 6 tools): `ssh_net_connections`, `ssh_net_interfaces`, `ssh_net_routes`, `ssh_net_ping`, `ssh_net_traceroute`, `ssh_net_dns`
  - **Process** (`process` group, 3 tools): `ssh_process_list`, `ssh_process_kill`, `ssh_process_top`
  - **Package** (`package` group, 4 tools): `ssh_pkg_list`, `ssh_pkg_search`, `ssh_pkg_install`, `ssh_pkg_update`
  - **Firewall** (`firewall` group, 4 tools): `ssh_firewall_status`, `ssh_firewall_list`, `ssh_firewall_allow`, `ssh_firewall_deny`
  - **Cron** (`cron` group, 3 tools): `ssh_cron_list`, `ssh_cron_add`, `ssh_cron_remove`
  - **Certificates** (`certificates` group, 3 tools): `ssh_cert_check`, `ssh_cert_info`, `ssh_cert_expiry`
  - **Nginx** (`nginx` group, 4 tools): `ssh_nginx_status`, `ssh_nginx_test`, `ssh_nginx_reload`, `ssh_nginx_list_sites`
  - **Redis** (`redis` group, 3 tools): `ssh_redis_info`, `ssh_redis_cli`, `ssh_redis_keys`
  - **Terraform** (`terraform` group, 5 tools): `ssh_terraform_init`, `ssh_terraform_plan`, `ssh_terraform_apply`, `ssh_terraform_state`, `ssh_terraform_output`
  - **Vault** (`vault` group, 4 tools): `ssh_vault_status`, `ssh_vault_read`, `ssh_vault_list`, `ssh_vault_write`
- **11 domain command builders**: `SystemdCommandBuilder`, `NetworkCommandBuilder`, `ProcessCommandBuilder`, `PackageCommandBuilder`, `FirewallCommandBuilder`, `CronCommandBuilder`, `CertificateCommandBuilder`, `NginxCommandBuilder`, `RedisCommandBuilder`, `TerraformCommandBuilder`, `VaultCommandBuilder`
- **28 new E2E tests** on Raspberry Pi (phases 11-20): systemd, network, process, package, cron, certificates, firewall, nginx, redis, and security validation tests
- **Input validation hardening**: 18 security findings fixed across command builders (shell injection prevention, empty input rejection, path traversal protection)

### Changed

- **Tool Count**: From 66 to 111 tools across 24 groups (was 13 groups)
- **E2E Test Count**: From 28 to 56 tests (20 phases)

## [1.8.2] - 2026-02-10

### Added

- **Docker Tools** (`docker` group): 7 new tools for Docker container management
  - `ssh_docker_ps`: List containers (all or running, with optional filters)
  - `ssh_docker_logs`: View container logs (with tail, since, timestamps)
  - `ssh_docker_inspect`: Inspect container/image details (JSON output)
  - `ssh_docker_exec`: Execute commands inside running containers
  - `ssh_docker_compose`: Run docker-compose commands (up, down, restart, ps, logs, build, pull)
  - `ssh_docker_images`: List Docker images (with optional repository filter)
  - `ssh_docker_stats`: Show container resource usage (CPU, memory, network)
- **ESXi Tools** (`esxi` group): 7 new tools for VMware ESXi host management
  - `ssh_esxi_vm_list`: List virtual machines on ESXi host
  - `ssh_esxi_vm_info`: Get detailed VM information (CPU, memory, disks, NICs)
  - `ssh_esxi_vm_power`: Power on/off/reset/suspend VMs
  - `ssh_esxi_snapshot`: Create, list, remove, or revert VM snapshots
  - `ssh_esxi_host_info`: Get ESXi host hardware and version info
  - `ssh_esxi_datastore_list`: List datastores with capacity info
  - `ssh_esxi_network_list`: List virtual switches and port groups
- **Git Tools** (`git` group): 7 new tools for remote Git repository management
  - `ssh_git_status`: Show working tree status (with optional short format)
  - `ssh_git_log`: View commit history (with filters: max_count, oneline, author, since, format)
  - `ssh_git_diff`: Show changes between commits or working tree (staged, file, commit)
  - `ssh_git_pull`: Fetch and integrate remote changes (with rebase, ff-only options)
  - `ssh_git_clone`: Clone a repository (with branch, depth, single-branch options)
  - `ssh_git_branch`: Manage branches (list, create, delete)
  - `ssh_git_checkout`: Switch branches or restore files (with create -b flag)
- **Tool Groups**: 10 → 13 groups, 44 → 66 tools
- Domain command builders: `DockerCommandBuilder`, `EsxiCommandBuilder`, `GitCommandBuilder`

## [1.8.1] - 2026-02-09

### Improved

- **LLM-optimized tool descriptions**: Rewritten all 44 tool descriptions for better LLM comprehension
  - Added output format guidance (e.g., "Returns JSON", "Returns stdout, stderr, exit code")
  - Added discovery workflow hints (e.g., "Use ssh_status first to discover host aliases")
  - Added tool alternatives (e.g., "For single files, prefer ssh_upload instead of ssh_sync")
  - Added inter-tool workflow guidance (e.g., "Use ssh_k8s_rollout after ssh_k8s_apply")
  - Added error handling hints (e.g., "If command denied, the security whitelist may need updating")
  - Kubernetes tools: ssh_k8s_get identified as entry point, tools cross-reference each other
  - Helm tools: ssh_helm_list as entry point, history→rollback workflow documented
  - Ansible tools: ssh_ansible_inventory as entry point, playbook vs adhoc distinction clarified
  - Database tools: workflow guidance (query→dump→download, upload→restore)
  - Backup tools: workflow guidance (create→list→restore)

## [1.8.0] - 2026-02-09

### Added

- **Kubernetes Tools** (`kubernetes` group): 9 new tools for kubectl management
  - `ssh_k8s_get`: List and inspect Kubernetes resources
  - `ssh_k8s_logs`: View pod logs with container/tail/since filters
  - `ssh_k8s_describe`: Describe resources in detail
  - `ssh_k8s_apply`: Apply manifests (file or inline YAML)
  - `ssh_k8s_delete`: Delete resources with namespace protection (blocks kube-system, kube-public, default, kube-node-lease)
  - `ssh_k8s_rollout`: Manage rollouts (status, restart, undo, history)
  - `ssh_k8s_scale`: Scale deployments/statefulsets
  - `ssh_k8s_exec`: Execute commands inside pods
  - `ssh_k8s_top`: View resource usage (pods/nodes)
- **Helm Tools** (`kubernetes` group): 7 new tools for Helm chart management
  - `ssh_helm_list`: List Helm releases
  - `ssh_helm_status`: Show release status
  - `ssh_helm_upgrade`: Upgrade releases with set values, values files
  - `ssh_helm_install`: Install new releases
  - `ssh_helm_rollback`: Rollback to previous revisions
  - `ssh_helm_history`: View release history
  - `ssh_helm_uninstall`: Uninstall releases
- **Ansible Tools** (`ansible` group): 3 new tools for Ansible automation
  - `ssh_ansible_playbook`: Run playbooks with inventory, tags, extra vars, check/diff modes
  - `ssh_ansible_inventory`: Query inventory (list, graph, host)
  - `ssh_ansible_adhoc`: Run ad-hoc commands with dangerous module/pattern blocking
- **Domain Command Builders**: `KubernetesCommandBuilder`, `HelmCommandBuilder`, `AnsibleCommandBuilder` with security validation
- **5 new fuzz targets**: `fuzz_k8s_command_builder`, `fuzz_k8s_validation`, `fuzz_helm_command_builder`, `fuzz_ansible_command_builder`, `fuzz_ansible_validation`
- **Architecture refactoring**:
  - Moved `CommandHistory` to domain layer (was in mcp adapter)
  - Moved `RealSshConnector` to ssh adapter (was in ports layer)
  - Moved protocol contract types (`ToolCallResult`, `PromptMessage`, etc.) to `ports/protocol.rs`
  - Centralized test context creation across all 37 handler files
- **Tool Groups**: 8 → 10 groups, 25 → 44 tools

## [1.7.0] - 2026-02-05

### Added

- **Database Tools** (`database` group): 3 new tools for MySQL/PostgreSQL management
  - `ssh_db_query`: Execute SQL queries with automatic dangerous query blocking
    (DROP DATABASE, DROP TABLE, TRUNCATE, DELETE FROM, GRANT, REVOKE)
  - `ssh_db_dump`: Database dump with optional compression (gzip/bzip2/xz)
  - `ssh_db_restore`: Restore database from dump files
  - `DatabaseCommandBuilder` domain service for safe command construction
  - Password handling via environment variables (MYSQL_PWD/PGPASSWORD)

- **Backup & Restore** (`backup` group): 3 new tools for tar archive management
  - `ssh_backup_create`: Create tar archives with optional compression and exclude patterns
  - `ssh_backup_list`: List archive contents with verbose mode
  - `ssh_backup_restore`: Extract archives with destination and strip_components support

- **SSH Tunnels** (`tunnels` group): 3 new tools for port forwarding
  - `ssh_tunnel_create`: Create local port forwarding tunnels
  - `ssh_tunnel_list`: List active tunnels with metadata
  - `ssh_tunnel_close`: Close tunnels by ID
  - `TunnelManager` domain service for tunnel lifecycle management

- **Directory Operations** (`directory` group):
  - `ssh_ls`: Structured directory listing with recursive, sort, and hidden file support

- **Recursive Directory Transfer**:
  - `ssh_sync`: Upload/download entire directories via SFTP with exclude patterns

- **SSH Config Auto-Discovery**: Parse `~/.ssh/config` to auto-discover hosts
  - Supports Host, HostName, Port, User, IdentityFile, ProxyJump, Include directives
  - Configurable exclude list and custom path
  - Discovered hosts use `AcceptNew` host key verification

- **Sudo Support**: Execute commands with sudo on ssh_exec, ssh_exec_multi, ssh_session_exec
  - Per-host `sudo_password` configuration
  - `sudo` and `sudo_user` parameters on execution tools

- **Tool Groups System**: Enable/disable tool groups to reduce LLM context
  - 8 groups: core, file_transfer, sessions, monitoring, tunnels, directory, database, backup
  - Hot-reload aware (restart required for tool group changes)

- **Docker Distribution**: Multi-stage Dockerfile (~15MB Alpine image)
  - docker-compose.yml with read-only volume mounts
  - Non-root container user

- **Fuzz Testing**: 5 new fuzz targets (21 total)
  - `fuzz_db_command_builder`, `fuzz_db_query_validation`, `fuzz_db_type_parse`
  - `fuzz_ssh_config_parser`, `fuzz_tunnel_manager`

- **Mutation Testing**: New `make mutants-db` target for database/domain module

### Changed

- **Tool Count**: From 15 to 25 tools across 8 groups
- **Test Count**: From 945 to 1113 tests
- **Fuzz Targets**: From 16 to 21 targets

## [1.6.0] - 2026-02-05

### Fixed

- **Hot-Reload for Whitelist/Blacklist/Mode**: Fixed `ConfigWatcher` not detecting
  configuration changes made by editors (vim, nano, VS Code) that use atomic saves
  (write temp file, rename over original):
  - **Root cause**: inotify watches file inodes, not paths. Atomic saves create a new
    inode, causing the watcher to lose track of the file
  - **Watch parent directory**: Now watches the config directory instead of the file
    directly, so rename events are captured
  - **Accept Create events**: In addition to Modify events, the watcher now reacts to
    Create events generated by atomic saves
  - **Debounce (500ms)**: Prevents duplicate reloads when editors generate multiple
    filesystem events per save

### Changed

- **Test Count**: From 929 to 945+ tests (25 new `ConfigWatcher` hot-reload tests)
- **Hot-Reload Test Coverage**: Comprehensive tests for whitelist add/remove/replace,
  blacklist add/remove/override, mode switching (strict/permissive), multiple
  consecutive reloads, debounce, invalid YAML resilience, and both atomic and
  direct write scenarios

## [1.5.0] - 2026-02-01

### Added

- **Claude Agent Pipeline**: TypeScript-based local CI/CD pipeline in `agents/`:
  - 7 orchestrated agents: lint, test, coverage, audit, fuzz, mutant, summary
  - Blocking/non-blocking execution modes
  - AI-powered summary generation (requires `ANTHROPIC_API_KEY`)
  - Configurable via CLI arguments (`--agent`, `-s/--skip`)

- **Mutation Testing Infrastructure**: cargo-mutants configuration in `.cargo/mutants.toml`:
  - Security module achieves ~88% mutation score
  - Makefile targets: `make mutants`, `make mutants-full`
  - Configured to skip logging calls and use nextest

- **Code Coverage**: cargo-tarpaulin integration:
  - LLVM engine for ptrace compatibility
  - Current coverage: ~54% (SSH modules require real server)

- **Documentation Updates**: Enhanced CLAUDE.md with:
  - Agent pipeline documentation
  - Testing tools section (mutation, coverage, fuzz)
  - Known advisories section

### Changed

- Updated fuzz target count from 9 to 16 in documentation

### Security

- Added `.cargo/audit.toml` to ignore RUSTSEC-2023-0071 (Marvin Attack on RSA):
  - Transitive dependency from russh -> rsa crate
  - No upstream fix available
  - Medium severity (5.9), timing attack requires network observation

## [1.4.0] - 2026-02-01

### Added

- **Comprehensive Fuzzing Infrastructure**: 16 fuzz targets covering all security-critical functions:
  - `fuzz_shell_escape`: Shell command escaping (149M+ executions)
  - `fuzz_validate_path`: Path traversal protection (82M+ executions)
  - `fuzz_sanitizer`: Password/secret masking (optimized: 12,800/s)
  - `fuzz_command_validator`: Whitelist/blacklist validation (optimized: 61,400/s)
  - `fuzz_parse_metrics`: System metrics parsing
  - `fuzz_truncate_output`: UTF-8 boundary-safe truncation
  - `fuzz_jsonrpc_parse`: MCP JSON-RPC protocol parsing
  - `fuzz_yaml_config`: Configuration file parsing
  - `fuzz_regex_redos`: ReDoS vulnerability detection
  - `fuzz_transfer_mode`: SFTP transfer mode parsing
  - `fuzz_tool_params`: MCP tool parameter parsing
  - `fuzz_host_config`: Host configuration parsing
  - `fuzz_rate_limiter`: Rate limiting logic
  - `fuzz_char_boundary`: UTF-8 character boundary functions
  - `fuzz_audit_serialize`: Audit event serialization
  - `fuzz_security_config`: Security configuration parsing

- **Corpus Seeds**: 67 seed files across all 16 fuzz targets for guided fuzzing

- **New Fuzzing Exports**: Exposed internal functions for fuzzing via `#[doc(hidden)]`:
  - `floor_char_boundary`, `ceil_char_boundary` from output truncator
  - `RateLimiter`, `CommandValidator`, `AuditEvent`, `CommandResult`
  - `TransferMode`, `SecurityConfig`, `HostConfig`

### Changed

- **Fuzz Harness Optimization**: Used `lazy_static!` to pre-compile regex patterns once:
  - `fuzz_sanitizer`: 4/s → 12,856/s (**3,214x faster**)
  - `fuzz_command_validator`: 39/s → 61,410/s (**1,574x faster**)

### Fixed

- **Fuzz Assertion**: Removed overly strict password masking assertion that caused
  false positives on edge cases like "Aassword=secret" (not a password pattern)

## [1.3.0] - 2026-01-31

### Added

- **Comprehensive Test Suite Expansion**: Added 72 new tests across multiple modules:
  - `mcp/protocol.rs`: JSON-RPC serialization/deserialization tests
  - `mcp/prompts/*.rs`: Tests for system-health, deploy, and security-audit prompts
  - `config/watcher.rs`: Config hot-reload and file watching tests
  - `mcp/tool_handlers/*.rs`: Schema validation, error handling, and description tests

### Fixed

- **JSON-RPC Null ID Handling**: Corrected test expectation for `"id": null` in JSON-RPC
  requests. Per serde_json behavior, `null` is correctly deserialized as `None` for
  `Option<Value>` fields, which aligns with JSON-RPC 2.0 spec (null id = notification).

### Changed

- **Test Count**: From 626 to 698 tests (+72 tests, +11.5% coverage)

## [1.2.0] - 2026-01-31

### Fixed

- **SFTP Division by Zero**: Fixed potential division by zero when calculating
  progress percentage for empty files (0 bytes). Now returns 100% correctly.

- **SFTP Checksum in Resume/Append Mode**: Disabled checksum calculation for
  Resume and Append transfer modes. Previously, the checksum only covered the
  transferred portion, not the complete file, which was misleading. Checksum
  is now only returned for Overwrite and FailIfExists modes where it represents
  the complete file.

- **SSH History JSON Parsing**: Changed from silent fallback to explicit error
  reporting when JSON arguments are malformed. Now consistent with other tool
  handlers that return `McpInvalidRequest` errors.

- **Parallel Sanitization Data Loss**: Fixed a subtle bug in the parallel
  sanitization code path where regex replacements that changed text length
  could cause data loss or duplication at chunk boundaries. The sanitizer now
  falls back to sequential processing when secrets are detected, ensuring
  correct output in all cases.

### Changed

- **Sanitizer Simplification**: Removed unused parallel chunk processing code
  (`create_chunks`, `apply_patterns_to_chunk`, `merge_chunks`) since the
  sanitizer now uses sequential processing when patterns match. Parallel
  detection via `RegexSet` is still used for fast-path rejection.

## [1.1.0] - 2026-01-30

### Added

- **Configurable Sanitizer** with fine-grained control:
  - `security.sanitize.enabled`: Enable/disable sanitization entirely
  - `security.sanitize.disable_builtin`: Disable specific pattern categories
  - `security.sanitize.custom_patterns`: Add custom patterns with custom replacements
  - 17 pattern categories: `github`, `gitlab`, `slack`, `discord`, `openai`, `aws`, `k3s`, `jwt`, `certificates`, `kubeconfig`, `docker`, `database`, `ansible`, `azure`, `gcp`, `hashicorp`, `generic`

- **New Sanitizer APIs**:
  - `Sanitizer::from_config()`: Create from `SanitizeConfig`
  - `Sanitizer::from_config_with_legacy()`: Support legacy `sanitize_patterns` field
  - `Sanitizer::disabled()`: Create a pass-through sanitizer
  - `Sanitizer::is_enabled()`: Check if sanitization is active

- **New Config Types**:
  - `SanitizeConfig`: Advanced sanitizer configuration
  - `CustomSanitizePattern`: Custom pattern with replacement and description

### Changed

- **SFTP Documentation**: Removed artificial 50GB limit mentions - streaming supports unlimited file sizes
- **Pattern Categories**: All ~50 builtin patterns now have a category for filtering
- **Backward Compatibility**: Legacy `sanitize_patterns` field still works alongside new `sanitize` config

### Fixed

- Integration test for default security config now validates new `SanitizeConfig` fields

## [1.0.0] - 2026-01-30

### 🎉 First Stable Release

This release marks the first stable version of MCP SSH Bridge with a completely rewritten, high-performance output sanitizer.

### Added

- **High-Performance Sanitizer** (complete rewrite):
  - **~50 secret patterns** covering: GitHub, GitLab, Slack, OpenAI, AWS, K3s, Kubernetes, Docker, Ansible, databases, and more
  - **5-tier pattern architecture**: Specific patterns first (unique markers), generic patterns last
  - **Aho-Corasick pre-filter**: O(n) keyword detection for fast-path rejection
  - **RegexSet detection**: Single-pass to identify which patterns match
  - **Zero-copy optimization**: `Cow<str>` returns borrowed reference when no secrets found
  - **Parallel processing**: Rayon-based chunked processing for outputs >512KB
  - **New pattern categories**:
    - CI/CD: `ghp_*`, `gho_*`, `glpat-*`, GitLab CI tokens
    - AI APIs: OpenAI (`sk-*`), Anthropic, NVIDIA
    - Messaging: Slack (`xoxb-*`), Discord webhooks
    - Kubernetes: K3s tokens (`K10*`), kubeconfig certificates, JWT service account tokens
    - Docker: Registry auth, compose passwords
    - Ansible: Vault passwords, encrypted content, SSH passwords
    - Cloud: AWS, Azure, GCP, DigitalOcean credentials
    - Certificates: RSA, OpenSSH, EC, PGP private keys

- **New dependency**: `aho-corasick` 1.x for multi-pattern literal matching

### Changed

- `Sanitizer::sanitize()` now returns `Cow<'a, str>` instead of `String` for zero-copy optimization
- Added `Sanitizer::sanitize_to_string()` for backward compatibility
- Added `Sanitizer::pattern_count()` method
- Patterns are now ordered by specificity (specific markers like `[GITHUB_PAT_REDACTED]` before generic `[REDACTED]`)

### Performance

| Scenario | Before (v0.9) | After (v1.0) |
|----------|---------------|--------------|
| No secrets detected | O(n × 7 patterns) | **Zero-copy** (borrowed) |
| With secrets (<512KB) | O(n × 7) | O(n × matched patterns only) |
| Large output (>512KB) | Sequential | **Parallel (Rayon chunks)** |

## [0.9.0] - 2026-01-29

### Added

- **New MCP Tool**:
  - `ssh_metrics_multi`: Collect system metrics from multiple hosts in parallel
    - Uses rayon for parallel parsing of results
    - Same metrics as `ssh_metrics`: cpu, memory, disk, network, load
    - Supports `fail_fast` option to stop on first failure
    - Returns aggregated results with per-host success/failure status

### Changed

- **Dependencies**:
  - Added `rayon` 1.10 for data parallelism in multi-host metrics parsing
  - Updated `clap` to 4.5.56

- **Documentation Updates**:
  - Updated tool count from 13 to 14 tools
  - Added `ssh_metrics_multi` documentation to README

## [0.8.0] - 2026-01-29

### Added

- **New MCP Tool**:
  - `ssh_health`: Diagnostic tool providing internal state information (connection pool stats, active sessions, command history, configuration summary)

- **Code Quality Improvements**:
  - Added `#[must_use]` attributes to important functions returning values that should be used
  - Added `# Errors` documentation sections to all public functions returning `Result`
  - Made appropriate functions `const fn` for compile-time evaluation
  - Used `mul_add` for floating-point multiply-add operations (rate limiter)

### Changed

- **Documentation Updates**:
  - Updated feature flags documentation (removed deprecated `audit`, added `mimalloc`)
  - Updated tool count from 12 to 13 tools
  - Added `ssh_health` documentation to tool handlers README
  - Added hot-reload documentation to security module README

### Fixed

- **Config Watcher Panic Risk**: Replaced `.expect()` with proper error handling when creating tokio runtime for config reload
- **Clippy Pedantic/Nursery Compliance**: Fixed all warnings from `clippy::pedantic` and `clippy::nursery` lints:
  - Replaced `match` with `map_or`/`map_or_else` idioms
  - Fixed `future_not_send` warnings by adding `+ Send` to callback types
  - Added `#[allow]` attributes for `significant_drop_tightening` where appropriate
  - Fixed `option_if_let_else` warnings in test code

## [0.7.0] - 2026-01-28

### Added

- **New MCP Tools**:
  - `ssh_tail`: Read last N lines of remote files with optional grep filtering
  - `ssh_metrics`: Collect system metrics (CPU, memory, disk, network, load) as structured JSON
  - `ssh_exec_multi`: Execute commands in parallel across multiple hosts with fail-fast option

- **Persistent Shell Sessions**:
  - `ssh_session_create`: Create persistent interactive shell with cwd/env state
  - `ssh_session_exec`: Execute commands in existing session (maintains state)
  - `ssh_session_list`: List active sessions with metadata (age, idle time)
  - `ssh_session_close`: Close and cleanup sessions
  - Configurable max sessions, idle timeout, and max age
  - Automatic zombie session cleanup on channel failure

- **MCP Resources**:
  - Resource registry with URI-based resolution
  - `hosts://list` and `hosts://{name}/config`: Host configuration resources
  - `security://policy` and `security://blacklist`: Security policy resources

### Fixed

- **Session Zombie Cleanup**: Dead sessions are now removed from the session
  manager when the shell channel fails (exit, crash, or timeout)
- **Empty Command Validation**: Empty or whitespace-only commands are now
  rejected with `CommandDenied` error instead of being sent to the remote host
- **Blacklist Pattern Improvement**: `rm` blacklist pattern now catches all
  dangerous variants (`rm -r`, `rm -fr`, `rm --recursive`, `rm --force`)
  instead of only `rm -rf`

## [0.6.0] - 2026-01-27

### Added

- **Smart Output Truncation**: Head+tail truncation for large command outputs
  - New `output_truncator` module in domain layer (`src/domain/output_truncator.rs`)
  - Keeps 20% from start (context) + 80% from end (results), cuts at line boundaries
  - Default limit: 20,000 characters (configurable via `max_output_chars`)
  - `max_output` parameter on `ssh_exec` tool (0 = disabled)
  - Truncation message: `[truncated: X lines total, Y lines omitted, A → B chars]`

## [0.5.0] - 2026-01-27

### Fixed

- **SFTP Jump Host Support**: Upload and download handlers now correctly route
  through bastion/proxy hosts when `proxy_jump` is configured
  - Extracted `connect_with_jump()` utility in `utils.rs`
  - Both `ssh_upload` and `ssh_download` use the same jump host resolution as `ssh_exec`

## [0.4.0] - 2026-01-27

### Changed

- **Build Optimizations**: Release profile tuned for smaller/faster binaries
  - `panic = "abort"`, LTO, single codegen unit
  - mimalloc allocator for better memory performance
  - Optimized tokio feature flags

## [0.3.0] - 2026-01-26

### Added

- Complete documentation for v0.2.0 features:
  - Updated CHANGELOG, README, and module READMEs
  - Documented RateLimiter (Token Bucket algorithm)
  - Documented async AuditLogger with AuditWriterTask
  - Documented ConfigWatcher for hot-reload
  - Documented concurrent MCP request handling architecture

### Fixed

- v0.2.0 release was incomplete (missing documentation commit)

## [0.2.0] - 2026-01-26

### Added

- **Async Audit Logging**: Non-blocking audit writes using tokio mpsc channels
  - Background file writing with `spawn_blocking` to avoid blocking async runtime
  - `AuditWriterTask` for dedicated audit file writer
  - Tracing logs remain synchronous for fast structured logging

- **Per-Host Rate Limiting**: Token Bucket algorithm implementation
  - Configurable via `limits.rate_limit_per_second` (0 = disabled)
  - Independent rate limits per host
  - Protects against accidental command flooding

- **Hot-Reload Infrastructure**: Configuration file watching
  - `ConfigWatcher` using notify crate (v8.2) for file change detection
  - `Arc<RwLock<Config>>` for thread-safe config updates
  - Ready for future server integration

- **Concurrent Request Handling**: MCP server processes requests in parallel
  - Worker pool limited by `max_concurrent_commands`
  - Semaphore-based concurrency control
  - Single writer task for stdout serialization

### Changed

- `AuditLogger::new()` now returns `(AuditLogger, Option<AuditWriterTask>)` tuple
- `McpServer::new()` now returns `(McpServer, Option<AuditWriterTask>)` tuple
- `McpServer::run()` now takes `Arc<Self>` and `audit_task` parameter
- `McpServer.initialized` is now `AtomicBool` for thread-safe access

## [0.1.0] - 2025-01-25

### Added

- Initial release
- MCP server mode (JSON-RPC over stdio) for Claude Code integration
- CLI mode with subcommands:
  - `exec` - Execute remote commands
  - `status` - Show configured hosts
  - `history` - View command history
  - `upload` - Upload files via SSH
  - `download` - Download files via SSH
- Security features:
  - Command whitelist/blacklist validation
  - Output sanitization (password/secret masking)
  - Audit logging
- SSH connection pooling with retry logic
- Multiple authentication methods: SSH key, agent, password
- Host key verification modes (strict/accept-new/off)
- Hexagonal architecture (ports & adapters)
- Extensible tool handler registry (Open/Closed principle)

[Unreleased]: https://github.com/muchini/mcp-ssh-bridge/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/muchini/mcp-ssh-bridge/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.9.0...v2.0.0
[1.9.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.8.3...v1.9.0
[1.8.3]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.8.2...v1.8.3
[1.8.2]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/muchini/mcp-ssh-bridge/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/muchini/mcp-ssh-bridge/releases/tag/v0.1.0
