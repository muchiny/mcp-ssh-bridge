---
name: ssh-ops
description: Remote server operations via mcp-ssh-bridge CLI. Use when managing infrastructure, SSH hosts, Docker, K8s, services, files, or running remote commands. Always prefer CLI over MCP for token efficiency.
argument-hint: [tool-name|group|search-term]
---

# Remote Infrastructure Operations

You have access to **337 tools** via the `mcp-ssh-bridge` CLI for managing remote servers over SSH.

## Golden Rule

**ALWAYS use the CLI** (`mcp-ssh-bridge tool ...` via Bash) instead of MCP tools.
CLI saves 10-32x tokens compared to MCP by loading schemas on-demand.

## Progressive Discovery Workflow

When you need a tool but don't know its exact name, follow these steps:

### Step 1 — Browse groups (~2K tokens)
```bash
mcp-ssh-bridge list-tools --groups-only
```

### Step 2 — Explore a group (~500 tokens)
```bash
mcp-ssh-bridge list-tools --group docker
```

### Step 3 — Get tool schema (~200 tokens)
```bash
mcp-ssh-bridge describe-tool ssh_docker_ps
```

### Step 4 — Invoke the tool
```bash
mcp-ssh-bridge tool ssh_docker_ps host=myserver --json
```

You can also search by keyword: `mcp-ssh-bridge list-tools --search kubernetes`

## Syntax Reference

```bash
# key=value arguments (auto type-coerced)
mcp-ssh-bridge tool ssh_exec host=prod command="df -h"

# Complex/nested args via JSON
mcp-ssh-bridge tool ssh_k8s_get --json-args '{"host":"k8s","resource":"pods","namespace":"default"}'

# JSON output for reliable parsing
mcp-ssh-bridge tool ssh_docker_ps host=prod --json

# Global JSON flag (works on all commands)
mcp-ssh-bridge --json status

# Aliases: t = tool, dt = describe-tool
mcp-ssh-bridge t ssh_exec host=prod command="whoami"
mcp-ssh-bridge dt ssh_docker_ps
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success | Continue |
| 1 | Command failed on remote host | Check stderr, retry or escalate |
| 2 | Unknown tool or bad arguments | Use `describe-tool` to check schema |
| 3 | SSH connection failure | Verify host config, network |
| 4 | Security denial (blocked by policy) | Command not allowed, inform user |
| 5 | Configuration error | Check config.yaml |

## Group Quick Reference

| Category | Groups |
|----------|--------|
| **Core** | core, file_ops, file_transfer, directory, process, monitoring, sessions |
| **System** | systemd, systemd_timers, firewall, package, cron, user_management, storage, journald |
| **Containers** | docker, podman, kubernetes, esxi |
| **Databases** | database, redis, postgresql, mysql, mongodb |
| **Web** | nginx, apache, letsencrypt, certificates |
| **IaC** | ansible, terraform, vault, git |
| **Security** | security_scan, network_security, compliance, security_modules |
| **Observability** | diagnostics, performance, container_logs, cron_analysis, drift |
| **Cloud** | cloud, inventory, multicloud |
| **Ops** | orchestration, runbooks, alerting, capacity, incident, log_aggregation |
| **Config** | templates, config, recording, key_management, chatops, tunnels |
| **Network** | network, network_equipment, ldap, backup |
| **Windows** | windows_services, windows_events, active_directory, scheduled_tasks, windows_firewall, iis, windows_updates, windows_perf, hyperv, windows_registry, windows_features, windows_network, windows_process |
| **Interactive** | pty |

## Top 10 Most-Used Commands

```bash
# Execute arbitrary command
mcp-ssh-bridge t ssh_exec host=HOST command="COMMAND"

# System health overview (single call, collects everything)
mcp-ssh-bridge t ssh_diagnose host=HOST

# Docker containers
mcp-ssh-bridge t ssh_docker_ps host=HOST all=true

# Service status
mcp-ssh-bridge t ssh_service_status host=HOST service=nginx

# Read a remote file
mcp-ssh-bridge t ssh_file_read host=HOST path=/etc/nginx/nginx.conf

# Check disk usage
mcp-ssh-bridge t ssh_disk_usage host=HOST

# Kubernetes pods
mcp-ssh-bridge t ssh_k8s_get host=HOST resource=pods namespace=default

# Recent logs
mcp-ssh-bridge t ssh_service_logs host=HOST service=myapp lines=50

# Process list (top consumers)
mcp-ssh-bridge t ssh_process_top host=HOST

# Network connections
mcp-ssh-bridge t ssh_net_connections host=HOST
```

## Best Practices

1. **Use `--json`** when you need to parse output programmatically
2. **Use `ssh_diagnose`** first for troubleshooting — it collects everything in one SSH call
3. **Use `ssh_exec`** as fallback for any command not covered by specialized tools
4. **Check exit code** to determine success/failure without parsing output
5. **Use `describe-tool --json`** to get the exact schema before invoking unfamiliar tools
