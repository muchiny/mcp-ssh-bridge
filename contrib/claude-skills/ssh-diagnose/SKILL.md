---
name: ssh-diagnose
description: Diagnose remote server issues — health checks, service failures, disk/memory/CPU problems, network issues. Use when debugging slow, unresponsive, or failing servers.
context: fork
agent: general-purpose
argument-hint: <host> [symptom]
---

# Server Diagnostics

Systematically diagnose issues on a remote server using mcp-ssh-bridge CLI.
Runs in a forked agent to avoid polluting the main conversation with verbose output.

**Host:** `$0` (first argument)
**Symptom:** `$1` (optional: slow, crash, oom, disk, network)

## Phase 1 — Quick Health Overview

Always start here. One command collects uptime, CPU, memory, disk, processes, failed services, and recent errors:

```bash
mcp-ssh-bridge tool ssh_diagnose host=$0 --json
```

If a specific symptom was provided, also run adaptive triage:

```bash
mcp-ssh-bridge tool ssh_incident_triage host=$0 symptom=$1 --json
```

Valid symptoms: `slow`, `crash`, `oom`, `disk`, `network`

## Phase 2 — Targeted Investigation

Based on Phase 1 findings, drill into the specific problem area.

### High CPU / Slow
```bash
mcp-ssh-bridge tool ssh_process_top host=$0 --json
mcp-ssh-bridge tool ssh_metrics host=$0 --json
```

### Out of Memory
```bash
mcp-ssh-bridge tool ssh_exec host=$0 command="free -h && cat /proc/meminfo | head -20"
mcp-ssh-bridge tool ssh_process_top host=$0 --json
```

### Disk Full
```bash
mcp-ssh-bridge tool ssh_disk_usage host=$0 --json
mcp-ssh-bridge tool ssh_exec host=$0 command="df -h && df -i"
mcp-ssh-bridge tool ssh_exec host=$0 command="du -sh /* 2>/dev/null | sort -rh | head -10"
```

### Service Down
```bash
mcp-ssh-bridge tool ssh_service_list host=$0 --json
mcp-ssh-bridge tool ssh_service_logs host=$0 service=SERVICE_NAME lines=100
```

### Network Issues
```bash
mcp-ssh-bridge tool ssh_net_connections host=$0 --json
mcp-ssh-bridge tool ssh_net_interfaces host=$0 --json
mcp-ssh-bridge tool ssh_exec host=$0 command="ss -tlnp"
```

## Phase 3 — Log Analysis

Check recent system logs for errors:

```bash
mcp-ssh-bridge tool ssh_exec host=$0 command="journalctl -p err --since '1 hour ago' --no-pager | tail -50"
```

For a specific service:

```bash
mcp-ssh-bridge tool ssh_service_logs host=$0 service=SERVICE_NAME lines=200
```

## Phase 4 — Report

Produce a structured diagnostic report with:

1. **Status**: healthy / degraded / critical
2. **Root Cause**: what is actually wrong (be specific)
3. **Evidence**: relevant metrics and log excerpts
4. **Recommendation**: concrete next steps to fix
5. **Urgency**: immediate / soon / monitor

See [playbooks.md](playbooks.md) for symptom-specific investigation workflows.
