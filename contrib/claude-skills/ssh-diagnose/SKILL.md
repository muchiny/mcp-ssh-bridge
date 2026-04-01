---
name: ssh-diagnose
description: This skill should be used when the user asks to "debug my server", "why is prod slow", "check why a service is down", "diagnose disk full", "server is unresponsive", or mentions troubleshooting remote server issues like CPU, memory, disk, or network problems.
argument-hint: <host> [symptom]
compatibility: "2.1+"
---

# Server Diagnostics

Systematically diagnose issues on a remote server using mcp-ssh-bridge CLI.

**Delegation**: Use a general-purpose agent (via the Agent tool) to run these commands in isolation, so verbose diagnostic output does not pollute the main conversation.

Parse `$ARGUMENTS`: first word = host, second word (optional) = symptom (slow, crash, oom, disk, network).

## Phase 1 — Quick Health Overview

Always start here. One command collects uptime, CPU, memory, disk, processes, failed services, and recent errors:

```bash
mcp-ssh-bridge tool ssh_diagnose host=HOST --json
```

If a specific symptom was provided, also run adaptive triage:

```bash
mcp-ssh-bridge tool ssh_incident_triage host=HOST symptom=SYMPTOM --json
```

Valid symptoms: `slow`, `crash`, `oom`, `disk`, `network`

## Phase 2 — Targeted Investigation

Based on Phase 1 findings, drill into the specific problem area.

### High CPU / Slow
```bash
mcp-ssh-bridge tool ssh_process_top host=HOST --json
mcp-ssh-bridge tool ssh_metrics host=HOST --json
```

### Out of Memory
```bash
mcp-ssh-bridge tool ssh_exec host=HOST command="free -h && cat /proc/meminfo | head -20"
mcp-ssh-bridge tool ssh_process_top host=HOST --json
```

### Disk Full
```bash
mcp-ssh-bridge tool ssh_disk_usage host=HOST --json
mcp-ssh-bridge tool ssh_exec host=HOST command="df -h && df -i"
mcp-ssh-bridge tool ssh_exec host=HOST command="du -sh /* 2>/dev/null | sort -rh | head -10"
```

### Service Down
```bash
mcp-ssh-bridge tool ssh_service_list host=HOST --json
mcp-ssh-bridge tool ssh_service_logs host=HOST service=SERVICE_NAME lines=100
```

### Network Issues
```bash
mcp-ssh-bridge tool ssh_net_connections host=HOST --json
mcp-ssh-bridge tool ssh_net_interfaces host=HOST --json
mcp-ssh-bridge tool ssh_exec host=HOST command="ss -tlnp"
```

## Phase 3 — Log Analysis

Check recent system logs for errors:

```bash
mcp-ssh-bridge tool ssh_exec host=HOST command="journalctl -p err --since '1 hour ago' --no-pager | tail -50"
```

For a specific service:

```bash
mcp-ssh-bridge tool ssh_service_logs host=HOST service=SERVICE_NAME lines=200
```

## Phase 4 — Report

Produce a structured diagnostic report with:

1. **Status**: healthy / degraded / critical
2. **Root Cause**: what is actually wrong (be specific)
3. **Evidence**: relevant metrics and log excerpts
4. **Recommendation**: concrete next steps to fix
5. **Urgency**: immediate / soon / monitor

See [playbooks.md](playbooks.md) for symptom-specific investigation workflows.
