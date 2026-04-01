---
name: ssh-discover
description: Explore mcp-ssh-bridge tool catalog — browse 337 tools across 74 groups, search by keyword, view full schemas
argument-hint: [group-name|search-keyword]
---

# Tool Discovery

Explore the mcp-ssh-bridge tool catalog interactively.

**Argument:** `$ARGUMENTS`

## How to Explore

Run one of these depending on what was requested:

**No argument — show all groups:**
```bash
mcp-ssh-bridge list-tools --groups-only
```

**Group name — show tools in that group:**
```bash
mcp-ssh-bridge list-tools --group $ARGUMENTS
```

**Keyword — search by name or description:**
```bash
mcp-ssh-bridge list-tools --search $ARGUMENTS
```

After finding interesting tools, show their full schema:
```bash
mcp-ssh-bridge describe-tool TOOL_NAME
```

## Category Quick Reference

| Category | Groups to explore |
|----------|-------------------|
| Servers | core, process, monitoring, systemd, storage, journald |
| Files | file_ops, file_transfer, directory |
| Containers | docker, podman, kubernetes, esxi, hyperv |
| Databases | database, redis, postgresql, mysql, mongodb |
| Network | network, firewall, network_equipment, tunnels |
| Security | security_scan, network_security, compliance, certificates |
| Deploy | orchestration, runbooks, ansible, terraform |
| Cloud | cloud, inventory, multicloud, vault |
| Windows | windows_services, windows_events, active_directory, iis |

To invoke any discovered tool:
```bash
mcp-ssh-bridge tool TOOL_NAME host=HOST key=value --json
```
