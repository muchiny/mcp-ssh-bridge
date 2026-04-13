---
name: discover
description: |
  Use when the user wants to explore available tools, find tools by category,
  or learn what mcp-ssh-bridge can do. Progressive discovery workflow.
user-invocable: true
argument-hint: "[group-name|search-term]"
---

# Tool Discovery -- Progressive Exploration

Explore the 338 tools across 74 groups available in mcp-ssh-bridge.

## No arguments -- show all groups

!`mcp-ssh-bridge list-tools --groups-only`

Ask which group interests the user, or suggest searching by keyword.

## Group name provided

!`mcp-ssh-bridge list-tools --group $ARGUMENTS`

For each tool shown, the user can ask for details:
!`mcp-ssh-bridge describe-tool <tool_name>`

The `describe-tool` output includes a **Reduction Strategy** line at the top
telling you which params (jq_filter, columns, limit, etc.) apply for token-efficient output.

## Search term provided

!`mcp-ssh-bridge list-tools --search $ARGUMENTS`

## Tips for the user

- **74 groups**: docker, kubernetes, systemd, networking, firewall, packages, users, cron, logs, files, etc.
- **Token-efficient**: always use `columns`, `limit`, or `jq_filter` params to reduce output
- **13 protocols**: SSH, WinRM, Telnet, K8s Exec, Serial, AWS SSM, Azure, GCP, ZeroMQ, NATS, MQTT, SNMP, NETCONF
