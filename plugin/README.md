# MCP SSH Bridge -- Claude Code Plugin

This plugin integrates [mcp-ssh-bridge](https://github.com/muchiny/mcp-ssh-bridge) into Claude Code, giving you access to **357 tools** for managing remote servers via SSH.

## Prerequisites

Install the mcp-ssh-bridge binary:

```bash
cargo install mcp-ssh-bridge
```

Then configure at least one host in `~/.config/mcp-ssh-bridge/config.yaml`:

```yaml
hosts:
  my-server:
    hostname: 192.168.1.100
    port: 22
    user: admin
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

## What's included

### MCP Server

The plugin registers `mcp-ssh-bridge` as an MCP server, exposing all 357 tools
directly to Claude Code for remote server management.

### Skills

| Skill | Description |
|-------|-------------|
| `/mcp-ssh-bridge:bridge` | Manage remote hosts -- status, config, tool execution |
| `/mcp-ssh-bridge:discover` | Explore 357 tools across 75 groups with progressive discovery |

### Capabilities

- **Linux** (60 groups): systemd, Docker, Kubernetes, networking, filesystems, logs, packages, users, cron, firewall, etc.
- **Windows** (13 groups): PowerShell, services, registry, IIS, Active Directory, EventLog, etc.
- **9 protocols**: SSH, WinRM, PSRP, Telnet, K8s Exec, Serial, AWS SSM, Azure, GCP
- **Token-efficient**: server-side output filtering (jq/yq, columns, limit, pagination)
- **Secure**: command validation, input sanitization, rate limiting, audit logging

## Links

- [GitHub](https://github.com/muchiny/mcp-ssh-bridge)
- [crates.io](https://crates.io/crates/mcp-ssh-bridge)
- [docs.rs](https://docs.rs/mcp-ssh-bridge)
- [Configuration reference](https://github.com/muchiny/mcp-ssh-bridge/blob/main/config/config.example.yaml)
