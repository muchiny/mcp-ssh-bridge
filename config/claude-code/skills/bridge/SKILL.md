---
name: bridge
description: Use when the user says "bridge", "remote", "ssh tool", "run on host", "check host", "configure host", "setup bridge", or wants to manage remote servers or bridge config via CLI.
user-invocable: true
disable-model-invocation: false
argument-hint: "[tool|config|status] [args...]"
---

# SSH Bridge CLI — Remote Tool Execution and Configuration

Execute MCP tools on remote hosts or manage bridge configuration via the token-efficient CLI.

## Current state

Host status:
!`mcp-ssh-bridge status 2>/dev/null || echo "CLI binary not found — run 'make build' or 'cargo install --path .'"`

## Instructions

### No arguments or status

Show host status (above) and available tool groups:
!`mcp-ssh-bridge list-tools --groups-only`

Then ask the user what they want to do.

### Config mode

Help the user configure the bridge. Show current config state:

1. Config file location: `~/.config/mcp-ssh-bridge/config.yaml`
2. Validate current config:
   !`mcp-ssh-bridge validate 2>&1`
3. Show diff vs defaults:
   !`mcp-ssh-bridge config-diff 2>&1`

Then guide the user through configuration. The config file has these sections:

**Adding a host:**

```yaml
hosts:
  my-server:
    hostname: 192.168.1.100
    port: 22
    user: admin
    description: "My server"
    auth:
      type: key              # key | password | agent
      path: ~/.ssh/id_ed25519
    # os_type: windows       # for Windows hosts
    # shell: powershell      # for Windows: cmd (default) or powershell
    # proxy_jump: bastion    # connect through a jump host
```

**Security modes:**

```yaml
security:
  mode: standard     # strict = whitelist only | standard = whitelist for exec, blacklist for tools | permissive = blacklist only
  whitelist:
    - "^docker\\s+(ps|logs|inspect).*"   # regex patterns
  blacklist:
    - "rm\\s+(-[a-zA-Z]*r|--recursive)"  # always denied
  sanitize:
    enabled: true    # mask secrets in output (~50 builtin patterns)
```

**Filtering tool groups (reduce MCP context):**

```yaml
tool_groups:
  groups:
    docker: false       # disable docker tools
    kubernetes: false   # disable k8s tools
    # Set any of the 74 groups to false to disable
```

**SSH config auto-discovery:**

```yaml
ssh_config:
  enabled: true   # auto-import hosts from ~/.ssh/config
```

Reference: `config/config.example.yaml` has the full documented example.

### Config validate

Validate the configuration:
!`mcp-ssh-bridge validate 2>&1`

### Config diff

Compare current config with defaults:
!`mcp-ssh-bridge config-diff 2>&1`

### Tool group name (e.g., docker, kubernetes, systemd)

List tools in that group:
!`mcp-ssh-bridge list-tools --group $ARGUMENTS`

### Search query (no "=" in args, not a known subcommand)

Search tools by keyword:
!`mcp-ssh-bridge list-tools --search $ARGUMENTS`

### Tool name with key=value pairs

Execute the tool directly:
!`mcp-ssh-bridge --json tool $ARGUMENTS`

### Workflow reminders

1. Verify connectivity with `status` before executing tools
2. Use `--json` output for structured parsing
3. Use `--dry-run` before destructive operations
4. Report results clearly with host name and command executed
