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

### Token-efficient invocation

ALWAYS run `describe-tool` before invoking a tool you haven't used recently —
its schema (with `RECOMMENDED:` hints) lists which reduction params apply
and costs ~200 tokens:

```bash
mcp-ssh-bridge describe-tool <tool_name>
```

Apply the right reduction strategy based on the tool's **Reduction
Strategy** line (shown at the top of describe-tool output):

| Output kind | Strategy | Example |
|---|---|---|
| **Tabular** (docker_ps, service_list, process_list) | `columns` + `limit` | `columns='["NAME","STATUS"]' limit=20` |
| **Json** (k8s_get, docker_inspect, awx_*) | `jq_filter` + `output_format=tsv` | `jq_filter='.items[] \| [.metadata.name, .status.phase]' output_format=tsv` |
| **Yaml** | `yq_filter` + `output_format=tsv` | same shape as jq |
| **Auto** | Any of the above | tool auto-detects |
| **RawText** (logs, arbitrary exec) | `save_output=/tmp/out.txt` | read the file locally afterwards |

**Ergonomic global flags** (alternatives to `jq_filter=`, `columns=`, `limit=`):

```bash
mcp-ssh-bridge --jq '.items[] | {name, phase}' --output-format=tsv tool ssh_k8s_get host=k8s resource=pods
mcp-ssh-bridge --columns name,status --limit 10 tool ssh_docker_ps host=prod
```

**Pagination cycle** for truncated output:

1. A truncated result prints `[output_id: abc123]`
2. Fetch the rest: `mcp-ssh-bridge tool ssh_output_fetch output_id=abc123 offset=N`

**Common params on every tool**: `host`, `timeout_seconds`, `max_output`, `save_output`.

Prefer server-side `jq_filter` over piping CLI stdout through `jq` — the
filter runs BEFORE truncation, so you don't lose data to the cap.

### Workflow reminders

1. Verify connectivity with `status` before executing tools
2. Use `--json` output for structured parsing
3. Use `--dry-run` before destructive operations
4. Report results clearly with host name and command executed
5. Run `describe-tool` first on unknown tools — the schema tells you which
   reduction params apply and is ~200 tokens
6. Prefer `output_format=tsv` for list-style JSON — 60-80% fewer tokens than
   pretty JSON
