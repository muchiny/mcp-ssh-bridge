# Configuration

Configuration files for MCP SSH Bridge.

## Location

Configuration is loaded from:

```
~/.config/mcp-ssh-bridge/config.yaml
```

Or specified via `--config`:

```bash
mcp-ssh-bridge --config /path/to/config.yaml
```

## Structure

The configuration file has four main sections:

- **hosts** - SSH host definitions (hostname, port, user, auth, etc.)
- **security** - Command validation rules (mode, whitelist, blacklist)
- **limits** - Timeouts, output limits, retry settings
- **audit** - Audit logging configuration

## Quick Start

```bash
mkdir -p ~/.config/mcp-ssh-bridge
cp config/config.example.yaml ~/.config/mcp-ssh-bridge/config.yaml
vim ~/.config/mcp-ssh-bridge/config.yaml
```

## Minimal Example

```yaml
hosts:
  my-server:
    hostname: "192.168.1.100"
    user: "admin"
    auth:
      type: key
      path: "~/.ssh/id_ed25519"

security:
  mode: strict
  whitelist:
    - "^ls\\b"
    - "^cat\\b"
    - "^docker\\s+"
```

## Authentication Methods

### SSH Key (recommended)

```yaml
auth:
  type: key
  path: "~/.ssh/id_ed25519"
  passphrase: "optional"  # only if the key is passphrase-protected
```

### SSH Agent (recommended)

```yaml
auth:
  type: agent
```

Requires `SSH_AUTH_SOCK` environment variable (Unix only).

### Password (not recommended)

```yaml
auth:
  type: password
  password: "secret"
```

## Host Key Verification

| Mode | Unknown host | Key changed | Use case |
|------|-------------|-------------|----------|
| `strict` (default) | Rejected | Rejected | Production |
| `acceptnew` | Auto-added | Rejected | First-time setup |
| `off` | Accepted | Accepted | Testing only |

```yaml
host_key_verification: strict  # default
```

## Jump Hosts

Connect to internal hosts via a bastion server:

```yaml
hosts:
  bastion:
    hostname: bastion.example.com
    user: admin
    auth:
      type: agent

  internal-db:
    hostname: 10.0.0.5
    user: deploy
    proxy_jump: bastion
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

## SOCKS Proxy

Alternative to jump hosts. `proxy_jump` and `socks_proxy` are mutually exclusive.

```yaml
hosts:
  remote-via-proxy:
    hostname: 10.0.0.5
    user: deploy
    socks_proxy:
      hostname: proxy.example.com
      port: 1080
      version: socks5
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

## Windows Hosts

```yaml
hosts:
  windows-dc:
    hostname: 192.168.1.200
    user: Administrator
    os_type: windows
    shell: powershell
    auth:
      type: key
      path: ~/.ssh/id_ed25519
```

## Security Modes

- **strict** (default): Only whitelisted commands are allowed. Blacklist is checked first.
- **permissive**: All commands are allowed except those matching the blacklist.

## Tool Groups

All 38 tool groups (197 tools) are enabled by default. Disable groups you don't need:

```yaml
tool_groups:
  groups:
    database: false
    terraform: false
    hyperv: false
```

## SSH Config Auto-Discovery

When enabled (default), hosts from `~/.ssh/config` are automatically imported. YAML-defined hosts take precedence.

```yaml
ssh_config:
  enabled: true
  exclude_patterns:
    - "*.internal"
```

## Validation

The configuration file is validated on load:

- At least one host must be defined
- `hostname` and `user` must not be empty
- SSH key files must exist (for key auth)
- Regex patterns must be valid (invalid patterns are skipped with a warning)

## Testing

```bash
mcp-ssh-bridge status         # verify config loads and list hosts
mcp-ssh-bridge exec my-server "echo test"  # test a connection
```

## Full Reference

See `config.example.yaml` for all available options with comments.
