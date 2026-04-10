---
description: Prefer CLI over MCP for ssh-bridge remote operations
globs: **/*
---

# SSH Bridge: Prefer CLI over MCP

When the user asks to manage remote hosts (Raspberry Pi, servers, containers, etc.),
**prefer the CLI via Bash** over the MCP tools for token efficiency (10-32x savings).

## CLI Quick Reference

```bash
# Discovery (progressive, token-efficient)
mcp-ssh-bridge list-tools --groups-only          # 74 groups (~2K tokens)
mcp-ssh-bridge list-tools --group <group>        # tools in group (~500 tokens)
mcp-ssh-bridge list-tools --search <keyword>     # keyword search
mcp-ssh-bridge describe-tool <tool_name>         # full schema (~200 tokens)

# Execution
mcp-ssh-bridge tool <tool_name> key=value ...    # invoke tool
mcp-ssh-bridge tool <tool_name> --json-args '{}' # JSON input
mcp-ssh-bridge --json tool <tool_name> ...       # JSON output

# Direct commands
mcp-ssh-bridge exec <host> "<command>"           # raw SSH exec
mcp-ssh-bridge status                            # host connectivity
mcp-ssh-bridge upload <host> <local> <remote>    # SFTP upload
mcp-ssh-bridge download <host> <remote> <local>  # SFTP download

# Configuration
mcp-ssh-bridge validate                          # validate config
mcp-ssh-bridge config-diff                       # compare vs defaults
```

## Workflow

1. Always run `mcp-ssh-bridge status` first to verify connectivity
2. Use `--json` when parsing output programmatically
3. Use `jq_filter` or `columns` params to reduce output size
4. Use `--dry-run` for destructive operations

## When to fall back to MCP tools

- CLI binary not built (`target/release/mcp-ssh-bridge` missing)
- User explicitly asks to use MCP tools
- Persistent sessions or output caching (MCP-only features)
