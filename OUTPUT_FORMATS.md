# Output Formats Strategy

> How MCP SSH Bridge formats tool results for optimal LLM token efficiency.
>
> **Aligned with production best practices 2026** (pgEdge, Axiom, Anthropic).

## Why This Matters

JSON wrapping of command output adds token overhead through key repetition, escaping of `\n`/`\t`/`"`, and structural characters (`{}`, `""`). Research shows:

- **TSV uses 30-40% fewer tokens** than JSON for tabular data ([pgEdge MCP Server](https://www.pgedge.com/blog/lessons-learned-writing-an-mcp-server-for-postgresql))
- **Plain text uses ~80% fewer tokens** than JSON for free-form output ([Axiom MCP Design](https://axiom.co/blog/designing-mcp-servers-for-wide-events))
- LLMs parse TSV and plain text **as well or better** than JSON ([TOON benchmarks](https://toonformat.dev/guide/benchmarks))

## Format by Category

### Category A: Standard Command Output (~220 tools)

**Tools:** All `StandardToolHandler` tools without `post_process` override.
**Examples:** `ssh_file_read`, `ssh_git_status`, `ssh_service_restart`, `ssh_k8s_logs`, etc.

**Format:**

| Condition | Format | Example |
|-----------|--------|---------|
| Success (exit_code=0, no stderr) | Raw stdout | `On branch main\nnothing to commit` |
| Success with warnings (exit_code=0, stderr present) | stdout + separator + stderr | `output...\n[stderr]\nwarning: something` |
| Error (exit_code != 0) | Prefixed error | `[exit:127]\ncommand not found` |

**Rationale:** Zero overhead on success. The AI already knows the host and command (it sent them as arguments). Exit code is only surfaced when non-zero.

### Category B: Tabular Output (6 tools)

**Tools:** `ssh_docker_ps`, `ssh_docker_stats`, `ssh_process_list`, `ssh_service_list`, `ssh_k8s_get`, `ssh_k8s_top`

**Format:** TSV (tab-separated values) + MCP App Table component

```
NAMES	IMAGE	STATUS	PORTS
web	nginx:latest	Up 2 hours	0.0.0.0:80->80/tcp
cache	redis:7	Up 3 hours	6379/tcp
```

The `content[0]` is TSV text (for AI consumption), and `content[1]` is an interactive App Table (for UI rendering with actions like Logs, Inspect, Refresh).

**Rationale:** TSV eliminates repeated keys that JSON would add per row. For a 50-row result, this saves ~30-40% tokens (pgEdge benchmark). The columnar parser (`parse_columnar_output`) converts raw command output to clean TSV.

### Category C: Custom Handlers with Command Output (4 tools)

**Tools:** `ssh_exec`, `ssh_tail`, `ssh_find`, `ssh_disk_usage`

**Format:** Same as Category A (raw stdout on success, prefixed error).

**Rationale:** These tools have custom `execute()` but still run SSH commands and return stdout/stderr. Same rules apply.

### Category D: Structured Data (11 tools)

**Tools:** `ssh_ls`, `ssh_session_create/list/exec/close`, `ssh_tunnel_create/list/close`, `ssh_exec_multi`

**Format:** Compact JSON (no pretty-printing)

```json
[{"session_id":"s-001","host":"server1","cwd":"/home","age_seconds":120}]
```

**Rationale:** These tools build their own structured data (not raw command output). JSON is the natural format for objects with typed fields. No `to_string_pretty` — compact JSON saves ~20% tokens vs pretty-printed.

### Category E: Dashboards and Status (5 tools)

**Tools:** `ssh_metrics`, `ssh_metrics_multi`, `ssh_status`, `ssh_history`, `ssh_config_get`

**Format:** Unchanged (JSON metrics + Dashboard App, or plain text status).

**Rationale:** Metrics tools return parsed structured data + dashboard UI component. Status/history tools already return plain text.

## Guide for Contributors

When adding a new tool:

1. **Does it run a command and return stdout?** → Category A (automatic via `StandardToolHandler`)
2. **Does the command produce columnar/tabular output?** → Category B (add `post_process` with `parse_columnar_output` + `to_tsv()`)
3. **Does it build its own data structure?** → Category D (use `serde_json::to_string()`)
4. **Does it need a UI component?** → Add `.with_app(table(...).build())` or `.with_app(dashboard(...).build())`

### Never Do

- Wrap stdout in JSON for standard commands (`{"stdout":"..."}` wastes tokens)
- Use `to_string_pretty` (adds whitespace tokens for no LLM benefit)
- Include host/command in the result (the AI sent them as arguments, it knows)
- Include `structured_content` duplicating the text content

### Always Do

- Return the most compact format possible for the data type
- Use TSV for tabular data (header + tab-separated rows)
- Surface exit_code only on errors (`[exit:N]` prefix)
- Surface stderr only when non-empty
- Use `parse_columnar_output()` + `to_tsv()` for columnar command output

## References

- [pgEdge: Lessons Learned Writing an MCP Server for PostgreSQL](https://www.pgedge.com/blog/lessons-learned-writing-an-mcp-server-for-postgresql) — TSV format, 30-40% token savings
- [Axiom: Designing MCP servers for wide schemas](https://axiom.co/blog/designing-mcp-servers-for-wide-events) — CSV format, cell budget, compact-first design
- [Speakeasy: Reducing MCP token usage by 100x](https://www.speakeasy.com/blog/how-we-reduced-token-usage-by-100x-dynamic-toolsets-v2) — Dynamic toolsets
- [TOON Benchmarks](https://toonformat.dev/guide/benchmarks) — Format comparison data
- [Anthropic: Advanced Tool Use](https://www.anthropic.com/engineering/advanced-tool-use) — Programmatic Tool Calling
- [10 Strategies to Reduce MCP Token Bloat](https://thenewstack.io/how-to-reduce-mcp-token-bloat/) — Industry overview
