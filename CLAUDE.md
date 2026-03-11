# CLAUDE.md

## Project Overview

MCP SSH Bridge is a Rust MCP server that enables Claude Code to securely execute commands on air-gapped environments via SSH. JSON-RPC over stdio, strict security controls. **197 tools** across **38 groups** (25 Linux, 13 Windows).

## Build Commands

```bash
make build              # Debug build
make release            # Optimized release build with LTO
make test               # Run tests (uses nextest if available)
make lint               # Run clippy with strict warnings
make ci                 # Quick CI (fmt-check, lint, test, audit, typos)
make ci-full            # Full CI (ci + hack + geiger)
make release-pipeline   # Full release (ci-full + release-all + docker-scan)
make deps-check         # Check outdated/unused deps
make help               # Show all available targets
```

## Architecture Hexagonale (Ports & Adapters)

```
┌─────────────────────────────────────────────────────────────┐
│                    ADAPTERS (Externe)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ MCP Adapter │  │ SSH Adapter │  │ Config YAML Adapter │  │
│  │ (JSON-RPC)  │  │  (russh)    │  │  (serde-saphyr)    │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
└─────────┼────────────────┼────────────────────┼─────────────┘
          │                │                    │
          ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                      PORTS (Traits)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ToolHandler  │  │ SshExecutor │  │  ConfigProvider     │  │
│  │   trait     │  │   trait     │  │      trait          │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
└─────────┼────────────────┼────────────────────┼─────────────┘
          │                │                    │
          ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                    DOMAIN (Core Logic)                       │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    Use Cases                         │    │
│  │  ExecuteCommand │ ValidateCommand │ SanitizeOutput  │    │
│  └─────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    Entities                          │    │
│  │   Command │ CommandResult │ SecurityPolicy │ Host    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
src/
├── main.rs, lib.rs, error.rs    # Entry point, exports, errors
├── cli/                          # CLI (feature-gated: clap)
├── config/                       # YAML config loading
├── domain/                       # Pure business logic (use cases, builders)
├── ports/                        # Traits (SshExecutor, ToolHandler, ConfigProvider)
├── mcp/                          # MCP protocol adapter + tool_handlers/
├── ssh/                          # SSH client adapter (russh)
└── security/                     # Validation, sanitization, rate limiting
```

## Feature Flags

```toml
default = ["cli"]
cli = ["dep:clap"]       # CLI binary (disable for lib-only)
mimalloc = ["dep:mimalloc"]
```

## Key Principles

1. **Ports (Traits)**: Define interfaces (`SshExecutor`, `ToolHandler`)
2. **Adapters**: Implement ports (russh, JSON-RPC, YAML)
3. **Domain**: Pure business logic, no external dependencies
4. **Use Cases**: Orchestrate: validation -> execution -> sanitization -> audit
5. **Tool Registry**: Open/Closed pattern for adding tools

## Code Quality

- `#![forbid(unsafe_code)]`
- Clippy with `-D warnings` (all lint groups enabled)
- rustfmt 100 char line width
- cargo-deny for security/license checks

## Configuration

YAML config at `~/.config/mcp-ssh-bridge/config.yaml`. See `config/config.example.yaml`.
Key sections: `hosts`, `security`, `limits`, `audit`, `tool_groups`.

## Known Advisories

RUSTSEC-2023-0071 (Marvin Attack on RSA) ignored — transitive dep from russh, no upstream fix, safe for local CLI.

## Path-Scoped Rules

Detailed guidance is loaded automatically via `.claude/rules/`:
- `tool-handlers.md` — Adding tools, handler pattern, clippy pitfalls
- `domain-builders.md` — Domain layer purity, builder conventions
- `security.md` — Security model, blacklist, sanitization
- `registry.md` — Test count assertions, clippy attributes
- `ssh-adapter.md` — Host keys, auth, connection pool, retry
- `testing.md` — Standard tests, fuzz, coverage, mutation
