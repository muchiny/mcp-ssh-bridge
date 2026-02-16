# Threat Model - MCP SSH Bridge

## Overview

MCP SSH Bridge is a Model Context Protocol (MCP) server that allows an AI client (Claude Code) to execute commands on remote hosts via SSH. It sits between the AI client and the SSH infrastructure, enforcing security controls on both inputs (commands) and outputs (results).

```
┌──────────────┐    JSON-RPC/stdio    ┌──────────────────┐      SSH       ┌──────────────┐
│  Claude Code  │◄───────────────────►│  MCP SSH Bridge  │◄──────────────►│  Remote Host │
│  (AI Client)  │                     │  (This Project)  │                │  (SSH Server)│
└──────────────┘                      └──────────────────┘                └──────────────┘
     Trusted                             Trust Boundary                      Semi-trusted
```

## STRIDE Analysis

### Spoofing

| Threat | Risk | Control | Status |
|--------|------|---------|--------|
| MITM on SSH connection | HIGH | Host key verification (Strict mode by default) | Covered |
| Rogue SSH server impersonation | HIGH | Known hosts database with StrictHostKeyChecking | Covered |
| Client impersonation | LOW | stdio transport (local process only) | Covered |

**Host Key Verification Modes:**

- **Strict** (default): Rejects unknown hosts and key changes
- **AcceptNew**: Accepts new hosts on first connect, rejects key changes
- **Off**: Accepts all keys (testing only, logged as warning)

### Tampering

| Threat | Risk | Control | Status |
|--------|------|---------|--------|
| Command injection via tool parameters | HIGH | Shell escaping (single-quote wrapping) in all 18 domain builders | Covered |
| Command injection via container/namespace names | HIGH | Shell escaping applied to all user-supplied identifiers | Covered |
| Path traversal in file operations | MEDIUM | `validate_path()` rejects `..` components | Covered |
| Path traversal in `save_output` | MEDIUM | `validate_path()` called before local file writes | Covered |
| SQL injection via database tools | MEDIUM | Shell escaping of query parameters, read-only default | Covered |
| Config tampering | LOW | YAML config read at startup, file permissions apply | Covered |

**Shell Escaping Strategy:**
All user-supplied parameters are wrapped in single quotes with internal single quotes escaped: `'user_input'`. This prevents shell metacharacter interpretation (`;`, `|`, `$()`, backticks, etc.).

### Repudiation

| Threat | Risk | Control | Status |
|--------|------|---------|--------|
| Untracked command execution | MEDIUM | AuditLogger logs all commands with timestamps | Covered |
| Audit log tampering | LOW | Append-only JSON-lines file, configurable path | Covered |
| Missing error logging | LOW | Both success and failure paths logged | Covered |

**Audit Logging:**

- Async JSON-lines format via mpsc channel
- Logs: timestamp, host, command, exit code, duration
- Configurable log path and rotation
- Sensitive data (passwords) never included in audit logs

### Information Disclosure

| Threat | Risk | Control | Status |
|--------|------|---------|--------|
| Secrets in command output | HIGH | Sanitizer with 50+ regex patterns (API keys, passwords, tokens, private keys) | Covered |
| Credentials in error messages | MEDIUM | Error types mask connection details | Covered |
| Sudo password in logs | LOW | Verified: original command (no password) passed to audit, not the sudo-wrapped command | Covered (verified false positive) |
| Credentials in memory | LOW | `Zeroizing<String>` for auth passwords and sudo passwords | Covered |
| SSH key material exposure | LOW | Key files read by SSH library, not stored in application memory | Covered |

**Sanitizer Architecture:**

1. Aho-Corasick keyword pre-filter for fast rejection of clean output
2. RegexSet for parallel pattern detection
3. Sequential 5-tier pattern application (specific → generic)
4. Covers: AWS, GCP, Azure, GitHub, GitLab, Stripe, Anthropic, npm, PyPI, JWT, private keys, database URIs, generic passwords

### Denial of Service

| Threat | Risk | Control | Status |
|--------|------|---------|--------|
| Command flooding | MEDIUM | Per-host token bucket rate limiter | Covered |
| Large output consumption | MEDIUM | Configurable `max_output_chars` with OutputCache pagination | Covered |
| Connection exhaustion | LOW | Connection pool with max connections per host, idle timeout, max age | Covered |
| Slow commands blocking | LOW | Configurable command timeout (`command_timeout_secs`) | Covered |

**Rate Limiter:**

- Token bucket algorithm with configurable burst and refill rate
- Per-host isolation (one host's rate limit doesn't affect others)
- Returns clear error messages when rate limited

### Elevation of Privilege

| Threat | Risk | Control | Status |
|--------|------|---------|--------|
| Arbitrary command execution | HIGH | SecurityMode (Strict: whitelist-only, or Permissive: blacklist) | Covered |
| Sudo abuse | MEDIUM | Dangerous commands blacklisted (rm -rf, mkfs, dd, chmod 777, etc.) | Covered |
| Tool group escalation | LOW | `ToolGroupsConfig` restricts which tool categories are available | Covered |
| Config-level restriction bypass | LOW | `allowed_commands` per-host limits which commands each host accepts | Covered |

**Default Blacklist Patterns:**
`rm -rf /`, `mkfs`, `dd if=`, `chmod 777`, `curl|sh`, `wget|sh`, `python -c`, `:(){ :|:& };:`, and more.

## Attack Surface

### Input Vectors

| Vector | Source | Validation |
|--------|--------|------------|
| Tool parameters (JSON) | AI client via JSON-RPC | Schema validation + shell escaping |
| File paths | AI client | `validate_path()` rejects traversal |
| Host names | Config file | Config validation at startup |
| SSH credentials | Config file | File permissions, Zeroizing memory |

### Trust Boundaries

1. **AI Client → Bridge**: JSON-RPC over stdio. The bridge treats all parameters as untrusted and validates/escapes them.
2. **Bridge → SSH Host**: SSH transport with host key verification. Commands are constructed by the bridge using shell escaping.
3. **SSH Host → Bridge**: Command output is sanitized before returning to the AI client.

## Residual Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| AI client compromise (prompt injection causing malicious commands) | MEDIUM | Defense-in-depth: validator + blacklist + escaping + rate limiting |
| Zero-day in SSH library (russh) | LOW | Dependency auditing via cargo-deny/cargo-audit |
| Timing attacks on RSA (RUSTSEC-2023-0071) | LOW | Accepted risk: transitive dependency, medium severity, local CLI usage |
| Memory forensics on credentials | LOW | Zeroizing at drop, but Config lives for process lifetime |

## Testing Coverage

- **240+ security-focused unit tests** across validator, sanitizer, rate limiter, audit logger, known hosts
- **58 adversarial integration tests** (`tests/security_audit.rs`) covering command injection, path traversal, credential leakage
- **26 fuzz targets** for input validation
- **Mutation testing** at ~88% score on security module
- **`#![forbid(unsafe_code)]`** enforced project-wide
