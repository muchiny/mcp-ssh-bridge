---
name: ssh-audit
description: Security audit and compliance scanning — CIS benchmarks, vulnerability scans, certificate checks, firewall rules, open ports. Use for security reviews or compliance assessments.
context: fork
agent: general-purpose
argument-hint: <host> [quick|full|network|compliance]
---

# Security Audit

Run security audits on a remote server via mcp-ssh-bridge CLI.
Runs in a forked agent to handle verbose scan output without polluting the main context.

**Host:** `$0`
**Scope:** `$1` (default: quick)

## Scope: quick (~2 min)

Fast security overview — run this first:

```bash
# Open ports
mcp-ssh-bridge tool ssh_port_scan host=$0 --json

# Certificate expiry
mcp-ssh-bridge tool ssh_cert_expiry host=$0 --json

# Fail2ban status
mcp-ssh-bridge tool ssh_fail2ban_status host=$0 --json

# Firewall rules
mcp-ssh-bridge tool ssh_firewall_list host=$0 --json

# Listening services
mcp-ssh-bridge tool ssh_exec host=$0 command="ss -tlnp" --json
```

## Scope: network

Network-focused security assessment:

```bash
# SSL/TLS audit
mcp-ssh-bridge tool ssh_ssl_audit host=$0 --json

# Port scan
mcp-ssh-bridge tool ssh_port_scan host=$0 --json

# Active connections
mcp-ssh-bridge tool ssh_net_connections host=$0 --json

# DNS configuration
mcp-ssh-bridge tool ssh_net_dns host=$0 --json
```

## Scope: compliance

Standards-based compliance check:

```bash
# CIS Benchmark
mcp-ssh-bridge tool ssh_cis_benchmark host=$0 --json

# STIG check
mcp-ssh-bridge tool ssh_stig_check host=$0 --json

# Compliance score
mcp-ssh-bridge tool ssh_compliance_score host=$0 --json

# Full compliance report
mcp-ssh-bridge tool ssh_compliance_report host=$0 --json
```

## Scope: full

Comprehensive audit — combines all scopes plus vulnerability scanning:

Run all commands from `quick`, `network`, and `compliance` scopes, then add:

```bash
# SBOM generation
mcp-ssh-bridge tool ssh_sbom_generate host=$0 --json

# Vulnerability scan
mcp-ssh-bridge tool ssh_vuln_scan host=$0 --json

# SELinux / AppArmor status
mcp-ssh-bridge tool ssh_selinux_status host=$0 --json
mcp-ssh-bridge tool ssh_apparmor_status host=$0 --json

# Security audit log
mcp-ssh-bridge tool ssh_security_audit host=$0 --json

# SSH key audit
mcp-ssh-bridge tool ssh_key_audit host=$0 --json

# User accounts review
mcp-ssh-bridge tool ssh_user_list host=$0 --json
```

## Audit Report Format

Produce a structured report:

1. **Risk Level**: critical / high / medium / low
2. **Findings**: list each issue with severity
   - Critical: exposed services, expired certs, no firewall
   - High: weak SSL, default passwords, no fail2ban
   - Medium: missing CIS controls, outdated packages
   - Low: informational, best-practice suggestions
3. **Compliance Score**: percentage if CIS/STIG was run
4. **Recommendations**: prioritized action items
5. **Next Steps**: specific commands to remediate each finding
