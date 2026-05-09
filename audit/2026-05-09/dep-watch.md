# Dependency Watchlist — Audit 2026-05-09

**Purpose:** track dependencies flagged as supply-chain risk during the audit. Each entry has a re-evaluation date; revisit at that time and either accept the new state, vendor the dep, or migrate.

**Owner:** security audit branch maintainer (re-eval dates fall on the audit lead).

---

## serde_saphyr (FIND-026, P1)

| Field | Value |
|---|---|
| Crate | `serde_saphyr` |
| Version pinned | `=0.0.21` |
| Used at | `src/domain/yaml.rs::parse_yaml` (5 production call sites — all config + runbook YAML) |
| Maintainer | `davidhewitt` (single primary author, 649/667 commits) |
| Repo | https://github.com/davidhewitt/serde-saphyr |
| GitHub stars | 167 |
| Open issues at audit time | 0 |
| RustSec advisories | none as of 2026-05-09 |
| Risk | Pre-1.0, single-maintainer YAML parser on the YAML critical path. Maintainer takeover or buggy update would compromise every YAML-parsing site. Default Budget caps were already too liberal for our threat model (FIND-001/002/004/032 fix tightens them). |

### Mitigations in place

- Pinned to exact version `=0.0.21` in `Cargo.toml`.
- All production parses go through `crate::domain::yaml::parse_yaml`, which enforces a hardened `Budget` (anchors 100, depth 50, nodes 10K, max input 1 MiB). Even a maliciously-permissive saphyr release cannot bypass our application-level cap on input size.
- `deny.toml` includes `[advisories] yanked = "deny"` so a yanked saphyr release breaks CI.

### Watch actions

- **Subscribe to RustSec advisory feed:** https://github.com/rustsec/advisory-db/issues — filter on `serde_saphyr`.
- **Watch the upstream repo for releases:** https://github.com/davidhewitt/serde-saphyr/releases.atom.
- **Re-evaluate by:** 2026-08-09 (90 days from audit date).
- **Trigger conditions for action:**
  - Saphyr reaches 1.0 → review new release notes, evaluate breaking changes, plan version bump.
  - Maintainer changes (transfer of ownership, new co-maintainer) → review the security model of the new contributors.
  - RustSec advisory issued → triage immediately, patch or pin to last-known-good.
  - Yanked release → CI breaks; investigate the reason for the yank.
  - Reasonable alternative emerges (saphyr-yaml-parser, libyaml-rs replacement, or serde_yaml_ng resumes maintenance) → spike a migration POC.

---

## tokio-socks (FIND-027, P2)

| Field | Value |
|---|---|
| Crate | `tokio-socks` |
| Version pinned | `0.5.x` |
| Used at | `src/ssh/client.rs:373-413` (SOCKS proxy on the SSH auth-perimeter path) |
| Maintainer | `sticnarf/tokio-socks` (last commit 2025-02-19, > 14 months stale at audit date) |
| Repo | https://github.com/sticnarf/tokio-socks |
| GitHub stars | 102 |
| Status | Inactive but not archived; no open security issues; no RustSec advisories. |
| Risk | Auth-perimeter relevant. A bug here can leak the operator's true IP or weaken the SSH connection initiation. |

### Mitigations in place

- Crate is small (~1500 LOC) — tractable to vendor or fork if necessary.
- SSH host-key verification still applies after the SOCKS tunnel completes; a SOCKS hijack does not silently succeed.

### Watch actions

- **Watch the upstream repo for activity:** https://github.com/sticnarf/tokio-socks/commits/master.atom.
- **Re-evaluate by:** 2026-08-01 (target: if no release by this date, plan vendoring).
- **Trigger conditions for action:**
  - No release by 2026-08-01 → plan vendoring under `vendor/tokio-socks` (~1 day of work).
  - Repo archived → vendor immediately.
  - RustSec advisory issued → triage and patch / vendor.
  - Active fork (e.g. tokio-socks-rs successor) appears with a security-conscious maintainer → evaluate as drop-in replacement.

---

## Process

- **Cadence:** review this list at the start of every monthly security checkpoint. Update the "Re-evaluate by" date if a watch trigger fired without action being needed.
- **Closure:** when a dep is migrated or vendored, move its row to a "Closed" section with the resolution date.
- **New entries:** any dep flagged in a future audit's supply-chain phase appends a row here using the same template.
