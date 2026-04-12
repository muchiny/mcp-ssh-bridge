---
paths:
  - "src/winrm/**"
  - "src/psrp/**"
  - "src/telnet/**"
  - "src/k8s_exec/**"
  - "src/serial_port/**"
  - "src/ssm/**"
  - "src/cloud_exec/**"
---

# Protocol Adapter Rules

## ExecutorRouter

All protocol adapters are dispatched via `ExecutorRouter` in `src/ports/executor_router.rs`.
Each protocol implements the `RemoteExecutor` trait from `src/ports/executor.rs`.

## Feature Gates

Every protocol adapter is behind a feature flag in `Cargo.toml`:
- `winrm` → `src/winrm/` (wraps `winrm-rs` for WS-Man/SOAP, NTLMv2/Basic/Kerberos/Certificate auth)
- `psrp` → `src/psrp/` (wraps `psrp-rs` for PowerShell Remoting Protocol over WinRM transport)
- `telnet` → `src/telnet/`
- `k8s-exec` → `src/k8s_exec/`
- `serial` → `src/serial_port/`
- `ssm` → `src/ssm/`
- `azure` → `src/cloud_exec/azure.rs`
- `gcp` → `src/cloud_exec/gcp.rs` (wraps the `gcloud` CLI — requires gcloud installed on the host)

Umbrella features: `air-gapped` (`winrm + telnet`), `cloud` (`ssm + azure + gcp`), `all-protocols` (all 8 including psrp).

**Note:** 5 protocols were removed in v1.11.0 as non-functional stubs: `mqtt`, `nats`, `netconf`, `snmp`, `zmq` (+ the `messaging` umbrella feature). Do not reference these.

## Connection Pools (Sprint 3 Phase B)

Three protocols have a dedicated **connection pool** that caches the expensive bits of the client:

| Pool | Module | Caches | TTL | Gain per warm call |
|---|---|---|---|---|
| `ConnectionPool` (SSH) | `src/ssh/pool.rs` | `russh` sessions | 1800 s | ~95 ms (TCP + SSH handshake) |
| `WinRmPool` | `src/winrm/pool.rs` | `reqwest::Client` with HTTPS keep-alive | 120 s | ~30-50 ms (TLS handshake) |
| `K8sExecPool` | `src/k8s_exec/pool.rs` | `kube::Client` (inferred config + auth plugin) | 300 s | ~50-200 ms (`Config::infer()` + TLS + auth refresh) |
| `PsrpPool` | `src/psrp/pool.rs` | `psrp_rs::RunspacePool` (PSRP session) | 300 s | ~200-500 ms (TLS + auth + PSRP handshake + runspace init) |

Each pool exposes the same surface (`new()`, `get_connection(host_name, host_config, limits)`, `evict(host_name)`, `cleanup()`, `close_all()`) so `ExecutorRouter` wires them in identically.

- **`ExecutorRouter` holds all three pools** (feature-gated) and the `Protocol::WinRm` / `Protocol::K8sExec` arms in `get_connection_with_jump` delegate to them.
- **`cleanup()` forwards to every pool** — the shared 60 s cleanup task in `McpServer::spawn_cleanup_tasks()` drains stale entries across all protocols.
- **`close_all()` too** — drops every cached entry on server shutdown.

### `from_parts()` constructors

When a pool hands out a connection it calls `XxxConnection::from_parts(host_name, host_config, client[, config])` rather than `XxxConnection::new(...)`:

- `new()` **builds** a fresh client from scratch (cold path).
- `from_parts()` **wraps an already-cached client** + re-parses any per-call metadata (namespace, pod name, credentials) from `host_config`.

When adding a new protocol pool, implement both constructors so the pool stays a pure cache layer without duplicating protocol setup.

## Adding a Protocol Adapter

1. Create module in `src/<protocol>/` implementing `RemoteExecutor` trait
2. Add feature gate in `Cargo.toml`
3. Add match arm in `ExecutorRouter::get_connection_with_jump()` for the new protocol
4. Wrap all code in `#[cfg(feature = "...")]`
5. Add integration tests behind same feature gate
6. Update `all-protocols` feature to include new feature
7. **If the protocol has expensive setup** (TLS, auth plugin, session negotiation), add a pool under `src/<protocol>/pool.rs` following the `WinRmPool` / `K8sExecPool` pattern + wire it into `ExecutorRouter::cleanup()` + `close_all()`.

## Import Rules

Same as ports: only import from `ports`, `domain`, `error`. Never from other adapters.
