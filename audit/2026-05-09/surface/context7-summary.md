# context7 upstream security guidance — summary (2026-05-09)

Aggregated from `audit/2026-05-09/surface/context7/*.md`. Drift status reflects
in-tree code as of branch `security/audit-2026-05-09` HEAD. Each drift row is
a candidate finding for Tasks 8–11 and feeds `FINDINGS.md` (Task 16).

---

## Drift table

| Crate | Recommended-default snippet | Project's current value | File / line | Drift? | Source |
|-------|------------------------------|--------------------------|-------------|--------|--------|
| russh | `check_server_key` must verify against pinned host-key store; default trait impl returns `Ok(true)` | Custom impl delegates to `known_hosts::verify_host_key(...)`, returns `Ok(false)` on failure with `tracing::error!` | `src/ssh/client.rs:165` | **no drift** | `surface/context7/russh.md` |
| russh | `client::Config::preferred = Preferred { kex, key, cipher, mac, compression }` with explicit allowlist (CURVE25519, ED25519, CHACHA20_POLY1305, etc.) | No `Preferred { ... }` literal anywhere in `src/`; relying on `client::Config::default()` | (no occurrence in `src/ssh/`, `src/config/`) | **DRIFT — P1** (allow weaker legacy algos by default) | `surface/context7/russh.md` |
| russh | `Limits::new(1<<30, 1<<30, Duration::from_secs(3600))` rekey caps | Not set explicitly | `src/ssh/client.rs` | **DRIFT — P2** | `surface/context7/russh.md` |
| russh | Explicit `inactivity_timeout`, `keepalive_interval`, `keepalive_max` | Not greppable; check `src/ssh/pool.rs` defaults | `src/ssh/pool.rs` (verify in Task 8) | **needs verification** | `surface/context7/russh.md` |
| russh-keys | `load_secret_key(path, Some(passphrase))` — passphrase must arrive wrapped in `Zeroizing` | Caller is `src/ssh/client.rs:491` — passphrase comes from a `Zeroizing<String>` field on the auth config | `src/ssh/client.rs:491`, `src/config/types.rs:1354` (test) | **no drift (verify Task 11)** | `surface/context7/russh-keys.md` |
| rustls | `ClientConfig::builder()` with explicit `with_webpki_verifier(...).with_crls(...).enforce_revocation_expiration()` for revocation | No direct rustls config in `src/`; TLS chain inherited from `reqwest`, `aws-sdk-*`, `kube` (rustls-tls feature) | (no direct config) | **n/a — indirect** (drift evaluated per downstream lib in Task 10) | `surface/context7/rustls.md` |
| rustls | `dangerous().set_certificate_verifier(...)` MUST be absent | No matches in `src/` | (none) | **no drift** | `surface/context7/rustls.md` |
| jsonwebtoken | Pin algorithm explicitly in `Validation::new(EXPECTED_ALG)`; reject HMAC/`none`; require `set_required_spec_claims(["exp","sub","iss","aud"])` | `src/mcp/transport/oauth.rs:191-216`: pre-filters `header.alg` to asymmetric only THEN `Validation::new(header.alg)`; sets issuer + audience + nbf + 30s leeway. **MISSING** `set_required_spec_claims` — only `exp` is required by default; `sub` / `iss` / `aud` are validated only if present in the token | `src/mcp/transport/oauth.rs:212-216` | **DRIFT — P1** (token without `sub`/`iss`/`aud` would pass Validation) | `surface/context7/jsonwebtoken.md` |
| axum | `TimeoutLayer + HandleErrorLayer + DefaultBodyLimit + SetSensitiveRequestHeadersLayer + SetSensitiveResponseHeadersLayer + CorsLayer (explicit allowlist) + RequestIdLayer` | Only `CorsLayer::new()` found. **MISSING** TimeoutLayer / HandleErrorLayer / DefaultBodyLimit override / SetSensitive*Headers / RequestIdLayer | `src/mcp/transport/http.rs:202` | **DRIFT — P0/P1** (no global request timeout, no audit-side header redaction) | `surface/context7/axum.md` |
| tokio | `blocking_write()` / `blocking_read()` MUST be inside `spawn_blocking` or in unambiguously-sync code | 3 call sites: `src/config/watcher.rs:117`, `:219` (file-watcher thread, NOT tokio task — explicit comment confirms safe) and `src/mcp/server.rs:603` (notification slot, must be re-checked) | `src/config/watcher.rs:117,219`, `src/mcp/server.rs:603` | **needs verification — P1 if `server.rs:603` runs in async context** | `surface/context7/tokio.md` |
| tokio | `tokio::sync::Mutex` is not poison-aware; security-critical paths should not rely on poisoning | All security-critical state uses `tokio::sync::Mutex` / `RwLock` (post Vuln 8/9 fix) | (no broken invariant assumption found) | **no drift** | `surface/context7/tokio.md` |
| zeroize | `Cargo.toml` `features = ["derive"]` (or `zeroize_derive`) when using `#[derive(Zeroize, ZeroizeOnDrop)]` | `Cargo.toml`: `zeroize = { version = "1", features = ["serde"] }` — **no `derive` feature**, but project uses `Zeroizing::new(...)` exclusively (no `#[derive(Zeroize)]` in `src/`); design choice is consistent | `Cargo.toml` line ~`zeroize = …` | **no drift (intentional)** | `surface/context7/zeroize.md` |
| zeroize | Every cred-bearing struct field uses `Zeroizing` or has a custom Drop | `Zeroizing::new(...)` appears in `src/config/types.rs` (passphrase, password), `src/winrm/`, `src/psrp/`, `src/cli/runner.rs`, `src/mcp/tool_handlers/ssh_status.rs`. Test sites only — production cred construction must be re-verified in Task 11 | (multiple) | **needs verification — Task 11** | `surface/context7/zeroize.md` |
| secrecy | `SecretBox<S> + ExposeSecret` for any secret that crosses a function boundary | Crate not in `Cargo.toml`; project relies entirely on `zeroize::Zeroizing` for both wrapping and dropping. Trade-off: no `expose_secret()` audit point, but no `Debug` leakage risk either since `Zeroizing<String>` derives the inner Debug | (none) | **no drift (intentional)** | `surface/context7/secrecy.md` |
| kube | `Client::try_default()` inherits in-cluster / kubeconfig — confirm intent. `pods.exec(...)` must validate argv via SecurityValidator. `AttachParams::stdin(true)` sessions must be per-MCP-session lifetime-bound | No `try_default()` / `pods.exec(` / `AttachParams.stdin(true)` matches in `src/`. `kube` crate is feature-gated (`cloud` / `all-protocols`); usage must be re-verified when those features compile in Task 11 | (feature-gated) | **needs verification — Task 11 with `--features all-protocols`** | `surface/context7/kube.md` |
| serde-saphyr | `from_str_with_options(yaml, options)` with explicit `Budget { max_anchors, max_depth, max_nodes, max_reader_input_bytes }` to defeat billion-laughs / depth-bombs | **EVERY** YAML load uses bare `serde_saphyr::from_str(...)` with NO Budget: `src/config/loader.rs:45` (main config), `src/domain/runbook.rs:160,188` (runbook YAML — runbooks may flow from runtime input), `src/security/rbac.rs:299`, `src/config/types.rs` (tests). | `src/config/loader.rs:45`, `src/domain/runbook.rs:160,188`, `src/security/rbac.rs:299` | **DRIFT — P0** (DOS vector on YAML inputs; runbook loader is the highest-risk because runbook bodies can be remote-sourced) | `surface/context7/serde-saphyr.md` |
| serde-saphyr | `serde_yaml::` MUST be zero matches (migration to saphyr complete) | No `serde_yaml::` matches | (none) | **no drift** | `surface/context7/serde-saphyr.md` |
| serde-saphyr | `#[serde(deny_unknown_fields)]` on every config struct | `rg -n deny_unknown_fields src/` returns matches in domain/data_reduction.rs only — `Config` and most types in `src/config/types.rs` do NOT have it; saphyr's strict-typing partially compensates but explicit attribute is belt-and-suspenders | `src/config/types.rs` | **DRIFT — P2** | `surface/context7/serde-saphyr.md` |

---

## Deprecated / removed APIs in use

- None confirmed at this layer. Possible candidates to verify in Task 8/10:
  - `serde_yaml` (unmaintained since 2024-04) — already removed from this codebase. ✅
  - `secrecy::Secret` (deprecated in 0.10 in favor of `SecretBox`) — n/a, project doesn't use secrecy.
  - `russh-keys` standalone crate — merged into `russh` 0.55+; project's `russh = "0.60"` is past the merge.

## Recent advisories or hardening notes (last 12 months) NOT in deny.toml

- **`Validation::new(alg)` algorithm-confusion class** (jsonwebtoken) — historically the #1 JWT footgun; project's pre-filter avoids it but `set_required_spec_claims` gap remains. (See drift row.)
- **YAML billion-laughs / depth-bomb** (serde-saphyr) — Budget API exists explicitly to defeat this; project uses none. (See drift row.)
- **rustls CRL handling** — RUSTSEC-2026-0098/0099/0104 already in `deny.toml` as ignored (transitive via aws-sdk). Project tracks; no new action.

## Open questions to confirm during /static-analysis or /insecure-defaults (Tasks 8/9)

- [ ] `src/ssh/pool.rs` — confirm `inactivity_timeout` / `keepalive_interval` are explicitly set, not inherited from `client::Config::default()`.
- [ ] `src/mcp/server.rs:603` — confirm `notification_tx_slot.blocking_read()` is in a sync block (Drop, sync callback, etc.) and never reachable from an async fn directly.
- [ ] `src/mcp/transport/http.rs` — write the missing layer stack: `TimeoutLayer + HandleErrorLayer + DefaultBodyLimit (or explicit max) + SetSensitiveRequestHeadersLayer + SetSensitiveResponseHeadersLayer + RequestIdLayer + PropagateRequestIdLayer`.
- [ ] `src/mcp/transport/oauth.rs:212` — add `validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"])`.
- [ ] `src/config/loader.rs:45`, `src/domain/runbook.rs:160,188` — switch `serde_saphyr::from_str` to `from_str_with_options` with an explicit `Budget`.
- [ ] `Cargo.toml` `kube` features — if `exec` plugin is reachable at runtime, confirm SecurityValidator integration in Task 11.

---

## Plugin / server version

- context7 MCP server: `@upstash/context7-mcp@latest` (resolved at `claude mcp list` time on 2026-05-09)
- Per-crate raw responses cached at `audit/2026-05-09/surface/context7/<crate>.md`
- libraryId pin list: `audit/2026-05-09/surface/context7/_targets.md`
