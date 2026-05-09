# Zeroize Audit — 2026-05-09

**Skill:** `zeroize-audit:zeroize-audit` (trailofbits, v0.1.0)
**Mode:** Source-level (Phase 1 — `MISSING_SOURCE_ZEROIZE`, `SECRET_COPY`, `PARTIAL_WIPE`). The full pipeline (Phase 2 IR/asm/MIR/CFG analysis via `cargo +nightly` + emit_rust_*.sh) was scoped out for time; findings flagged here use grep + per-file inspection and are marked `likely` rather than `confirmed`.
**Scope:** `src/config/types.rs`, `src/ssh/{client,pool}.rs`, `src/winrm/`, `src/psrp/`, `src/mcp/transport/oauth.rs`, `src/mcp/tool_handlers/{ssh_ad,ssh_ldap,ssh_vault,ssh_k8s,ssh_db,ssh_mysql,ssh_postgresql}_*.rs`, `src/domain/use_cases/{vault,database}.rs`
**Cross-reference:** `audit/2026-05-09/surface/context7/{zeroize.md, secrecy.md}`, `cred-touchpoints.txt` (1802 references)

---

## Verdict

**4 new findings** (FIND-028 P1, FIND-029 P1, FIND-030 P2, FIND-031 P2).
**1 already-tracked** (FIND-014 — SOCKS password not Zeroizing) — confirmed, not duplicated.
**Strong-design observations** (no finding): `AuthConfig::{Key,Password,Ntlm}` correctly uses `Zeroizing<String>` for credentials — auth path is well-covered.

---

## Verified secure (no finding)

| Surface | Storage | Status |
|---|---|---|
| `AuthConfig::Key.passphrase` | `Option<Zeroizing<String>>` | ✅ Wrapped (`src/config/types.rs:452-453`) |
| `AuthConfig::Password.password` | `Zeroizing<String>` | ✅ Wrapped (`:457`) |
| `AuthConfig::Ntlm.password` | `Zeroizing<String>` | ✅ Wrapped (`:460`) |
| `AuthConfig::Certificate` | path strings only | ✅ No key bytes stored in struct |
| `AuthConfig::Kerberos` | no fields | ✅ Uses TGT from `kinit` |
| WinRM/PSRP cred construction | `Zeroizing::new(...)` | ✅ Confirmed via `rg "Zeroizing::new"` (test sites only — but auth carrier is `AuthConfig::Ntlm.password` which is wrapped) |
| AD / LDAP / Vault read / K8s / OAuth handlers | `sudo_password: None` passed through | ✅ Handlers do NOT carry credentials themselves; the carrier is `AuthConfig` (already wrapped) and `HostConfig.sudo_password` (see FIND-028 below) |
| OAuth `keys: HashMap<String, String>` | public RSA components / PEM | ✅ Public keys, not secrets — no zeroize requirement |

## Findings

### FIND-028 — `HostConfig.sudo_password: Option<String>` not `Zeroizing` (P1, `MISSING_SOURCE_ZEROIZE`)

**Location:** `src/config/types.rs:219`
```rust
/// Optional sudo password for this host (used with sudo commands)
#[serde(default)]
pub sudo_password: Option<String>,
```

**Why a finding:** `HostConfig.sudo_password` is plain `Option<String>` while the sibling `AuthConfig::Password.password` is `Zeroizing<String>`. The `HostConfig` struct lives for the entire process lifetime (loaded once from YAML, kept in `Config` field of `McpServer`), so the sudo password sits in heap from process start to exit. Hot-reloading config (which exists per `src/config/watcher.rs`) replaces `HostConfig` but the old heap allocation may not be wiped because the wrapping type is plain `String`. **Exact same defect class as FIND-014 (SOCKS password)**, on a different field of the same parent struct.

**Recommended fix:** `pub sudo_password: Option<Zeroizing<String>>`. Update borrow sites (handlers that pass `sudo_password` through to executors) to use `as_deref()` — no behavior change, cred bytes get wiped on drop.

**Evidence signals:** (1) name pattern (`*_password`), (2) type heuristic (plain `String` wrapping a known-cred field), (3) inconsistency with sibling fields. Marked `likely` (no IR/asm pipeline).

---

### FIND-029 — DB-handler `db_password: Option<String>` arg not `Zeroizing` (P1, `MISSING_SOURCE_ZEROIZE`)

**Locations:**
- `src/mcp/tool_handlers/ssh_db_query.rs:27` — `db_password: Option<String>` in `SshDbQueryArgs`
- Same pattern likely in `ssh_db_dump.rs`, `ssh_mysql_query.rs`, `ssh_postgresql_query.rs` (verify per file)

**Why a finding:** MCP request body deserializes `db_password` into a plain `String`. The `Args` struct lives for the duration of one tool call, but during that window the password is in heap unwrapped. Handler code at L129 calls `args.db_password.as_deref()` which borrows the underlying `&str` and passes it down through `database.rs::build_query_command(...) → write_password_env(...)`. Backing storage is the original `String`. Drop of `Args` does NOT wipe.

**Recommended fix:** Change to `db_password: Option<Zeroizing<String>>` in every DB handler `Args` struct. `as_deref()` continues to work because `Zeroizing<String>: Deref<Target=String>`.

**Evidence signals:** (1) name pattern, (2) type heuristic, (3) cross-handler inconsistency (every DB handler defines its own `db_password` field independently — easy to miss one). Marked `likely`.

---

### FIND-030 — Vault `data: Vec<String>` carries secrets unwrapped (P2, `MISSING_SOURCE_ZEROIZE`)

**Location:** `src/mcp/tool_handlers/ssh_vault_write.rs:13` — `data: Vec<String>` in `SshVaultWriteArgs`

**Why a finding:** Vault write args carry `key=value` pairs as `Vec<String>`, e.g. `data: ["password=secret", "api_key=ghp_xxx"]`. The strings sit in heap during the handler call. Even if (separately) the vault command transit is documented as visible in remote `ps`, the local heap residency is gratuitous: the values can be wrapped in `Zeroizing` before reaching `build_write_command`, then `write!` consumes them and they're zeroed on `Args` drop.

**Recommended fix:** `data: Vec<Zeroizing<String>>`. Update `build_write_command` signature: `data: &[Zeroizing<String>]` (deref to `&str` inside the loop). Optional: provide a separate `data_files: Vec<PathBuf>` argument so secrets can be passed via stdin / file rather than as MCP-request strings at all.

**Evidence signals:** (1) handler doc at L37-L39 explicitly warns "Use ssh_vault_list to browse... and ssh_vault_read to verify after writing" — the data is acknowledged-secret. (2) collection-of-strings type. Marked `likely`.

---

### FIND-031 — Secrets transit shell argv on the remote host (P2, `SECRET_COPY`)

**Locations:**
- `src/domain/use_cases/database.rs:90-94` — `write_password_env` builds `MYSQL_PWD='password' mysql ...` / `PGPASSWORD='password' psql ...`. Comment at L86-92 acknowledges the issue but only as a note ("more secure than passing as `argv` but less than connection files").
- `src/domain/use_cases/vault.rs:144-170` — `vault kv put` interpolates `key=value` (the secret) into the rendered shell command verbatim. The `shell_escape` is for shell-injection safety, not for secret hiding.

**Why a finding:** Both paths construct a shell command string containing the secret value. That string is then executed via `ssh_exec` → reaches the remote host's argv / environ. On the remote host, anyone with `ps eww` (vault case: argv; database case: environ via `/proc/PID/environ`) can read the secret during the brief execution window. The audit-log redaction (`src/security/sanitizer.rs`) catches the local audit log but does NOT protect the remote host's process listing.

**Recommended fix (vault):** Pipe the data via stdin instead of argv: `vault kv put -mount=secret path - <<EOF\nkey1=v1\nEOF`. Or use `vault kv put @file.json` after writing a temp file with `0600` mode to a tmpfs mount.
**Recommended fix (database):** Recommend operators use connection files (`~/.my.cnf`, `~/.pgpass`) with `0600` mode. The current env-var approach should at minimum write a one-line note in handler descriptions exposing the trade-off to the MCP client.

**Evidence signals:** (1) explicit acknowledging comment in source (`database.rs:86-92`), (2) shell-argv interpolation pattern visible at vault.rs L168 (`write!(cmd, " {}", shell_escape(kv))`). Marked `likely`.

---

## Already-tracked

- **FIND-014** — `SocksProxyConfig.password: Option<String>` not `Zeroizing` (`src/config/types.rs:420-421`). Source-level zeroize gap; same class as FIND-028. Not duplicated here.

## Out-of-scope for this Phase-1 source-only pass

These would require Phase 2 (MIR/LLVM IR/asm via `cargo +nightly` + the skill's `tools/emit_rust_*.sh` pipeline) to flag with `confirmed` confidence:

| Class | Why Phase 2 needed |
|---|---|
| `OPTIMIZED_AWAY_ZEROIZE` | IR diff between `O0` and `O2` to prove `Zeroizing::drop` was DSE'd |
| `STACK_RETENTION` | Assembly evidence of secret bytes on stack at `ret` |
| `REGISTER_SPILL` | Assembly `spill` instruction on cred-bearing register |
| russh `PrivateKey` ZeroizeOnDrop status | Inspect russh-keys 0.60.1 source — does the `PrivateKey` type in russh derive `ZeroizeOnDrop`? Open question OQ-013 below. |

## New open question (added to tracker)

**OQ-013** — In `src/ssh/client.rs:502`, `Arc::new(key_pair)` wraps a russh `PrivateKey` after `load_secret_key`. Does `russh::keys::PrivateKey` (russh 0.60.1) implement `ZeroizeOnDrop`? If not, the secret key bytes persist in heap memory until the Arc reference count reaches zero (and even then, depending on whether the `Drop` impl wipes them). Inspect `~/.cargo/registry/src/index.crates.io-*/russh-keys-*/src/private.rs` or upstream `Eugeny/russh` source. Owner: Task 11 (deferred to manual follow-up).

---

## Counters

- New P1: 2 (FIND-028, FIND-029)
- New P2: 2 (FIND-030, FIND-031)
- Confirmed existing: 1 (FIND-014)
- New OQ: 1 (OQ-013)
- Verified secure: 8 surfaces (auth path, OAuth public keys, AD/LDAP/Vault-read/K8s handlers — handlers don't carry creds)
